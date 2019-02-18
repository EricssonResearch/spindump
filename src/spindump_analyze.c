
//
//
//  ////////////////////////////////////////////////////////////////////////////////////
//  /////////                                                                ///////////
//  //////       SSS    PPPP    I   N    N   DDDD    U   U   M   M   PPPP         //////
//  //          S       P   P   I   NN   N   D   D   U   U   MM MM   P   P            //
//  /            SSS    PPPP    I   N NN N   D   D   U   U   M M M   PPPP              /
//  //              S   P       I   N   NN   D   D   U   U   M   M   P                //
//  ////         SSS    P       I   N    N   DDDD     UUU    M   M   P            //////
//  /////////                                                                ///////////
//  ////////////////////////////////////////////////////////////////////////////////////
//
//  SPINDUMP (C) 2018-2019 BY ERICSSON RESEARCH
//  AUTHOR: JARI ARKKO
//
//

//
// Includes -----------------------------------------------------------------------------------
//

#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include "spindump_util.h"
#include "spindump_connections.h"
#include "spindump_connections_set.h"
#include "spindump_connections_set_iterator.h"
#include "spindump_analyze.h"
#include "spindump_analyze_tcp.h"
#include "spindump_analyze_udp.h"
#include "spindump_analyze_quic.h"
#include "spindump_analyze_icmp.h"
#include "spindump_analyze_aggregate.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static void
spindump_analyze_process_null(struct spindump_analyze* state,
			      struct spindump_packet* packet,
			      struct spindump_connection** p_connection);
static void
spindump_analyze_process_ethernet(struct spindump_analyze* state,
				  struct spindump_packet* packet,
				  struct spindump_connection** p_connection);
static void
spindump_analyze_decodeiphdr(struct spindump_analyze* state,
			     struct spindump_packet* packet,
			     unsigned int position,
			     struct spindump_connection** p_connection);
static void
spindump_analyze_decodeip6hdr(struct spindump_analyze* state,
			      struct spindump_packet* packet,
			      unsigned int position,
			      struct spindump_connection** p_connection);
static void
spindump_analyze_decodeippayload(struct spindump_analyze* state,
				 struct spindump_packet* packet,
				 unsigned int ipHeaderPosition,
				 unsigned int ipHeaderSize,
				 uint8_t ipVersion,
				 uint8_t ecnFlags,
				 unsigned int ipPacketLength,
				 unsigned char proto,
				 unsigned int payloadPosition,
				 struct spindump_connection** p_connection);
static void
spindump_analyze_otherippayload(struct spindump_analyze* state,
				struct spindump_packet* packet,
				unsigned int ipHeaderPosition,
				unsigned int ipHeaderSize,
				uint8_t ipVersion,
				uint8_t ecnFlags,
				unsigned int ipPacketLength,
				struct spindump_connection** p_connection);

//
// Actual code --------------------------------------------------------------------------------
//

//
// Create an object to represent an analyzer. Allocate memory as needed.
//

struct spindump_analyze*
spindump_analyze_initialize(void) {

  //
  // Checks
  //

  if (spindump_connection_max_handlers != spindump_analyze_max_handlers) {
    spindump_errorf("the maximum number of registered handlers must be defined to be the same, "
		    "now spindump_connection_max_handlers (%u) and spindump_analyze_max_handlers (%u) "
		    "differ",
		    spindump_connection_max_handlers,
		    spindump_analyze_max_handlers);
    return(0);
  }

  //
  // Calculate size and allocate state
  //

  unsigned int size = sizeof(struct spindump_analyze);
  struct spindump_analyze* state = (struct spindump_analyze*)malloc(size);
  if (state == 0) {
    spindump_errorf("cannot allocate analyzer state of %u bytes", size);
    return(0);
  }

  //
  // Initialize state
  //

  memset(state,0,size);
  state->table = spindump_connectionstable_initialize();
  if (state->table == 0) {
    free(state);
    return(0);
  }
  state->stats = spindump_stats_initialize();
  if (state->stats == 0) {
    spindump_connectionstable_uninitialize(state->table);
    free(state);
    return(0);
  }

  //
  // Done. Return state.
  //

  return(state);
}

//
// Destroy the analyzer resources and memory object
//

void
spindump_analyze_uninitialize(struct spindump_analyze* state) {

  //
  // Checks
  //

  spindump_assert(state != 0);
  spindump_assert(state->table != 0);
  spindump_assert(state->stats != 0);
  spindump_connectionstable_uninitialize(state->table);
  spindump_stats_uninitialize(state->stats);

  //
  // Reset contents, just in case
  //

  memset(state,0,sizeof(*state));

  //
  // Actually free up the space
  //

  free(state);
}

//
// Register a handler for specific events
//

void
spindump_analyze_registerhandler(struct spindump_analyze* state,
				 spindump_analyze_event eventmask,
				 spindump_analyze_handler handler,
				 void* handlerData) {
  //
  // Checks
  //

  spindump_assert(state != 0);
  spindump_assert(eventmask != 0);
  spindump_assert((eventmask & spindump_analyze_event_alllegal) == eventmask);
  spindump_assert(handler != 0);

  //
  // Do we have space for this handler?
  //

  if (state->nHandlers == spindump_analyze_max_handlers) {
    spindump_errorf("cannot add any more handlers, supporting only max %u handlers", spindump_analyze_max_handlers);
    return;
  }

  state->handlers[state->nHandlers].eventmask = eventmask;
  state->handlers[state->nHandlers].function = handler;
  state->handlers[state->nHandlers].handlerData = handlerData;
  state->nHandlers++;
}

//
// Run all the handlers for a specific event
//

void
spindump_analyze_process_handlers(struct spindump_analyze* state,
				  spindump_analyze_event event,
				  struct spindump_packet* packet,
				  struct spindump_connection* connection) {
  //
  // Checks
  //

  spindump_assert(state != 0);
  spindump_assert((event & spindump_analyze_event_alllegal) == event);
  spindump_assert(event == spindump_analyze_event_connectiondelete ||
		  spindump_packet_isvalid(packet));
  spindump_assert(connection != 0);
  spindump_deepdebugf("calling handlers for event %x (%s)",
		      event, spindump_analyze_eventtostring(event));

  //
  // Scan through the registered handlers and execute them if they
  // match this event
  //

  for (unsigned int i = 0; i < state->nHandlers; i++) {
    struct spindump_analyze_handler* handler = &state->handlers[i];
    if ((handler->eventmask & event) != 0) {
      spindump_assert(spindump_analyze_max_handlers == spindump_connection_max_handlers);
      spindump_assert(i < spindump_connection_max_handlers);
      spindump_deepdebugf("calling handler %x", handler->eventmask);
      (*(handler->function))(state,
			     handler->handlerData,
			     &connection->handlerConnectionDatas[i],
			     event,
			     packet,
			     connection);
    }
  }

  //
  // Done
  //
}

//
// Retrieve statistics associated with the analyzer
//

struct spindump_stats*
spindump_analyze_getstats(struct spindump_analyze* state) {
  spindump_assert(state != 0);
  spindump_assert(state->stats != 0);
  return(state->stats);
}

//
// Get the packet's source IP address stored in the "address" output
// parameter, regardless of whether the IP version is 4 or 6.
//

void
spindump_analyze_getsource(struct spindump_packet* packet,
			   uint8_t ipVersion,
			   unsigned int ipHeaderPosition,
			   spindump_address *address) {
  spindump_assert(spindump_packet_isvalid(packet));
  spindump_assert(address != 0);
  if (ipVersion == 4) {
    struct spindump_ip iphdr;
    spindump_protocols_ip_header_decode(packet->contents + ipHeaderPosition,&iphdr);
    spindump_address_frombytes(address,AF_INET,(const unsigned char*)&iphdr.ip_src);
  } else if (ipVersion == 6) {
    struct spindump_ip6 ip6hdr;
    spindump_protocols_ip6_header_decode(packet->contents + ipHeaderPosition,&ip6hdr);
    spindump_address_frombytes(address,AF_INET6,(const unsigned char*)&ip6hdr.ip6_source);
  } else {
    spindump_errorf("no version set");
    spindump_address_fromstring(address,"0.0.0.0");
  }
}

//
// Get the packet's destination IP address stored in the "address"
// output parameter, regardless of whether the IP version is 4 or 6.
//

void
spindump_analyze_getdestination(struct spindump_packet* packet,
				uint8_t ipVersion,
				unsigned int ipHeaderPosition,
				spindump_address *address) {
  spindump_assert(spindump_packet_isvalid(packet));
  spindump_assert(address != 0);
  if (ipVersion == 4) {
    struct spindump_ip iphdr;
    spindump_protocols_ip_header_decode(packet->contents + ipHeaderPosition,&iphdr);
    spindump_address_frombytes(address,AF_INET,(const unsigned char*)&iphdr.ip_dst);
  } else if (ipVersion == 6) {
    struct spindump_ip6 ip6hdr;
    spindump_protocols_ip6_header_decode(packet->contents + ipHeaderPosition,&ip6hdr);
    spindump_address_frombytes(address,AF_INET6,(const unsigned char*)&ip6hdr.ip6_destination);
  } else {
    spindump_errorf("no version set");
    spindump_address_fromstring(address,"0.0.0.0");
  }
}

//
// This is the main function to process an incoming packet, and decide
// what category it falls under, and then process it
// appropriately. The function sets the p_connection output parameter
// to the connection that this packet belongs to (and possibly creates
// this connection if the packet is the first in a flow, e.g., TCP
// SYN).
//
// It is assumed that prior modules, e.g., the capture module have
// filled in the relevant header pointers in the packet structure
// "packet" correctly. The etherlen, caplen, timestamp, and the actual
// packet (the contents field) needs to have been set.
//

void
spindump_analyze_process(struct spindump_analyze* state,
			 enum spindump_capture_linktype linktype,
			 struct spindump_packet* packet,
			 struct spindump_connection** p_connection) {

  //
  // Checks
  //

  spindump_assert(state != 0);
  spindump_assert(packet != 0);
  spindump_assert(spindump_packet_isvalid(packet));
  spindump_assert(p_connection != 0);

  //
  // Switch based on type of L2
  //

  switch (linktype) {
  case spindump_capture_linktype_null:
    spindump_analyze_process_null(state,packet,p_connection);
    break;
  case spindump_capture_linktype_ethernet:
    spindump_analyze_process_ethernet(state,packet,p_connection);
    break;
  default:
    spindump_errorf("unsupported linktype");
  }
}

//
// Process a packet when the datalink layer is the BSD null/loop layer.
// This layer has just a 4-byte number indicating the packet type.
//

static void
spindump_analyze_process_null(struct spindump_analyze* state,
			      struct spindump_packet* packet,
			      struct spindump_connection** p_connection) {
  //
  // Check there is enough of the null header. As pcap_datalink man page says:
  //
  //    https://www.tcpdump.org/linktypes.html  lists  the values
  //    pcap_datalink() can return and describes the packet formats
  //    that correspond to those values.
  //
  // And tcpdump.org says:
  //
  //    BSD loopback encapsulation; the link layer header is a 4-byte
  //    field, in host byte order, containing a value of 2 for IPv4
  //    packets, a value of either 24, 28, or 30 for IPv6 packets, a
  //    value of 7 for OSI packets, or a value of 23 for IPX packets. All
  //    of the IPv6 values correspond to IPv6 packets; code reading files
  //    should check for all of them.
  //
  //    Note that ``host byte order'' is the byte order of the machine on
  //    which the packets are captured; if a live capture is being done,
  //    ``host byte order'' is the byte order of the machine capturing
  //    the packets, but if a ``savefile'' is being read, the byte order
  //    is not necessarily that of the machine reading the capture file.
  //

  if (packet->etherlen < spindump_null_header_size ||
      packet->caplen < spindump_null_header_size) {
    spindump_warnf("not enough bytes for the Null header, only %u bytes in received frame",
		   packet->etherlen);
    *p_connection = 0;
    return;
  }

  //
  // Branch based on the stored int
  //

  uint32_t nullInt;
  memcpy(&nullInt,packet->contents,sizeof(nullInt));
  switch (nullInt) {
  case 2:
    spindump_analyze_decodeiphdr(state,
				 packet,
				 spindump_null_header_size,
				 p_connection);
    return;

  case 22:
  case 28:
  case 30:
    spindump_analyze_decodeip6hdr(state,
				  packet,
				  spindump_null_header_size,
				  p_connection);
    return;

  default:
    spindump_debugf("received an unsupported null datalink layer type %4x", nullInt);
    state->stats->unsupportedNulltype++;
    *p_connection = 0;
    return;

  }
}

//
// Process a packet when the datalink layer is the Ethernet layer.
// This layer has the Ethernet header before the IP packet.
//

void
spindump_analyze_process_ethernet(struct spindump_analyze* state,
				  struct spindump_packet* packet,
				  struct spindump_connection** p_connection) {
  //
  // Check there is enough of the Ethernet header
  //

  if (packet->etherlen < spindump_ethernet_header_size ||
      packet->caplen < spindump_ethernet_header_size) {
    spindump_warnf("not enough bytes for the Ethernet header, only %u bytes in received frame",
		   packet->etherlen);
    state->stats->notEnoughPacketForEthernetHdr++;
    *p_connection = 0;
    return;
  }

  //
  // Branch based on the ether type
  //

  struct spindump_ethernet ethernet;
  spindump_protocols_ethernet_header_decode(packet->contents,&ethernet);
  switch (ethernet.ether_type) {

  case spindump_ethertype_ip:
    spindump_analyze_decodeiphdr(state,
				 packet,
				 spindump_ethernet_header_size,
				 p_connection);
    return;

  case spindump_ethertype_ip6:
    spindump_analyze_decodeip6hdr(state,
				  packet,
				  spindump_ethernet_header_size,
				  p_connection);
    return;

  default:
    spindump_debugf("received an unsupported ethertype %4x", ethernet.ether_type);
    state->stats->unsupportedEthertype++;
    *p_connection = 0;
    return;

  }

}

//
// This is the primary analysis function for reception of an IPv4
// packet. It is called from spindump_analyze_process, if the
// ethertype points to an IPv4 packet.
//

static void
spindump_analyze_decodeiphdr(struct spindump_analyze* state,
			     struct spindump_packet* packet,
			     unsigned int position,
			     struct spindump_connection** p_connection) {

  //
  // Some sanity checks
  //

  spindump_assert(state != 0);
  spindump_assert(spindump_packet_isvalid(packet));
  spindump_assert(p_connection != 0);

  //
  // Statistics update
  //

  state->stats->receivedIp++;

  //
  // Parse and verify IP header
  //

  if (packet->caplen < position) {
    state->stats->notEnoughPacketForIpHdr++;
    spindump_warnf("not enough bytes for the IP header (capture length only %u)", packet->caplen);
    *p_connection = 0;
    return;
  }
  
  struct spindump_ip ip;
  spindump_protocols_ip_header_decode(packet->contents + position,&ip);
  unsigned int ipHeaderSize = SPINDUMP_IP_HL(&ip)*4;
  if (ipHeaderSize < 20) {
    state->stats->invalidIpHdrSize++;
    spindump_warnf("packet header length %u less than 20 bytes", ipHeaderSize);
    *p_connection = 0;
    return;
  }
  
  uint8_t ipVersion = SPINDUMP_IP_V(&ip);
  if (ipVersion != 4) {
    state->stats->versionMismatch++;
    spindump_warnf("IP versions inconsistent in Ethernet frame and IP packet", SPINDUMP_IP_V(&ip));
    *p_connection = 0;
    return;
  }

  //
  // Verify packet length is appropriate
  //

  if (packet->caplen < position + ipHeaderSize) {
    state->stats->notEnoughPacketForIpHdr++;
    spindump_warnf("not enough bytes for the IP header (capture length only %u, IP header size %u)",
		   packet->caplen, ipHeaderSize);
    *p_connection = 0;
    return;
  }

  unsigned int ipPacketLength = ip.ip_len;
  if (ipPacketLength > packet->etherlen - position) {
    state->stats->invalidIpLength++;
    spindump_warnf("IP packet length is invalid (%u vs. %u)",
		   ipPacketLength,
		   packet->etherlen - position);
    *p_connection = 0;
    return;
  }

  uint8_t ecnFlags = SPINDUMP_IP_ECN(&ip);
  
  //
  // Check if the packet is a fragment
  //

  uint16_t off = ip.ip_off;
  if ((off & SPINDUMP_IP_OFFMASK) != 0) {
    state->stats->unhandledFragment++;
    spindump_debugf("ignored a fragment at offset %u", (off & SPINDUMP_IP_OFFMASK));
    *p_connection = 0;
    return;
  }

  //
  // Done with the IP header. Now look at what protocol (TCP, ICMP,
  // UDP, etc) is carried inside!
  //

  spindump_analyze_decodeippayload(state,
				   packet,
				   position,
				   ipHeaderSize,
				   ipVersion,
				   ecnFlags,
				   ipPacketLength,
				   ip.ip_proto,
				   position + ipHeaderSize,
				   p_connection);
}

//
// This is the primary analysis function for reception of an IPv6
// packet. It is called from spindump_analyze_process, if the
// ethertype points to an IPv6 packet.
//

static void
spindump_analyze_decodeip6hdr(struct spindump_analyze* state,
			      struct spindump_packet* packet,
			      unsigned int position,
			      struct spindump_connection** p_connection) {

  //
  // Some sanity checks
  //

  spindump_assert(state != 0);
  spindump_assert(spindump_packet_isvalid(packet));
  spindump_assert(p_connection != 0);

  //
  // Statistics update
  //

  state->stats->receivedIpv6++;

  //
  // Parse and verify IP header
  //

  if (packet->caplen < position) {
    state->stats->notEnoughPacketForIpHdr++;
    spindump_warnf("not enough bytes for the IPv6 header (capture length only %u)", packet->caplen);
    *p_connection = 0;
    return;
  }

  struct spindump_ip6 ip6;
  spindump_protocols_ip6_header_decode(packet->contents + position,&ip6);
  unsigned int ipHeaderSize = 40;
  uint8_t ipVersion = SPINDUMP_IP6_V(&ip6);
  if (ipVersion != 6) {
    state->stats->versionMismatch++;
    spindump_warnf("IP versions inconsistent in Ethernet frame and IP packet", SPINDUMP_IP6_V(&ip6));
    *p_connection = 0;
    return;
  }

  //
  // Verify packet length is appropriate
  //

  if (packet->caplen < position + ipHeaderSize) {
    state->stats->notEnoughPacketForIpHdr++;
    spindump_warnf("not enough bytes for the IPv6 header (capture length only %u, IP header size %u)",
		   packet->caplen, ipHeaderSize);
    *p_connection = 0;
    return;
  }

  unsigned int ipPacketLength = ipHeaderSize + (unsigned int)ip6.ip6_payloadlen;
  if (ipPacketLength > packet->etherlen - position) {
    state->stats->invalidIpLength++;
    spindump_warnf("IP packet length is invalid (%u vs. %u)",
		   ipPacketLength,
		   packet->etherlen - position);
    *p_connection = 0;
    return;
  }
  
  uint8_t ecnFlags = SPINDUMP_IP6_ECN(&ip6);
  
  //
  // Check if the packet is a fragment
  //

  uint8_t proto = ip6.ip6_nextheader;
  unsigned int passFh = 0;

  if (proto == SPINDUMP_IP6_FH_NEXTHDR) {

    unsigned int fhSize = spindump_ip6_fh_header_size;
    uint16_t pl = ip6.ip6_payloadlen;
    if (pl < fhSize || packet->caplen < position + ipHeaderSize + fhSize) {
      state->stats->fragmentTooShort++;
      spindump_debugf("not enough fragment header to process");
      *p_connection = 0;
      return;
    }
    struct spindump_ip6_fh fh;
    spindump_protocols_ip6_fh_header_decode(packet->contents + position + ipHeaderSize,&fh);
    uint16_t off = fh.fh_off;
    if (spindump_ip6_fh_fragoff(off) != 0) {
      state->stats->unhandledFragment++;
      spindump_debugf("ignored a fragment at offset %u", (off & SPINDUMP_IP_OFFMASK));
      *p_connection = 0;
      return;
    } else {
      passFh = fhSize;
      ipHeaderSize += fhSize;
    }
  }

  //
  // Done with the IP header. Now look at what protocol (TCP, ICMP,
  // UDP, etc) is carried inside!
  //

  spindump_analyze_decodeippayload(state,
				   packet,
				   position,
				   ipHeaderSize,
				   ipVersion,
					 ecnFlags,
				   ipPacketLength,
				   proto,
				   position + ipHeaderSize + passFh,
				   p_connection);
}

//
// Mark the reception of a packet belonging to a connection, increase
// statistics.
//
// If fromResponder = 1, the sending party is the server of the
// connection, if fromResponder = 0, it is the client.
//

void
spindump_analyze_process_pakstats(struct spindump_analyze* state,
				  struct spindump_connection* connection,
				  int fromResponder,
				  struct spindump_packet* packet,
				  unsigned int ipPacketLength,
					uint8_t ecnFlags) {

  //
  // Checks
  //

  spindump_assert(state != 0);
  spindump_assert(connection != 0);
  spindump_assert(spindump_isbool(fromResponder));
  spindump_assert(packet != 0);
  spindump_assert(spindump_packet_isvalid(packet));
	spindump_assert(ecnFlags <= 3);

  //
  // Update the statistics based on whether the packet was from side1
  // or side2.
  //

  if (fromResponder) {
    connection->latestPacketFromSide2 = packet->timestamp;
    connection->packetsFromSide2++;
    connection->bytesFromSide2 += ipPacketLength;
  } else {
    connection->latestPacketFromSide1 = packet->timestamp;
    connection->packetsFromSide1++;
    connection->bytesFromSide1 += ipPacketLength;
  }
  
  int ecnCe = 0;
  
  switch (ecnFlags) {
  case 0x1:
    if (fromResponder) {
      connection->ect0FromResponder++;
    } else {
      connection->ect0FromInitiator++;
    }
    break;
    
  case 0x2:
    if (fromResponder) {
      connection->ect1FromResponder++;
    } else {
      connection->ect1FromInitiator++;
    }
    break;
    
  case 0x3:
    ecnCe = 1;
    if (fromResponder) {
      connection->ceFromResponder++;
    } else {
      connection->ceFromInitiator++;
    }
    break;
    
  default:
    //
    // No ECN flags set
    //
    break;
  }
  
  //
  // Call some handlers, if any, for the new measurements
  //

  if (fromResponder && connection->packetsFromSide2 == 1) {
    spindump_analyze_process_handlers(state,
				      spindump_analyze_event_firstresponsepacket,
				      packet,
				      connection);
  }

  spindump_analyze_process_handlers(state,
				    spindump_analyze_event_newpacket,
				    packet,
				    connection);

	if (ecnCe) {
		spindump_analyze_process_handlers(state,
                                      fromResponder ? spindump_analyze_event_responderecnce :
																			spindump_analyze_event_initiatorecnce,
                                      packet,
                                      connection);
	}



  //
  // Loop through any possible aggregated connections this connection
  // belongs to, and report the same measurement udpates there.
  //

  struct spindump_connection_set_iterator iter;
  for (spindump_connection_set_iterator_initialize(&connection->aggregates,&iter);
       !spindump_connection_set_iterator_end(&iter);
       ) {

    struct spindump_connection* aggregate = spindump_connection_set_iterator_next(&iter);
    spindump_assert(aggregate != 0);
    spindump_analyze_process_pakstats(state,aggregate,fromResponder,packet,ipPacketLength,ecnFlags);

  }

}

//
// This is the primary IP payload processing function. An IP payload
// is, e.g., a TCP, ICMP, or UDP packet. If we get this far, the IP
// header (IPv4 or IPv6) has been checked and is valid.
//

static void
spindump_analyze_decodeippayload(struct spindump_analyze* state,
				 struct spindump_packet* packet,
				 unsigned int ipHeaderPosition,
				 unsigned int ipHeaderSize,
				 uint8_t ipVersion,
				 uint8_t ecnFlags,
				 unsigned int ipPacketLength,
				 unsigned char proto,
				 unsigned int payloadPosition,
				 struct spindump_connection** p_connection) {

  //
  // Sanity checks
  //

  spindump_assert(state != 0);
  spindump_assert(packet != 0);
  spindump_assert(spindump_packet_isvalid(packet));
  spindump_assert(ipHeaderPosition < payloadPosition);
  spindump_assert(ipHeaderSize > 0);
  spindump_assert(ipVersion == 4 || ipVersion == 6);
  spindump_assert(ipPacketLength > 0);
  spindump_assert(p_connection != 0);

  //
  // Check there is enough of the IP header
  //

  unsigned int iplen = packet->etherlen - ipHeaderPosition;
  if (iplen < ipHeaderSize ||
      packet->caplen < payloadPosition) {
    state->stats->notEnoughPacketForIpHdr++;
    spindump_warnf("not enough bytes for the IPv%u header (only %u bytes remain after Ethernet header)",
		   ipVersion,
		   iplen);
    *p_connection = 0;
    return;
  }

  //
  // Determine upper layer protocol lengths
  //

  unsigned int protolen = packet->etherlen - ipHeaderPosition - ipHeaderSize;
  spindump_deepdebugf("packet received with %u bytes, %u to ethernet, %u to ip (IPv%u), %u remains",
		      packet->etherlen,
		      ipHeaderPosition,
		      ipHeaderSize,
		      ipVersion,
		      protolen);
  spindump_assert(ipHeaderPosition + ipHeaderSize <= packet->caplen);
  unsigned int remainingCaplen = packet->caplen - ipHeaderPosition - ipHeaderSize;

  //
  // Account for statistics
  //

  if (ipVersion == 4) {
    state->stats->receivedIpBytes += (unsigned long long)(iplen);
  } else if (ipVersion == 6) {
    state->stats->receivedIpv6Bytes += (unsigned long long)(iplen);
  } else {
    spindump_errorf("should not process a non-IPv4 and non-IPv6 packet here");
    *p_connection = 0;
    return;
  }

  //
  // Branch based on the upper layer protocol
  //

  switch (proto) {

  case IPPROTO_TCP:
    spindump_analyze_process_tcp(state,
				 packet,
				 ipHeaderPosition,
				 ipHeaderSize,
				 ipVersion,
				 ecnFlags,
				 ipPacketLength,
				 ipHeaderPosition + ipHeaderSize,
				 protolen,
				 remainingCaplen,
				 p_connection);
    break;

  case IPPROTO_UDP:
    spindump_analyze_process_udp(state,
				 packet,
				 ipHeaderPosition,
				 ipHeaderSize,
				 ipVersion,
				 ecnFlags,
				 ipPacketLength,
				 ipHeaderPosition + ipHeaderSize,
				 protolen,
				 remainingCaplen,
				 p_connection);
    break;

  case IPPROTO_ICMP:
    spindump_analyze_process_icmp(state,
				  packet,
				  ipHeaderPosition,
				  ipHeaderSize,
				  ipVersion,
					ecnFlags,
				  ipPacketLength,
				  ipHeaderPosition + ipHeaderSize,
				  protolen,
				  remainingCaplen,
				  p_connection);
    break;

  case IPPROTO_ICMPV6:
    spindump_analyze_process_icmp6(state,
				   packet,
				   ipHeaderPosition,
				   ipHeaderSize,
				   ipVersion,
					 ecnFlags,
				   ipPacketLength,
				   ipHeaderPosition + ipHeaderSize,
				   protolen,
				   remainingCaplen,
				   p_connection);
    break;

  default:

    //
    // Debugs
    //

    spindump_debugf("received an unknown protocol %u", proto);

    //
    // Statistics update
    //

    state->stats->protocolNotSupported++;
    break;

  }

  //
  // If the packet was not a recognized protocol or if the relevant
  // TCP or other protocol analyzers failed to parse it an place into
  // an existing or new connection, the packet still needs to be
  // counted at least in the aggregate connections, e.g., host-to-host
  // or network-to-network stats.
  //

  if (*p_connection == 0) {
    spindump_analyze_otherippayload(state,
				    packet,
				    ipHeaderPosition,
				    ipHeaderSize,
				    ipVersion,
				    ecnFlags,
				    ipPacketLength,
				    p_connection);
  }
}

//
// This function is called to process an IP packet that carries a
// protocol that this analyzer does not recognise, or if it
// recognises, the packet is not correct or at least not parseable by
// the analyzer. The latter can happen, for instance, if the TCP
// options, DNS request format, etc. is incorrect. Such packets do
// still get counted, but not in any of the individual connections (as
// they cannot be parsed). They get counted in any aggregate counters,
// e.g., host-to-host aggregate connections between the two IP
// addresses indicated in the packet.
//

static void
spindump_analyze_otherippayload(struct spindump_analyze* state,
				struct spindump_packet* packet,
				unsigned int ipHeaderPosition,
				unsigned int ipHeaderSize,
				uint8_t ipVersion,
				uint8_t ecnFlags,
				unsigned int ipPacketLength,
				struct spindump_connection** p_connection) {
  //
  // Make some sanity checks on the input
  //

  spindump_assert(state != 0);
  spindump_assert(packet != 0);
  spindump_assert(spindump_packet_isvalid(packet));
  spindump_assert(ipHeaderSize > 0);
  spindump_assert(ipVersion == 4 || ipVersion == 6);
  spindump_assert(ipPacketLength > 0);
  spindump_assert(p_connection != 0);
  spindump_assert(*p_connection == 0);

  //
  // See if the packet falls under any of the aggregate connections,
  // and note the reception of an unmatching packet.
  //

  unsigned int i;
  spindump_address source;
  spindump_address destination;

  spindump_analyze_getsource(packet,ipVersion,ipHeaderPosition,&source);
  spindump_analyze_getdestination(packet,ipVersion,ipHeaderPosition,&destination);

  for (i = 0; i < state->table->nConnections; i++) {

    struct spindump_connection* connection = state->table->connections[i];
    if (connection != 0 &&
	spindump_connections_isaggregate(connection) &&
	spindump_connections_matches_aggregate_srcdst(&source,&destination,connection)) {

      //
      // Found a matching connection! Report it there.
      //
      
      spindump_analyze_process_aggregate(state,
					 connection,
					 packet,
					 ipHeaderPosition,
					 ipHeaderSize,
					 ipVersion,
					 ecnFlags,
					 ipPacketLength,
					 state->stats);
      
      //
      // Return the first matching connection to the caller; note that
      // there may be more than one match!
      //

      if (*p_connection == 0) {
	*p_connection = connection;
      }

    }
  }

  //
  // Not found or not recognisable. Ignore.
  //

  *p_connection = 0;

  //
  // Debug printouts
  //

  spindump_debugf("non-matching packet...");
}

//
// Event flag to string. The returned string points to a static area,
// and need not be deallocated.
//

const char*
spindump_analyze_eventtostring(spindump_analyze_event event) {
  if (event == 0) {
    return("none");
  } else if (event == spindump_analyze_event_newconnection) {
    return("newconnection");
  } else if (event == spindump_analyze_event_connectiondelete) {
    return("connectiondelete");
  } else if (event == spindump_analyze_event_newleftrttmeasurement) {
    return("newleftrttmeasurement");
  } else if (event == spindump_analyze_event_newrightrttmeasurement) {
    return("newrightrttmeasurement");
  } else if (event == spindump_analyze_event_initiatorspinflip) {
    return("initiatorspinflip");
  } else if (event == spindump_analyze_event_responderspinflip) {
    return("responderspinflip");
  } else if (event == spindump_analyze_event_initiatorspinvalue) {
    return("initiatorspinvalue");
  } else if (event == spindump_analyze_event_responderspinvalue) {
    return("responderspinvalue");
  } else if (event == spindump_analyze_event_newpacket) {
    return("newpacket");
  } else if (event == spindump_analyze_event_firstresponsepacket) {
    return("firstresponsepacket");
  } else if (event == spindump_analyze_event_statechange) {
    return("statechange");
  } else {
    return("multiple");
  }
}
