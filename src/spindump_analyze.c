
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
				 unsigned int ipPacketLength,
				 unsigned char proto,
				 unsigned int payloadPosition,
				 struct spindump_connection** p_connection);

//
// Actual code --------------------------------------------------------------------------------
//

//
// Create an object to represent an analyzer. Allocate memory as needed.
//

struct spindump_analyze*
spindump_analyze_initialize(struct spindump_connectionstable* table) {

  //
  // Checks
  //
  
  spindump_assert(table != 0);
  if (spindump_connection_max_handlers != spindump_analyze_max_handlers) {
    spindump_fatalf("the maximum number of registered handlers must be defined to be the same, "
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
    spindump_fatalf("cannot allocate analyzer state of %u bytes", size);
    return(0);
  }
  
  //
  // Initialize state
  // 
  
  memset(state,0,size);
  state->table = table;
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
  spindump_assert(state != 0);
  spindump_assert(state->table != 0);
  spindump_assert(state->stats != 0);
  spindump_connectionstable_uninitialize(state->table);
  spindump_stats_uninitialize(state->stats);
  memset(state,0,sizeof(*state));
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
    spindump_fatalf("cannot add any more handlers, supporting only max %u handlers", spindump_analyze_max_handlers);
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
  spindump_assert(connection != 0);

  //
  // Scan through the registered handlers and execute them if they
  // match this event
  // 
  
  for (unsigned int i = 0; i < state->nHandlers; i++) {
    struct spindump_analyze_handler* handler = &state->handlers[i];
    if ((handler->eventmask & event) != 0) {
      spindump_assert(spindump_analyze_max_handlers == spindump_connection_max_handlers);
      spindump_assert(i < spindump_connection_max_handlers);
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
  if (ipVersion == 4) {
    const struct spindump_ip* iphdr = (const struct spindump_ip*)(packet->contents + ipHeaderPosition);
    spindump_address_frombytes(address,AF_INET,(unsigned char*)&iphdr->ip_src);
  } else if (ipVersion == 6) {
    const struct spindump_ip6* ip6hdr = (const struct spindump_ip6*)(packet->contents + ipHeaderPosition);
    spindump_address_frombytes(address,AF_INET6,(unsigned char*)&ip6hdr->source);
  } else {
    spindump_fatalf("no version set");
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
  if (ipVersion == 4) {
    const struct spindump_ip* iphdr = (const struct spindump_ip*)(packet->contents + ipHeaderPosition);
    spindump_address_frombytes(address,AF_INET,(unsigned char*)&iphdr->ip_dst);
  } else if (ipVersion == 6) {
    const struct spindump_ip6* ip6hdr = (const struct spindump_ip6*)(packet->contents + ipHeaderPosition);
    spindump_address_frombytes(address,AF_INET6,(unsigned char*)&ip6hdr->destination);
  } else {
    spindump_fatalf("no version set");
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
// "packet" correctly. For instance, the packet->ip or packet->ip6
// pointer needs to have already been set, the packet->tcp or
// packet->udp needs to have been set for TCP and UDP packets, etc.
// 

void
spindump_analyze_process(struct spindump_analyze* state,
			 struct spindump_packet* packet,
			 struct spindump_connection** p_connection) {

  //
  // Checks
  // 

  spindump_assert(state != 0);
  spindump_assert(packet != 0);
  spindump_assert(p_connection != 0);
  
  //
  // Check there is enough of the Ethernet header
  // 
  
  if (packet->etherlen < spindump_ethernet_header_size ||
      packet->caplen < spindump_ethernet_header_size) {
    spindump_warnf("not enough bytes for the Ethernet header, only %u bytes in received frame",
		   packet->etherlen);
    *p_connection = 0;
    return;
  }
  
  //
  // Branch based on the ether type
  // 
  
  const struct spindump_ethernet *ethernet = (const struct spindump_ethernet*)packet->contents;
  switch (htons(ethernet->etherType)) {
    
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
    spindump_debugf("received an unsupported ethertype %4x", htons(ethernet->etherType));
    state->stats->unsupportedEthertype++;
    *p_connection = 0;
    return;
    
  }
  
}

static void
spindump_analyze_decodeiphdr(struct spindump_analyze* state,
			     struct spindump_packet* packet,
			     unsigned int position,
			     struct spindump_connection** p_connection) {
  
  state->stats->receivedIp++;
  const struct spindump_ip* ip = (const struct spindump_ip*)(packet->contents + position);
  unsigned int ipHeaderSize = SPINDUMP_IP_HL(ip)*4;
  if (ipHeaderSize < 20) {
    state->stats->invalidIpHdrSize++;
    spindump_warnf("packet header length %u less than 20 bytes", ipHeaderSize);
    *p_connection = 0;
    return;
  }
  
  uint8_t ipVersion = SPINDUMP_IP_V(ip);
  if (ipVersion != 4) {
    state->stats->versionMismatch++;
    spindump_warnf("IP versions inconsistent in Ethernet frame and IP packet", SPINDUMP_IP_V(ip));
    *p_connection = 0;
    return;
  }

  //
  // Verify packet length is appropriate
  // 
  
  unsigned int ipPacketLength = ntohs(ip->ip_len);
  if (ipPacketLength > packet->etherlen - position) {
    state->stats->invalidIpLength++;
    spindump_warnf("IP packet length is invalid (%u vs. u%)",
		   ipPacketLength,
		   packet->etherlen - position);
    *p_connection = 0;
    return;
  }
  
  spindump_analyze_decodeippayload(state,
				   packet,
				   position,
				   ipHeaderSize,
				   ipVersion,
				   ipPacketLength,
				   ip->ip_proto,
				   position + ipHeaderSize,
				   p_connection);
}

static void
spindump_analyze_decodeip6hdr(struct spindump_analyze* state,
			      struct spindump_packet* packet,
			      unsigned int position,
			      struct spindump_connection** p_connection) {
  
  state->stats->receivedIpv6++;
  const struct spindump_ip6* ip6 = (const struct spindump_ip6*)(packet->contents + position);
  unsigned int ipHeaderSize = 40;
  uint8_t ipVersion = SPINDUMP_IP6_V(ip6);
  if (ipVersion != 6) {
    state->stats->versionMismatch++;
    spindump_warnf("IP versions inconsistent in Ethernet frame and IP packet", SPINDUMP_IP6_V(ip6));
    *p_connection = 0;
    return;
  }

  //
  // Verify packet length is appropriate
  // 
  
  unsigned int ipPacketLength = ipHeaderSize + (unsigned int)ntohs(ip6->ip6_payloadlen);
  if (ipPacketLength > packet->etherlen - position) {
    state->stats->invalidIpLength++;
    spindump_warnf("IP packet length is invalid (%u vs. u%)",
		   ipPacketLength,
		   packet->etherlen - position);
    *p_connection = 0;
    return;
  }
  
  spindump_analyze_decodeippayload(state,
				   packet,
				   position,
				   ipHeaderSize,
				   ipVersion,
				   ipPacketLength,
				   ip6->ip6_nextheader,
				   position + ipHeaderSize,
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
				  unsigned int ipPacketLength) {

  //
  // Checks
  // 

  spindump_assert(state != 0);
  spindump_assert(connection != 0);
  spindump_assert(fromResponder == 0 || fromResponder == 1);
  spindump_assert(packet != 0);
  
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

  //
  // Call some handlers, if any, for the new measurements
  // 
  
  spindump_analyze_process_handlers(state,
				    spindump_analyze_event_newpacket,
				    packet,
				    connection);
  
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
    spindump_analyze_process_pakstats(state,aggregate,fromResponder,packet,ipPacketLength);
    
  }
  
}

static void
spindump_analyze_decodeippayload(struct spindump_analyze* state,
				 struct spindump_packet* packet,
				 unsigned int ipHeaderPosition,
				 unsigned int ipHeaderSize,
				 uint8_t ipVersion,
				 unsigned int ipPacketLength,
				 unsigned char proto,
				 unsigned int payloadPosition,
				 struct spindump_connection** p_connection) {
  
  //
  // Sanity checks
  // 
  
  spindump_assert(state != 0);
  spindump_assert(packet != 0);
  spindump_assert(packet != 0);
  spindump_assert(p_connection != 0);
  
  //
  // Check there is enough of the IP header
  // 
  
  unsigned int iplen = packet->etherlen - ipHeaderPosition;
  if (iplen < ipHeaderSize ||
      packet->caplen < payloadPosition) {
    state->stats->notEnoughPacketForIpHdr++;
    spindump_warnf("not enough bytes IPv%u header (only %u bytes remain after Ethernet header)",
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
  
  //
  // Account for statistics
  // 
  
  if (ipVersion == 4) {
    state->stats->receivedIpBytes += (unsigned long long)(iplen);
  } else if (ipVersion == 6) {
    state->stats->receivedIpv6Bytes += (unsigned long long)(iplen);
  } else {
    spindump_fatalf("should not process a non-IPv4 and non-IPv6 packet here");
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
				 ipPacketLength,
				 ipHeaderPosition + ipHeaderSize,
				 protolen,
				 p_connection);
    return;
    
  case IPPROTO_UDP:
    spindump_analyze_process_udp(state,
				 packet,
				 ipHeaderPosition,
				 ipHeaderSize,
				 ipVersion,
				 ipPacketLength,
				 ipHeaderPosition + ipHeaderSize,
				 protolen,
				 p_connection);
    return;
    
  case IPPROTO_ICMP:
    spindump_analyze_process_icmp(state,
				  packet,
				  ipHeaderPosition,
				  ipHeaderSize,
				  ipVersion,
				  ipPacketLength,
				  ipHeaderPosition + ipHeaderSize,
				  protolen,
				  p_connection);
    return;
    
  case IPPROTO_ICMPV6:
    spindump_analyze_process_icmp6(state,
				   packet,
				   ipHeaderPosition,
				   ipHeaderSize,
				   ipVersion,
				   ipPacketLength,
				   ipHeaderPosition + ipHeaderSize,
				   protolen,
				   p_connection);
    return;
    
  default:

    //
    // Debugs
    // 
    
    spindump_debugf("received an unknown protocol %u", proto);
    
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
	spindump_analyze_process_aggregate(connection,packet,state->stats);
	*p_connection = connection;
      }
    }
    
    //
    // Not found or not recognisable. Ignore.
    // 

    //
    // Debug printouts
    // 
    
    spindump_debugf("non-matching packet...");
    state->stats->protocolNotSupported++;
    *p_connection = 0;
    return;
    
  }
}


