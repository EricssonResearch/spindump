
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
//  AUTHOR: JARI ARKKO AND MARCUS IHLAR
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
#include "spindump_analyze_ip.h"
#include "spindump_analyze_tcp.h"
#include "spindump_analyze_udp.h"
#include "spindump_analyze_quic.h"
#include "spindump_analyze_icmp.h"
#include "spindump_analyze_aggregate.h"
#include "spindump_event.h"

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
static int
spindump_analyze_connectionspecifichandlerstillinuse(struct spindump_analyze* state,
                                                     spindump_handler_mask mask);

//
// Actual code --------------------------------------------------------------------------------
//

//
// Create an object to represent an analyzer. Allocate memory as needed.
//

struct spindump_analyze*
spindump_analyze_initialize(unsigned int filterExceptionalValuePercentage,
                            unsigned long long bandwidthMeasurementPeriod) {

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
  struct spindump_analyze* state = (struct spindump_analyze*)spindump_malloc(size);
  if (state == 0) {
    spindump_errorf("cannot allocate analyzer state of %u bytes", size);
    return(0);
  }

  //
  // Initialize state
  //

  memset(state,0,size);
  state->table = spindump_connectionstable_initialize(bandwidthMeasurementPeriod);
  if (state->table == 0) {
    spindump_free(state);
    return(0);
  }
  state->stats = spindump_stats_initialize();
  if (state->stats == 0) {
    spindump_connectionstable_uninitialize(state->table);
    spindump_free(state);
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

  spindump_free(state);
}

//
// Register a handler for specific events
//

void
spindump_analyze_registerhandler(struct spindump_analyze* state,
                                 spindump_analyze_event eventmask,
                                 struct spindump_connection* connection,
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
  spindump_deepdeepdebugf("registered %uth handler %lx for %u", state->nHandlers, (unsigned long)handler, eventmask);
  state->nHandlers++;
}

//
// De-register a handler
//

void
spindump_analyze_unregisterhandler(struct spindump_analyze* state,
                                   spindump_analyze_event eventmask,
                                   struct spindump_connection* connection,
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
  // Find the registration from earlier
  //

  for (unsigned int i = 0; i < state->nHandlers; i++) {

    struct spindump_analyze_handler* handlerPtr = &state->handlers[i];
    if (handlerPtr->eventmask == eventmask &&
        ((!handlerPtr->connectionSpecific && connection == 0) ||
         (handlerPtr->connectionSpecific && connection != 0)) &&
        handlerPtr->function == handler &&
        handlerPtr->handlerData == handlerData) {

      //
      // If this was a connection-specific handler, deregister the
      // handler from the bitmask in the connection object.
      //

      if (connection != 0) {
        
        spindump_handler_mask mask = (1 << i);
        
        //
        // Check that the mask was on
        //
        
        if ((connection->handlerMask & mask) == 0) {
          spindump_errorf("unregistering a handler for a connection for which it was not registered");
        }

        //
        // Zero the bit in the mask
        //
        
        connection->handlerMask &= (~mask);
        spindump_assert((connection->handlerMask & mask) == 0);

        //
        // Finally, if the handler is still registered in some other
        // connection objects, we cannot entirely delete it, but
        // rather just the deletion from the bit mask is enough.
        //
        
        if (spindump_analyze_connectionspecifichandlerstillinuse(state,mask)) {
          spindump_deepdebugf("connection-specific handler is still in use by some other connections");
          return;
        }
      }
      
      //
      // Found the matching registration. Delete it.
      //
      
      handlerPtr->eventmask = 0;
      handlerPtr->connectionSpecific = 0;
      handlerPtr->function = 0;
      handlerPtr->handlerData = 0;

      //
      // Also decrease nHandlers if this was the last item in the array
      //
      
      while (i == state->nHandlers - 1 &&
             state->nHandlers > 0 &&
             handlerPtr->eventmask == 0 &&
             handlerPtr->function == 0 &&
             handlerPtr->handlerData == 0) {
        state->nHandlers--;
        if  (state->nHandlers > 0) {
          i = state->nHandlers - 1;
          handlerPtr = &state->handlers[i];
        }
      }
      
      //
      // Done. Return.
      //
      
      return;
    }
  }

  //
  // Not found. Signal an error, but we can recover.
  //
  
  spindump_errorf("de-registering a non-registered handler");
}

static int
spindump_analyze_connectionspecifichandlerstillinuse(struct spindump_analyze* state,
                                                     spindump_handler_mask mask) {
  for (unsigned int i = 0; i < state->table->nConnections; i++) {
    
    struct spindump_connection* connection = state->table->connections[i];
    
    if (connection != 0 &&
        (connection->handlerMask & mask) != 0) {
      
      //
      // Found. Return 1.
      //
      
      return(1);
      
    }
    
  }
  
  //
  // Not found
  //
  
  return(0);
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

  spindump_assert((event & spindump_analyze_event_alllegal) == event);
  spindump_assert(connection != 0);
  spindump_deepdebugf("calling handlers for event %x (%s) for connection %u of type %u packet %lx",
                      event,
                      spindump_analyze_eventtostring(event),
                      connection->id,
                      connection->type,
                      (unsigned long)packet);
  spindump_assert(state != 0);
  spindump_assert(packet == 0 || spindump_packet_isvalid(packet));
  
  //
  // Scan through the registered handlers and execute them if they
  // match this event
  //
  
  for (unsigned int i = 0; i < state->nHandlers; i++) {
    struct spindump_analyze_handler* handler = &state->handlers[i];
    if ((handler->eventmask & event) != 0) {
      spindump_assert(spindump_analyze_max_handlers == spindump_connection_max_handlers);
      spindump_assert(i < spindump_connection_max_handlers);
      state->stats->analyzerHandlerCalls++;
      spindump_deepdebugf("calling %uth handler %x (%lx)",
                          state->stats->analyzerHandlerCalls,
                          handler->eventmask,
                          (unsigned long)handler->function);
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
  spindump_assert(state->stats != 0);
  spindump_assert(packet != 0);
  spindump_assert(spindump_packet_isvalid(packet));
  spindump_assert(p_connection != 0);

  //
  // Store a count of events before processing this packet
  //
  
  packet->analyzerHandlerCalls = state->stats->analyzerHandlerCalls;
  spindump_deepdebugf("initialized handler counter to %u for spindump_analyze_process",
                      packet->analyzerHandlerCalls);
  
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

  //
  // We cannot simply convert to correct byte-order, as per
  // description above, hence we need to prepare to be ready to
  // receive in either byte order
  //
  
  switch (nullInt) {
  case 0x00000002:
  case 0x02000000:
    spindump_analyze_ip_decodeiphdr(state,
                                    packet,
                                    spindump_null_header_size,
                                    p_connection);
    return;

  case 0x00000016:
  case 0x16000000:
  case 0x0000001C:
  case 0x1C000000:
  case 0x0000001E:
  case 0x1E000000:
    spindump_analyze_ip_decodeip6hdr(state,
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
    spindump_analyze_ip_decodeiphdr(state,
                                    packet,
                                    spindump_ethernet_header_size,
                                    p_connection);
    return;

  case spindump_ethertype_ip6:
    spindump_analyze_ip_decodeip6hdr(state,
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
  spindump_deepdeepdebugf("pakstats got a packet of length %u for a connection of type %s",
                          ipPacketLength,
                          spindump_connection_type_to_string(connection->type));
  
  //
  // Update the statistics based on whether the packet was from side1
  // or side2.
  //

  if (fromResponder) {
    connection->latestPacketFromSide2 = packet->timestamp;
    connection->packetsFromSide2++;
    spindump_bandwidth_newpacket(&connection->bytesFromSide2,ipPacketLength,&packet->timestamp);
  } else {
    connection->latestPacketFromSide1 = packet->timestamp;
    connection->packetsFromSide1++;
    spindump_bandwidth_newpacket(&connection->bytesFromSide1,ipPacketLength,&packet->timestamp);
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

  if (ecnCe) {
    spindump_analyze_process_handlers(state,
                                      fromResponder ? spindump_analyze_event_responderecnce :
                                      spindump_analyze_event_initiatorecnce,
                                      packet,
                                      connection);
  }

  //
  // Call the generic "new packet" handler unless some other handler was called earlier
  //

  spindump_deepdebugf("considering whether to call newpacket handler %u == %u?",
                      packet->analyzerHandlerCalls,state->stats->analyzerHandlerCalls);
  if (packet->analyzerHandlerCalls == state->stats->analyzerHandlerCalls) {
    spindump_analyze_process_handlers(state,
                                      spindump_analyze_event_newpacket,
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
    spindump_deepdeepdebugf("pakstats recursing to an aggregate for a packet of length %u", ipPacketLength);
    spindump_analyze_process_pakstats(state,aggregate,fromResponder,packet,ipPacketLength,ecnFlags);

  }

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
  } else if (event == spindump_analyze_event_changeconnection) {
    return("changeconnection");
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
  } else if (event == spindump_analyze_event_initiatorrtlossmeasurement) {
    return("initiatorrtlossmeasurement");
  } else if (event == spindump_analyze_event_responderrtlossmeasurement) {
    return("responderrtlossmeasurement");
  } else {
    return("multiple");
  }
}
