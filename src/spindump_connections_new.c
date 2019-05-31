
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
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include "spindump_util.h"
#include "spindump_seq.h"
#include "spindump_rtt.h"
#include "spindump_spin_structs.h"
#include "spindump_connections.h"
#include "spindump_connections_set.h"
#include "spindump_table.h"
#include "spindump_stats.h"
#include "spindump_analyze_quic_parser.h"
#include "spindump_spin.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static void
spindump_connections_newconnection_aux(struct spindump_connection* connection,
                                       enum spindump_connection_type type,
                                       const struct timeval* when,
                                       int manuallyCreated);
static void
spindump_connections_newconnection_addtoaggregates(struct spindump_connection* connection,
                                                   struct spindump_connectionstable* table);

//
// Actual code --------------------------------------------------------------------------------
//

//
// Helper function to fill in a new connection object with its basic
// fields set correctly.
//
// Note: this function is not thread safe.
//

static void
spindump_connections_newconnection_aux(struct spindump_connection* connection,
                                       enum spindump_connection_type type,
                                       const struct timeval* when,
                                       int manuallyCreated) {

  //
  // Ensure connection fields are all set to 0s.
  // 
  
  memset(connection,0,sizeof(*connection));

  //
  // Generate a unique id for a connection, using a counter
  // 
  
  static unsigned int generatedIdCounter = 0;
  connection->id = generatedIdCounter++;
  spindump_deepdeepdebugf("spindump_connections_newconnection_aux %u %s",
                          connection->id, spindump_connection_type_to_string(type));
  
  //
  // Set the basic fields of the connection
  // 
  
  connection->type = type;
  connection->manuallyCreated = manuallyCreated;
  connection->creationTime = *when;
  connection->latestPacketFromSide1 = *when;
  spindump_zerotime(&connection->latestPacketFromSide2);
  connection->packetsFromSide1 = 0;
  connection->packetsFromSide2 = 0;
  spindump_bandwidth_initialize(&connection->bytesFromSide1);
  spindump_bandwidth_initialize(&connection->bytesFromSide2);
  spindump_rtt_initialize(&connection->leftRTT);
  spindump_rtt_initialize(&connection->rightRTT);
  spindump_connections_set_initialize(&connection->aggregates);

  //
  // Do any initialization that is connection-type -dependent (e.g.,
  // TCP connections need their sequence number trackers initialized
  // properly).
  // 
  
  switch (type) {

  case spindump_connection_transport_tcp:
    spindump_seqtracker_initialize(&connection->u.tcp.side1Seqs);
    spindump_seqtracker_initialize(&connection->u.tcp.side2Seqs);
    break;

  case spindump_connection_transport_udp:
    break;

  case spindump_connection_transport_dns:
    spindump_messageidtracker_initialize(&connection->u.dns.side1MIDs);
    spindump_messageidtracker_initialize(&connection->u.dns.side2MIDs);
    break;

  case spindump_connection_transport_coap:
    spindump_messageidtracker_initialize(&connection->u.coap.side1MIDs);
    spindump_messageidtracker_initialize(&connection->u.coap.side2MIDs);
    break;

  case spindump_connection_transport_quic:
    spindump_spintracker_initialize(&connection->u.quic.spinFromPeer1to2);
    spindump_spintracker_initialize(&connection->u.quic.spinFromPeer2to1);
    connection->u.quic.side1initialPacket = *when;
    spindump_zerotime(&connection->u.quic.side2initialResponsePacket);
    connection->u.quic.initialRightRTT = spindump_rtt_infinite;
    connection->u.quic.initialLeftRTT = spindump_rtt_infinite;
    break;

  case spindump_connection_transport_icmp:
    break;

  case spindump_connection_aggregate_hostpair:
    spindump_connections_set_initialize(&connection->u.aggregatehostpair.connections);
    break;

  case spindump_connection_aggregate_hostnetwork:
    spindump_connections_set_initialize(&connection->u.aggregatehostnetwork.connections);
    break;

  case spindump_connection_aggregate_networknetwork:
    spindump_connections_set_initialize(&connection->u.aggregatenetworknetwork.connections);
    break;

  case spindump_connection_aggregate_multicastgroup:
    spindump_connections_set_initialize(&connection->u.aggregatemulticastgroup.connections);
    break;

  default:
    spindump_errorf("invalid connection type %u in spindump_connections_newconnection_aux",
                    connection->type);
    break;
    
  }
}

//
// Add a new connection to any already existing aggregates it might
// fall under. Search the table of connections to look for aggregate
// connections that match this particular new connection's source and
// destination address.
// 

static void
spindump_connections_newconnection_addtoaggregates(struct spindump_connection* connection,
                                                   struct spindump_connectionstable* table) {
  spindump_debugf("looking at aggregates that the new connection %u might fit into",
                  connection->id);
  for (unsigned int i = 0; i < table->nConnections; i++) {
    struct spindump_connection* aggregate = table->connections[i];
    if (aggregate != 0 &&
        spindump_connections_isaggregate(aggregate)) {

      spindump_deepdebugf("testing aggregate %u", aggregate->id);
      
      if (spindump_connections_matches_aggregate_connection(connection,aggregate)) {

        //
        // This aggregate matches the new connection. Add to a list of
        // aggregates this connection belongs to.
        // 
        
        spindump_debugf("connection %u matches aggregate %u",
                        connection->id, aggregate->id);
        spindump_connections_set_add(&connection->aggregates,aggregate);
        
        //
        // Add to the aggregate's list of what connections belong to it.
        // 
        
        switch (aggregate->type) {
          
        case spindump_connection_aggregate_hostpair:
          spindump_connections_set_add(&aggregate->u.aggregatehostpair.connections,connection);
          break;
          
        case spindump_connection_aggregate_hostnetwork:
          spindump_connections_set_add(&aggregate->u.aggregatehostnetwork.connections,connection);
          break;
          
        case spindump_connection_aggregate_networknetwork:
          spindump_connections_set_add(&aggregate->u.aggregatenetworknetwork.connections,connection);
          break;
          
        case spindump_connection_aggregate_multicastgroup:
          spindump_connections_set_add(&aggregate->u.aggregatemulticastgroup.connections,connection);
          break;

        case spindump_connection_transport_udp:
        case spindump_connection_transport_tcp:
        case spindump_connection_transport_quic:
        case spindump_connection_transport_dns:
        case spindump_connection_transport_coap:
        case spindump_connection_transport_icmp:
        default:
          spindump_errorf("invalid connection type %u in spindump_connections_newconnection_addtoaggregates",
                          aggregate->type);
          break;
          
        }
      }
    }
    
  }
}

//
// This is the main function for creating a new connection. The
// parameter table holds the object that keeps track of all
// connections, type is the new connection's type, when is the time at
// which point the connection is created, and manuallyCreated is set
// to 1 when the connection is being setup by management rather than
// dynamically through seeing a new flow in the network.
// 
    
struct spindump_connection*
spindump_connections_newconnection(struct spindump_connectionstable* table,
                                   enum spindump_connection_type type,
                                   const struct timeval* when,
                                   int manuallyCreated) {

  //
  // Sanity checks and debugs
  //

  spindump_assert(table != 0);
  spindump_assert(when != 0);
  spindump_deepdeepdebugf("spindump_connections_newconnection %s",
                          spindump_connection_type_to_string(type));
  
  //
  // Allocate the object
  // 
  
  unsigned int size = sizeof(struct spindump_connection);
  struct spindump_connection* connection = (struct spindump_connection*)spindump_malloc(size);
  if (connection == 0) {
    spindump_errorf("cannot allocate memory for a connection of size %u", size);
    return(0);
  }

  //
  // Initialize counters etc
  // 
  
  spindump_connections_newconnection_aux(connection,type,when,manuallyCreated);
  
  //
  // Look for a place in the connections table
  // 
  
  unsigned int i;
  for (i = 0; i < table->nConnections; i++) {
    if (table->connections[i] == 0) {
      table->connections[i] = connection;
      return(connection);
    }
  }

  //
  // No reclaimed place, but maybe space between used space and allocated space?
  // 

  if (table->nConnections < table->maxNConnections) {
    table->connections[table->nConnections++] = connection;
    return(connection);
  }

  //
  // No space, need to reallocate table
  // 
  
  table->maxNConnections *= 2;
  unsigned int newtabsize = table->maxNConnections * sizeof(struct spindump_connection*);
  struct spindump_connection** oldtable = table->connections;
  struct spindump_connection** newtable = (struct spindump_connection**)spindump_malloc(newtabsize);
  if (newtable == 0) {
    spindump_errorf("cannot allocate memory for a connection table of size %u", newtabsize);
    spindump_deepdebugf("free connection after an error");
    spindump_free(connection);
    return(0);
  }
  table->connections = newtable;
  memset(newtable,0,newtabsize);
  for (i = 0; i < table->nConnections; i++) {
    table->connections[i] = oldtable[i];
  }
  spindump_deepdebugf("free oldtable after a growth");
  spindump_free(oldtable);
  table->connections[table->nConnections++] = connection;
  spindump_assert(table->nConnections < table->maxNConnections);
  return(connection);
  
}

//
// Create a new connection for an ICMP flow that has been observed in
// the network.
// 

struct spindump_connection*
spindump_connections_newconnection_icmp(const spindump_address* side1address,
                                        const spindump_address* side2address,
                                        u_int8_t side1peerType,
                                        u_int16_t side1peerId,
                                        const struct timeval* when,
                                        struct spindump_connectionstable* table) {
  spindump_assert(side1address != 0);
  spindump_assert(side2address != 0);
  spindump_assert(table != 0);
  
  struct spindump_connection* connection =
    spindump_connections_newconnection(table,spindump_connection_transport_icmp,when,0);
  if (connection == 0) return(0);
  
  connection->state = spindump_connection_state_establishing;
  connection->u.icmp.side1peerAddress = *side1address;
  connection->u.icmp.side2peerAddress = *side2address;
  connection->u.icmp.side1peerType = side1peerType;
  connection->u.icmp.side1peerId = side1peerId;
  connection->u.icmp.side1peerLatestSequence = 0;
  spindump_connections_newconnection_addtoaggregates(connection,table);
  
  spindump_debugf("created a new ICMP connection %u", connection->id);
  return(connection);
}

//
// Create a new connection for an TCP flow that has been observed in
// the network.
// 

struct spindump_connection*
spindump_connections_newconnection_tcp(const spindump_address* side1address,
                                       const spindump_address* side2address,
                                       spindump_port side1port,
                                       spindump_port side2port,
                                       const struct timeval* when,
                                       struct spindump_connectionstable* table) {
  
  spindump_assert(side1address != 0);
  spindump_assert(side2address != 0);
  spindump_assert(table != 0);
  
  struct spindump_connection* connection =
    spindump_connections_newconnection(table,spindump_connection_transport_tcp,when,0);
  if (connection == 0) return(0);
  
  connection->state = spindump_connection_state_establishing;
  connection->u.tcp.side1peerAddress = *side1address;
  connection->u.tcp.side2peerAddress = *side2address;
  connection->u.tcp.side1peerPort = side1port;
  connection->u.tcp.side2peerPort = side2port;
  spindump_connections_newconnection_addtoaggregates(connection,table);
  
  spindump_debugf("created a new TCP connection %u", connection->id);
  return(connection);
}

//
// Create a new connection for a UDP flow that has been observed in
// the network.
// 

struct spindump_connection*
spindump_connections_newconnection_udp(const spindump_address* side1address,
                                       const spindump_address* side2address,
                                       spindump_port side1port,
                                       spindump_port side2port,
                                       const struct timeval* when,
                                       struct spindump_connectionstable* table) {
  
  spindump_assert(side1address != 0);
  spindump_assert(side2address != 0);
  spindump_assert(table != 0);
  
  struct spindump_connection* connection =
    spindump_connections_newconnection(table,spindump_connection_transport_udp,when,0);
  if (connection == 0) return(0);
  
  connection->state = spindump_connection_state_establishing;
  connection->u.udp.side1peerAddress = *side1address;
  connection->u.udp.side2peerAddress = *side2address;
  connection->u.udp.side1peerPort = side1port;
  connection->u.udp.side2peerPort = side2port;
  spindump_connections_newconnection_addtoaggregates(connection,table);
  
  spindump_debugf("created a new UDP connection %u", connection->id);
  return(connection);
}

//
// Create a new connection for a DNS flow that has been observed in
// the network.
// 

struct spindump_connection*
spindump_connections_newconnection_dns(const spindump_address* side1address,
                                       const spindump_address* side2address,
                                       spindump_port side1port,
                                       spindump_port side2port,
                                       const struct timeval* when,
                                       struct spindump_connectionstable* table) {
  
  spindump_assert(side1address != 0);
  spindump_assert(side2address != 0);
  spindump_assert(table != 0);
  
  struct spindump_connection* connection =
    spindump_connections_newconnection(table,spindump_connection_transport_dns,when,0);
  if (connection == 0) return(0);
  
  connection->state = spindump_connection_state_establishing;
  connection->u.dns.side1peerAddress = *side1address;
  connection->u.dns.side2peerAddress = *side2address;
  connection->u.dns.side1peerPort = side1port;
  connection->u.dns.side2peerPort = side2port;
  spindump_connections_newconnection_addtoaggregates(connection,table);
  
  spindump_debugf("created a new DNS connection %u", connection->id);
  return(connection);
}

//
// Create a new connection for a COAP flow that has been observed in
// the network.
// 

struct spindump_connection*
spindump_connections_newconnection_coap(const spindump_address* side1address,
                                        const spindump_address* side2address,
                                        spindump_port side1port,
                                        spindump_port side2port,
                                        const struct timeval* when,
                                        struct spindump_connectionstable* table) {
  
  spindump_assert(side1address != 0);
  spindump_assert(side2address != 0);
  spindump_assert(table != 0);
  
  struct spindump_connection* connection =
    spindump_connections_newconnection(table,spindump_connection_transport_coap,when,0);
  if (connection == 0) return(0);
  
  connection->state = spindump_connection_state_establishing;
  connection->u.coap.side1peerAddress = *side1address;
  connection->u.coap.side2peerAddress = *side2address;
  connection->u.coap.side1peerPort = side1port;
  connection->u.coap.side2peerPort = side2port;
  spindump_connections_newconnection_addtoaggregates(connection,table);
  
  spindump_debugf("created a new COAP connection %u", connection->id);
  return(connection);
}

//
// Create a new connection for an QUIC flow that has been observed in
// the network. Identify the flow based on the 5-tuple of the UDP
// transport connection that carries it.
// 

struct spindump_connection*
spindump_connections_newconnection_quic_5tuple(const spindump_address* side1address,
                                               const spindump_address* side2address,
                                               spindump_port side1port,
                                               spindump_port side2port,
                                               const struct timeval* when,
                                               struct spindump_connectionstable* table) {
  
  spindump_assert(side1address != 0);
  spindump_assert(side2address != 0);
  spindump_assert(table != 0);

  spindump_deepdeepdebugf("spindump_connections_newconnection_quic_5tuple");
  struct spindump_connection* connection =
    spindump_connections_newconnection(table,spindump_connection_transport_quic,when,0);
  if (connection == 0) return(0);
  
  connection->state = spindump_connection_state_establishing;
  connection->u.quic.side1peerAddress = *side1address;
  connection->u.quic.side2peerAddress = *side2address;
  connection->u.quic.side1peerPort = side1port;
  connection->u.quic.side2peerPort = side2port;
  memset(&connection->u.quic.peer1ConnectionID,0,sizeof(struct spindump_quic_connectionid));
  memset(&connection->u.quic.peer2ConnectionID,0,sizeof(struct spindump_quic_connectionid));
  spindump_connections_newconnection_addtoaggregates(connection,table);
  
  spindump_debugf("created a new QUIC connection %u via a 5-tuple", connection->id);
  return(connection);
}

//
// Create a new connection for an QUIC flow that has been observed in
// the network. Identify the connection via the 5-tuple of the UDP
// transport connection and the two QUIC Connection IDs.
// 

struct spindump_connection*
spindump_connections_newconnection_quic_5tupleandcids(const spindump_address* side1address,
                                                      const spindump_address* side2address,
                                                      spindump_port side1port,
                                                      spindump_port side2port,
                                                      struct spindump_quic_connectionid* destinationCid,
                                                      struct spindump_quic_connectionid* sourceCid,
                                                      const struct timeval* when,
                                                      struct spindump_connectionstable* table) {
  
  spindump_assert(side1address != 0);
  spindump_assert(side2address != 0);
  spindump_assert(destinationCid != 0);
  spindump_assert(sourceCid != 0);
  spindump_assert(table != 0);
  spindump_deepdeepdebugf("spindump_connections_newconnection_quic_5tupleandcids");
  
  struct spindump_connection* connection =
    spindump_connections_newconnection(table,spindump_connection_transport_quic,when,0);
  if (connection == 0) return(0);
  
  connection->state = spindump_connection_state_establishing;
  connection->u.quic.side1peerAddress = *side1address;
  connection->u.quic.side2peerAddress = *side2address;
  connection->u.quic.side1peerPort = side1port;
  connection->u.quic.side2peerPort = side2port;
  memcpy(&connection->u.quic.peer1ConnectionID,sourceCid,sizeof(struct spindump_quic_connectionid));
  memcpy(&connection->u.quic.peer2ConnectionID,destinationCid,sizeof(struct spindump_quic_connectionid));
  spindump_connections_newconnection_addtoaggregates(connection,table);
  
  spindump_debugf("created a new QUIC connection %u via a 5-tuple and CIDs", connection->id);
  return(connection);
}

//
// Create a new aggregate connection, to track all traffic between two
// hosts.
// 

struct spindump_connection*
spindump_connections_newconnection_aggregate_hostpair(const spindump_address* side1address,
                                                      const spindump_address* side2address,
                                                      const struct timeval* when,
                                                      int manuallyCreated,
                                                      struct spindump_connectionstable* table) {
  spindump_assert(side1address != 0);
  spindump_assert(side2address != 0);
  spindump_assert(when != 0);
  spindump_assert(table != 0);
  
  struct spindump_connection* connection =
    spindump_connections_newconnection(table,spindump_connection_aggregate_hostpair,when,manuallyCreated);
  if (connection == 0) return(0);

  connection->state = spindump_connection_state_static;
  connection->u.aggregatehostpair.side1peerAddress = *side1address;
  connection->u.aggregatehostpair.side2peerAddress = *side2address;
  
  spindump_debugf("created a new host pair aggregate onnection %u", connection->id);
  return(connection);
}

//
// Create a new aggregate connection, to track all traffic between a host
// and a given network.
// 

struct spindump_connection*
spindump_connections_newconnection_aggregate_hostnetwork(const spindump_address* side1address,
                                                         const spindump_network* side2network,
                                                         const struct timeval* when,
                                                         int manuallyCreated,
                                                         struct spindump_connectionstable* table) {
  spindump_assert(side1address != 0);
  spindump_assert(side2network != 0);
  spindump_assert(when != 0);
  spindump_assert(table != 0);
  
  struct spindump_connection* connection =
    spindump_connections_newconnection(table,spindump_connection_aggregate_hostnetwork,when,manuallyCreated);
  if (connection == 0) return(0);
  
  connection->state = spindump_connection_state_static;
  connection->u.aggregatehostnetwork.side1peerAddress = *side1address;
  connection->u.aggregatehostnetwork.side2Network = *side2network;
  
  spindump_debugf("created a new host-network aggregate onnection %u", connection->id);
  return(connection);
}

//
// Create a new aggregate connection, to track all traffic between two networks.
// 

struct spindump_connection*
spindump_connections_newconnection_aggregate_networknetwork(const spindump_network* side1network,
                                                            const spindump_network* side2network,
                                                            const struct timeval* when,
                                                            int manuallyCreated,
                                                            struct spindump_connectionstable* table) {
  spindump_assert(side1network != 0);
  spindump_assert(side2network != 0);
  spindump_assert(when != 0);
  spindump_assert(table != 0);
  
  struct spindump_connection* connection =
    spindump_connections_newconnection(table,spindump_connection_aggregate_networknetwork,when,manuallyCreated);
  if (connection == 0) return(0);
  
  connection->state = spindump_connection_state_static;
  connection->u.aggregatenetworknetwork.side1Network = *side1network;
  connection->u.aggregatenetworknetwork.side2Network = *side2network;
  
  spindump_debugf("created a new network-network aggregate onnection %u", connection->id);
  return(connection);
}

//
// Create a new aggregate connection, to represent traffic to or from
// a given multicast address.
// 

struct spindump_connection*
spindump_connections_newconnection_aggregate_multicastgroup(const spindump_address* group,
                                                            const struct timeval* when,
                                                            int manuallyCreated,
                                                            struct spindump_connectionstable* table) {
  spindump_assert(group != 0);
  spindump_assert(when != 0);
  spindump_assert(table != 0);
  
  struct spindump_connection* connection =
    spindump_connections_newconnection(table,spindump_connection_aggregate_multicastgroup,when,manuallyCreated);
  if (connection == 0) return(0);
  
  connection->state = spindump_connection_state_static;
  connection->u.aggregatemulticastgroup.group = *group;
  
  spindump_debugf("created a new multicast group aggregate onnection %u", connection->id);
  return(connection);
}

//
// Delete a connection object. This causes the physical deallocation
// of the object, and is typically called by a periodic cleanup
// process, rather than directly after e.g., a TCP session closes.
// 

void
spindump_connections_delete(struct spindump_connection* connection) {

  spindump_assert(connection != 0);
  
  switch (connection->type) {
    
  case spindump_connection_transport_tcp:
    spindump_seqtracker_uninitialize(&connection->u.tcp.side1Seqs);
    spindump_seqtracker_uninitialize(&connection->u.tcp.side2Seqs);
    break;
    
  case spindump_connection_transport_udp:
    break;
    
  case spindump_connection_transport_dns:
    spindump_messageidtracker_uninitialize(&connection->u.dns.side1MIDs);
    spindump_messageidtracker_uninitialize(&connection->u.dns.side2MIDs);
    break;
    
  case spindump_connection_transport_coap:
    spindump_messageidtracker_uninitialize(&connection->u.coap.side1MIDs);
    spindump_messageidtracker_uninitialize(&connection->u.coap.side2MIDs);
    break;
    
  case spindump_connection_transport_quic:
    break;
    
  case spindump_connection_transport_icmp:
    break;
    
  case spindump_connection_aggregate_hostpair:
    spindump_connections_set_uninitialize(&connection->u.aggregatehostpair.connections,connection);
    break;
    
  case spindump_connection_aggregate_hostnetwork:
    spindump_connections_set_uninitialize(&connection->u.aggregatehostnetwork.connections,connection);
    break;
    
  case spindump_connection_aggregate_networknetwork:
    spindump_connections_set_uninitialize(&connection->u.aggregatenetworknetwork.connections,connection);
    break;
    
  case spindump_connection_aggregate_multicastgroup:
    spindump_connections_set_uninitialize(&connection->u.aggregatemulticastgroup.connections,connection);
    break;
    
  default:
    spindump_errorf("invalid connection type %u in spindump_connections_delete",
                    connection->type);
    break;
    
  }
  
  spindump_connections_set_uninitialize(&connection->aggregates,connection);
  memset(connection,0x93,sizeof(*connection));
  spindump_free(connection);
}
