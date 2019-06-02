
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
#include "spindump_table.h"
#include "spindump_stats.h"
#include "spindump_analyze_quic_parser.h"
#include "spindump_spin.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static int
spindump_connections_match(struct spindump_connection* connection,
                           struct spindump_connection_searchcriteria* criteria,
                           int* fromResponder);

//
// Actual code --------------------------------------------------------------------------------
//

//
// Does a connection match search criteria?
//

static int
spindump_connections_match(struct spindump_connection* connection,
                           struct spindump_connection_searchcriteria* criteria,
                           int* fromResponder) {
  //
  // Make some checks first
  // 
  
  spindump_assert(connection != 0);
  spindump_assert(criteria != 0);
  spindump_assert(fromResponder != 0);
  
  spindump_assert(spindump_isbool(criteria->matchType));
  spindump_assert(spindump_isbool(criteria->matchIcmpType));
  spindump_assert(spindump_isbool(criteria->matchIcmpId));
  spindump_assert(spindump_isbool(criteria->matchPartialDestinationCid));
  spindump_assert(spindump_isbool(criteria->matchPartialSourceCid));

  //
  // Set a flag to indicate whether we've already matched direction of
  // the connection.
  // 
  
  int fromResponderSet = 0;
  
  //
  // Start going through the criteria to check if they match. First
  // up: connection type (IP protocol):
  // 
  
  if (criteria->matchType) {
    if (connection->type != criteria->type) {
      spindump_deepdebugf("match fails due to connection type");
      return(0);
    }
  }
  
  spindump_deepdeepdebugf("connection type match ok");
  
  //
  // ICMP type and ID
  // 
  
  if (criteria->matchIcmpType) {
    spindump_assert(criteria->matchType && criteria->type == spindump_connection_transport_icmp);
    if (connection->u.icmp.side1peerType != criteria->icmpType) {
      spindump_deepdebugf("match fails due to icmp type");
      return(0);
    }
  }
  
  if (criteria->matchIcmpId) {
    spindump_assert(criteria->matchType && criteria->type == spindump_connection_transport_icmp);
    if (connection->u.icmp.side1peerId != criteria->icmpId) {
      spindump_deepdebugf("match fails due to icmp id");
      return(0);
    }
  }
  
  spindump_deepdeepdebugf("icmp type match ok");
  
  //
  // Source and destination addresses
  // 
  
  spindump_address* side1address = 0;
  spindump_address* side2address = 0;
  spindump_network side1network;
  spindump_network side2network;
  int portOrCidTestsRemain =
    ((criteria->matchPorts != spindump_connection_searchcriteria_srcdst_none) ||
     (criteria->matchQuicCids != spindump_connection_searchcriteria_srcdst_none));
  
  switch (criteria->matchAddresses) {

  case spindump_connection_searchcriteria_srcdst_none:
    break;

  case spindump_connection_searchcriteria_srcdst_sourceonly:
    spindump_connections_getaddresses(connection,&side1address,&side2address);
    if (side1address == 0) {
      spindump_deepdebugf("match fails due to src address missing");
      return(0);
    }
    if (!spindump_address_equal(side1address,&criteria->side1address)) {
      spindump_deepdebugf("match fails due to src address");
      return(0);
    }
    *fromResponder = 1;
    fromResponderSet = 1;
    break;

  case spindump_connection_searchcriteria_srcdst_destinationonly:
    spindump_connections_getaddresses(connection,&side1address,&side2address);
    if (side2address == 0) {
      spindump_deepdebugf("match fails due to dst address missing");
      return(0);
    }
    if (!spindump_address_equal(side2address,&criteria->side2address)) {
      spindump_deepdebugf("match fails due to dst address");
      return(0);
    }
    *fromResponder = 0;
    fromResponderSet = 1;
    break;

  case spindump_connection_searchcriteria_srcdst_both:
    spindump_connections_getaddresses(connection,&side1address,&side2address);
    if (side1address == 0 || side2address == 0) {
      spindump_deepdebugf("match fails due to address missing");
      return(0);
    }
    if (!spindump_address_equal(side1address,&criteria->side1address)) {
      spindump_deepdebugf("match fails due to src address %s",
                          spindump_address_tostring(side1address));
      spindump_deepdebugf("vs. %s",
                          spindump_address_tostring(side2address));
      return(0);
    }
    if (!spindump_address_equal(side2address,&criteria->side2address)) {
      spindump_deepdebugf("match fails due to dst address %s",
                          spindump_address_tostring(side1address));
      spindump_deepdebugf("vs. %s",
                          spindump_address_tostring(side2address));
      return(0);
    }
    *fromResponder = 0;
    fromResponderSet = 1;
    break;
    
  case spindump_connection_searchcriteria_srcdst_both_allowreverse:
    spindump_connections_getaddresses(connection,&side1address,&side2address);
    if (side1address == 0 || side2address == 0) {
      spindump_deepdebugf("match fails due to address missing");
      return(0);
    }
    if (spindump_address_equal(side1address,&criteria->side1address) &&
        spindump_address_equal(side2address,&criteria->side2address)) {
      if (!spindump_address_equal(side1address,side2address) ||
          !portOrCidTestsRemain) {
        *fromResponder = 0;
        fromResponderSet = 1;
        spindump_deepdeepdebugf("address srcdst_both_allowreverse ok and not fromResponder");
      } else {
        spindump_deepdeepdebugf("address srcdst_both_allowreverse ok but cannot set direction yet");
      }
    } else if (spindump_address_equal(side2address,&criteria->side1address) &&
               spindump_address_equal(side1address,&criteria->side2address)) {
      if (!spindump_address_equal(side1address,side2address) ||
          !portOrCidTestsRemain) {
        *fromResponder = 1;
        fromResponderSet = 1;
        spindump_deepdeepdebugf("address srcdst_both_allowreverse ok and fromResponder");
      } else {
        spindump_deepdeepdebugf("address srcdst_both_allowreverse ok but cannot set direction yet");
      }
    } else {
      spindump_deepdebugf("match fails due to no address match");
      return(0);
    }
    break;
    
  case spindump_connection_searchcriteria_srcdst_both_hostnetwork:
    spindump_connections_getnetworks(connection,&side1network,&side2network);
    if (!spindump_network_ishost(&side1network)) {
      spindump_deepdeepdebugf("match fails because side1 is not a host");
      return(0);
    }
    side1address = &side1network.address;
    if (!spindump_address_equal(side1address,&criteria->side1address)) {
      spindump_deepdeepdebugf("match fails because side1 is not equal");
      return(0);
    }
    if (!spindump_network_equal(&side2network,&criteria->side2network)) {
      spindump_deepdeepdebugf("match fails because side 2 is not equal");  
      return(0);
    }
    *fromResponder = 0;
    fromResponderSet = 1;
    break;
    
  case spindump_connection_searchcriteria_srcdst_both_networknetwork:
    spindump_connections_getnetworks(connection,&side1network,&side2network);
    if (!spindump_network_equal(&side1network,&criteria->side1network)) {
      spindump_deepdeepdebugf("match fails because side1 network is not equal to criteria");  
      return(0);
    }
    if (!spindump_network_equal(&side2network,&criteria->side2network)) {
      spindump_deepdeepdebugf("match fails because side2 network is not equal to criteria");  
      return(0);
    }
    *fromResponder = 0;
    fromResponderSet = 1;
    break;
    
  default:
    spindump_errorf("invalid match addresses criteria");
    return(0);
    
  }
  
  spindump_deepdeepdebugf("address match ok");
  
  //
  // Source and destination ports
  // 
  
  spindump_port side1port = 0;
  spindump_port side2port = 0;
  
  switch (criteria->matchPorts) {

  case spindump_connection_searchcriteria_srcdst_none:
    spindump_deepdeepdebugf("no port match needed");
    break;

  case spindump_connection_searchcriteria_srcdst_sourceonly:
    spindump_connections_getports(connection,&side1port,&side2port);
    spindump_deepdeepdebugf("source port match needed to %u", side1port);
    if (side1port == 0) return(0);
    if (side1port != criteria->side1port) return(0);
    if (fromResponderSet && *fromResponder != 1) return(0);
    *fromResponder = 1;
    fromResponderSet = 1;
    break;
    
  case spindump_connection_searchcriteria_srcdst_destinationonly:
    spindump_connections_getports(connection,&side1port,&side2port);
    spindump_deepdeepdebugf("destination port match needed to %u", side2port);
    if (side2port == 0) return(0);
    if (side2port != criteria->side2port) return(0);
    if (fromResponderSet && *fromResponder != 0) return(0);
    *fromResponder = 0;
    fromResponderSet = 1;
    break;
    
  case spindump_connection_searchcriteria_srcdst_both:
    spindump_connections_getports(connection,&side1port,&side2port);
    spindump_deepdeepdebugf("source and destination port match needed to %u:%u", side1port, side2port);
    if (side1port == 0 || side2port == 0) return(0);
    if (side1port != criteria->side1port) return(0);
    if (side2port != criteria->side2port) return(0);
    if (fromResponderSet && *fromResponder != 0) return(0);
    *fromResponder = 0;
    fromResponderSet = 1;
    break;
    
  case spindump_connection_searchcriteria_srcdst_both_allowreverse:
    spindump_connections_getports(connection,&side1port,&side2port);
    spindump_deepdeepdebugf("source and destination port match needed to %u:%u (allow reverse)", side1port, side2port);
    spindump_deepdeepdebugf("fromResponderSet = %u fromResponder = %u", fromResponderSet, *fromResponder);
    if (side1port == 0 || side2port == 0) {
      spindump_deepdeepdebugf("port match fail 1");
      return(0);
    }
    if (side1port == criteria->side1port &&
        side2port == criteria->side2port &&
        (!fromResponderSet || *fromResponder == 0)) {
      *fromResponder = 0;
      fromResponderSet = 1;
    } else if (side2port == criteria->side1port &&
               side1port == criteria->side2port &&
               (!fromResponderSet || *fromResponder == 1)) {
      *fromResponder = 1;
      fromResponderSet = 1;
    } else {
      spindump_deepdeepdebugf("port match fail 2");
      return(0);
    }
    break;
    
  case spindump_connection_searchcriteria_srcdst_both_hostnetwork:
  case spindump_connection_searchcriteria_srcdst_both_networknetwork:
  default:
    spindump_errorf("invalid match addresses criteria");
    return(0);
    
  }
  
  spindump_deepdeepdebugf("port match ok");
  
  //
  // QUIC CIDs
  // 

  struct spindump_quic_connectionid* side1connectionId = 0;
  struct spindump_quic_connectionid* side2connectionId = 0;
  
  switch (criteria->matchQuicCids) {

  case spindump_connection_searchcriteria_srcdst_none:
    spindump_deepdeepdebugf("no cid match needed");
    break;

  case spindump_connection_searchcriteria_srcdst_sourceonly:
    spindump_assert(criteria->matchType && criteria->type == spindump_connection_transport_quic);
    side1connectionId = &connection->u.quic.peer1ConnectionID;
    spindump_deepdeepdebugf("source cid match needed to %s",
                            spindump_connection_quicconnectionid_tostring(side1connectionId));
    if (!spindump_analyze_quic_quicidequal(side1connectionId,&criteria->side1connectionId)) return(0);
    if (fromResponderSet && *fromResponder != 1) return(0);
    *fromResponder = 1;
    fromResponderSet = 1;
    break;
    
  case spindump_connection_searchcriteria_srcdst_destinationonly:
    spindump_assert(criteria->matchType && criteria->type == spindump_connection_transport_quic);
    side2connectionId = &connection->u.quic.peer2ConnectionID;
    spindump_deepdeepdebugf("destination cid match needed to %s",
                            spindump_connection_quicconnectionid_tostring(side2connectionId));
    if (!spindump_analyze_quic_quicidequal(side2connectionId,&criteria->side2connectionId)) return(0);
    if (fromResponderSet && *fromResponder != 0) return(0);
    *fromResponder = 0;
    fromResponderSet = 1;
    break;
    
  case spindump_connection_searchcriteria_srcdst_both:
    spindump_assert(criteria->matchType && criteria->type == spindump_connection_transport_quic);
    side1connectionId = &connection->u.quic.peer1ConnectionID;
    side2connectionId = &connection->u.quic.peer2ConnectionID;
    spindump_deepdeepdebugf("destination and source cid match needed to destination %s",
                            spindump_connection_quicconnectionid_tostring(side2connectionId));
    spindump_deepdeepdebugf("destination and source cid match needed to souerce %s",
                            spindump_connection_quicconnectionid_tostring(side1connectionId));
    if (!spindump_analyze_quic_quicidequal(side1connectionId,&criteria->side1connectionId)) return(0);
    if (!spindump_analyze_quic_quicidequal(side2connectionId,&criteria->side2connectionId)) return(0);
    if (fromResponderSet && *fromResponder != 0) return(0);
    *fromResponder = 0;
    fromResponderSet = 1;
    break;
    
  case spindump_connection_searchcriteria_srcdst_both_allowreverse:
    spindump_assert(criteria->matchType && criteria->type == spindump_connection_transport_quic);
    side1connectionId = &connection->u.quic.peer1ConnectionID;
    side2connectionId = &connection->u.quic.peer2ConnectionID;
    spindump_deepdeepdebugf("destination and source cid match needed to destination %s (allow reverse)",
                            spindump_connection_quicconnectionid_tostring(side2connectionId));
    spindump_deepdeepdebugf("destination and source cid match needed to souerce %s (allow reverse)",
                            spindump_connection_quicconnectionid_tostring(side1connectionId));
    if (spindump_analyze_quic_quicidequal(side1connectionId,&criteria->side1connectionId) &&
        spindump_analyze_quic_quicidequal(side2connectionId,&criteria->side2connectionId) &&
        (!fromResponderSet || *fromResponder == 0)) {
      *fromResponder = 0;
      fromResponderSet = 1;
    } else if (spindump_analyze_quic_quicidequal(side2connectionId,&criteria->side1connectionId) &&
               spindump_analyze_quic_quicidequal(side1connectionId,&criteria->side2connectionId) &&
               (!fromResponderSet || *fromResponder == 1)) {
      *fromResponder = 1;
      fromResponderSet = 1;
    } else {
      return(0);
    }
    break;
    
  case spindump_connection_searchcriteria_srcdst_both_hostnetwork:
  case spindump_connection_searchcriteria_srcdst_both_networknetwork:
  default:
    spindump_errorf("invalid match addresses criteria");
    return(0);
    
  }

  spindump_deepdeepdebugf("cid match ok");
  
  //
  // Partial QUIC CIDs
  // 
  
  if (criteria->matchPartialDestinationCid) {
    spindump_assert(criteria->partialDestinationCid != 0);
    side2connectionId = &connection->u.quic.peer2ConnectionID;
    if (!spindump_analyze_quic_partialquicidequal(criteria->partialDestinationCid,
                                                  side2connectionId)) return(0);
  }
  
  if (criteria->matchPartialSourceCid) {
    spindump_assert(criteria->partialSourceCid != 0);
    side1connectionId = &connection->u.quic.peer1ConnectionID;
    if (!spindump_analyze_quic_partialquicidequal(criteria->partialSourceCid,
                                                  side1connectionId)) return(0);
  }
  
  //
  // All tests have passed, so this connection satisfies the criteria!
  // 
  
  spindump_deepdebugf("match succeeds");
  return(1);
}

//
// Search for a connection based on given criteria
//

struct spindump_connection*
spindump_connections_search(struct spindump_connection_searchcriteria* criteria,
                            struct spindump_connectionstable* table,
                            int* fromResponder) {
  
  //
  // Make some checks first
  // 

  spindump_assert(criteria != 0);
  spindump_assert(table != 0);
  spindump_assert(fromResponder != 0);
  
  //
  // Search the table
  // 

  for (unsigned i = 0; i < table->nConnections; i++) {
    struct spindump_connection* connection = table->connections[i];
    if (connection != 0) {

      spindump_deepdeepdebugf("search compares to connection %u", connection->id);

      if (spindump_connections_match(connection,criteria,fromResponder)) {
        
        spindump_debugf("found an existing %s connection %u",
                        spindump_connection_type_to_string(connection->type),
                        connection->id);
        return(connection);

      }
      
    }
  }

  //
  // Not found at all. Return null pointer.
  // 
  
  return(0);
}

//
// Search for an ICMP connection, based on addresses a ICMP type and
// id. Return the found object, or 0 if not found.
//

struct spindump_connection*
spindump_connections_searchconnection_icmp(const spindump_address* side1address,
                                           const spindump_address* side2address,
                                           u_int8_t side1peerType,
                                           u_int16_t side1peerId,
                                           struct spindump_connectionstable* table) {

  spindump_assert(side1address != 0);
  spindump_assert(side2address != 0);
  spindump_assert(table != 0);

  struct spindump_connection_searchcriteria criteria;
  memset(&criteria,0,sizeof(criteria));
  
  criteria.matchType = 1;
  criteria.type = spindump_connection_transport_icmp;
  
  criteria.matchIcmpType = 1;
  criteria.icmpType = side1peerType;

  criteria.matchIcmpId = 1;
  criteria.icmpId = side1peerId;
  
  criteria.matchAddresses = spindump_connection_searchcriteria_srcdst_both;
  criteria.side1address = *side1address;
  criteria.side2address = *side2address;
  
  int fromResponder;
  
  return(spindump_connections_search(&criteria,
                                     table,
                                     &fromResponder));
}

//
// Search for a TCP connection, based on addresses and ports. Return
// the found object, or 0 if not found.
//

struct spindump_connection*
spindump_connections_searchconnection_tcp(const spindump_address* side1address,
                                          const spindump_address* side2address,
                                          spindump_port side1port,
                                          spindump_port side2port,
                                          struct spindump_connectionstable* table) {

  spindump_assert(side1address != 0);
  spindump_assert(side2address != 0);
  spindump_assert(table != 0);

  struct spindump_connection_searchcriteria criteria;
  memset(&criteria,0,sizeof(criteria));
  
  criteria.matchType = 1;
  criteria.type = spindump_connection_transport_tcp;
  
  criteria.matchPorts = spindump_connection_searchcriteria_srcdst_both;
  criteria.side1port = side1port;
  criteria.side2port = side2port;
  
  criteria.matchAddresses = spindump_connection_searchcriteria_srcdst_both;
  criteria.side1address = *side1address;
  criteria.side2address = *side2address;
  
  int fromResponder;
  
  return(spindump_connections_search(&criteria,
                                     table,
                                     &fromResponder));
}

//
// Search for a TCP connection, based on addresses and ports; allow
// finding either direction object. Return the found object, or 0 if
// not found.
//

struct spindump_connection*
spindump_connections_searchconnection_tcp_either(const spindump_address* side1address,
                                                 const spindump_address* side2address,
                                                 spindump_port side1port,
                                                 spindump_port side2port,
                                                 struct spindump_connectionstable* table,
                                                 int* fromResponder) {
  
  spindump_assert(side1address != 0);
  spindump_assert(side2address != 0);
  spindump_assert(table != 0);
  
  struct spindump_connection_searchcriteria criteria;
  memset(&criteria,0,sizeof(criteria));
  
  criteria.matchType = 1;
  criteria.type = spindump_connection_transport_tcp;
  
  criteria.matchPorts = spindump_connection_searchcriteria_srcdst_both_allowreverse;
  criteria.side1port = side1port;
  criteria.side2port = side2port;
  
  criteria.matchAddresses = spindump_connection_searchcriteria_srcdst_both_allowreverse;
  criteria.side1address = *side1address;
  criteria.side2address = *side2address;
  
  return(spindump_connections_search(&criteria,
                                     table,
                                     fromResponder));
}

//
// Search for a UDP connection, based on addresses and ports. Return
// the found object, or 0 if not found.
//

struct spindump_connection*
spindump_connections_searchconnection_udp(const spindump_address* side1address,
                                          const spindump_address* side2address,
                                          spindump_port side1port,
                                          spindump_port side2port,
                                          struct spindump_connectionstable* table) {

  spindump_assert(side1address != 0);
  spindump_assert(side2address != 0);
  spindump_assert(table != 0);

  struct spindump_connection_searchcriteria criteria;
  memset(&criteria,0,sizeof(criteria));
  
  criteria.matchType = 1;
  criteria.type = spindump_connection_transport_udp;
  
  criteria.matchPorts = spindump_connection_searchcriteria_srcdst_both;
  criteria.side1port = side1port;
  criteria.side2port = side2port;
  
  criteria.matchAddresses = spindump_connection_searchcriteria_srcdst_both;
  criteria.side1address = *side1address;
  criteria.side2address = *side2address;
  
  int fromResponder;
  
  return(spindump_connections_search(&criteria,
                                     table,
                                     &fromResponder));
}

//
// Search for a UDP connection, based on addresses and ports; allow
// finding either direction object. Return the found object, or 0 if
// not found.
//

struct spindump_connection*
spindump_connections_searchconnection_udp_either(const spindump_address* side1address,
                                                 const spindump_address* side2address,
                                                 spindump_port side1port,
                                                 spindump_port side2port,
                                                 struct spindump_connectionstable* table,
                                                 int* fromResponder) {
  spindump_assert(side1address != 0);
  spindump_assert(side2address != 0);
  spindump_assert(table != 0);
  
  struct spindump_connection_searchcriteria criteria;
  memset(&criteria,0,sizeof(criteria));
  
  criteria.matchType = 1;
  criteria.type = spindump_connection_transport_udp;
  
  criteria.matchPorts = spindump_connection_searchcriteria_srcdst_both_allowreverse;
  criteria.side1port = side1port;
  criteria.side2port = side2port;
  
  criteria.matchAddresses = spindump_connection_searchcriteria_srcdst_both_allowreverse;
  criteria.side1address = *side1address;
  criteria.side2address = *side2address;
  
  return(spindump_connections_search(&criteria,
                                     table,
                                     fromResponder));
}

//
// Search for a DNS connection, based on addresses and ports. Return
// the found object, or 0 if not found.
//

struct spindump_connection*
spindump_connections_searchconnection_dns(const spindump_address* side1address,
                                          const spindump_address* side2address,
                                          spindump_port side1port,
                                          spindump_port side2port,
                                          struct spindump_connectionstable* table) {

  spindump_assert(side1address != 0);
  spindump_assert(side2address != 0);
  spindump_assert(table != 0);

  struct spindump_connection_searchcriteria criteria;
  memset(&criteria,0,sizeof(criteria));
  
  criteria.matchType = 1;
  criteria.type = spindump_connection_transport_dns;
  
  criteria.matchPorts = spindump_connection_searchcriteria_srcdst_both;
  criteria.side1port = side1port;
  criteria.side2port = side2port;
  
  criteria.matchAddresses = spindump_connection_searchcriteria_srcdst_both;
  criteria.side1address = *side1address;
  criteria.side2address = *side2address;
  
  int fromResponder;
  
  return(spindump_connections_search(&criteria,
                                     table,
                                     &fromResponder));
}

//
// Search for a DNS connection, based on addresses and ports; allow
// finding either direction object. Return the found object, or 0 if
// not found.
//

struct spindump_connection*
spindump_connections_searchconnection_dns_either(const spindump_address* side1address,
                                                 const spindump_address* side2address,
                                                 spindump_port side1port,
                                                 spindump_port side2port,
                                                 struct spindump_connectionstable* table,
                                                 int* fromResponder) {
  spindump_assert(side1address != 0);
  spindump_assert(side2address != 0);
  spindump_assert(table != 0);
  
  struct spindump_connection_searchcriteria criteria;
  memset(&criteria,0,sizeof(criteria));
  
  criteria.matchType = 1;
  criteria.type = spindump_connection_transport_dns;
  
  criteria.matchPorts = spindump_connection_searchcriteria_srcdst_both_allowreverse;
  criteria.side1port = side1port;
  criteria.side2port = side2port;
  
  criteria.matchAddresses = spindump_connection_searchcriteria_srcdst_both_allowreverse;
  criteria.side1address = *side1address;
  criteria.side2address = *side2address;
  
  return(spindump_connections_search(&criteria,
                                     table,
                                     fromResponder));
}

//
// Search for a COAP connection, based on addresses and ports. Return
// the found object, or 0 if not found.
//

struct spindump_connection*
spindump_connections_searchconnection_coap(const spindump_address* side1address,
                                           const spindump_address* side2address,
                                           spindump_port side1port,
                                           spindump_port side2port,
                                           struct spindump_connectionstable* table) {
  
  spindump_assert(side1address != 0);
  spindump_assert(side2address != 0);
  spindump_assert(table != 0);
  
  struct spindump_connection_searchcriteria criteria;
  memset(&criteria,0,sizeof(criteria));
  
  criteria.matchType = 1;
  criteria.type = spindump_connection_transport_coap;
  
  criteria.matchPorts = spindump_connection_searchcriteria_srcdst_both;
  criteria.side1port = side1port;
  criteria.side2port = side2port;
  
  criteria.matchAddresses = spindump_connection_searchcriteria_srcdst_both;
  criteria.side1address = *side1address;
  criteria.side2address = *side2address;
  
  int fromResponder;
  
  return(spindump_connections_search(&criteria,
                                     table,
                                     &fromResponder));
}

//
// Search for a COAP connection, based on addresses and ports; allow
// finding either direction object. Return the found object, or 0 if
// not found.
//

struct spindump_connection*
spindump_connections_searchconnection_coap_either(const spindump_address* side1address,
                                                  const spindump_address* side2address,
                                                  spindump_port side1port,
                                                  spindump_port side2port,
                                                  struct spindump_connectionstable* table,
                                                  int* fromResponder) {
  spindump_assert(side1address != 0);
  spindump_assert(side2address != 0);
  spindump_assert(table != 0);
  
  struct spindump_connection_searchcriteria criteria;
  memset(&criteria,0,sizeof(criteria));
  
  criteria.matchType = 1;
  criteria.type = spindump_connection_transport_coap;
  
  criteria.matchPorts = spindump_connection_searchcriteria_srcdst_both_allowreverse;
  criteria.side1port = side1port;
  criteria.side2port = side2port;
  
  criteria.matchAddresses = spindump_connection_searchcriteria_srcdst_both_allowreverse;
  criteria.side1address = *side1address;
  criteria.side2address = *side2address;
  
  return(spindump_connections_search(&criteria,
                                     table,
                                     fromResponder));
}

//
// Search for a QUIC connection, based on addresses and ports. Return
// the found object, or 0 if not found.
//

struct spindump_connection*
spindump_connections_searchconnection_quic_5tuple(const spindump_address* side1address,
                                                  const spindump_address* side2address,
                                                  spindump_port side1port,
                                                  spindump_port side2port,
                                                  struct spindump_connectionstable* table) {
  
  spindump_assert(side1address != 0);
  spindump_assert(side2address != 0);
  spindump_assert(table != 0);
  
  spindump_deepdeepdebugf("searchconnection_quic_5tuple port %u:%u", side1port, side2port);
  struct spindump_connection_searchcriteria criteria;
  memset(&criteria,0,sizeof(criteria));
  
  criteria.matchType = 1;
  criteria.type = spindump_connection_transport_quic;
  
  criteria.matchPorts = spindump_connection_searchcriteria_srcdst_both;
  criteria.side1port = side1port;
  criteria.side2port = side2port;
  
  criteria.matchAddresses = spindump_connection_searchcriteria_srcdst_both;
  criteria.side1address = *side1address;
  criteria.side2address = *side2address;
  
  int fromResponder;
  
  return(spindump_connections_search(&criteria,
                                     table,
                                     &fromResponder));
}

//
// Search for a QUIC connection, based on addresses the QUIC connection
// IDs. Return the found object, or 0 if not found.
//

struct spindump_connection*
spindump_connections_searchconnection_quic_cids(struct spindump_quic_connectionid* destinationCid,
                                                struct spindump_quic_connectionid* sourceCid,
                                                struct spindump_connectionstable* table) {
  
  spindump_assert(destinationCid != 0);
  spindump_assert(sourceCid != 0);
  spindump_assert(table != 0);

  spindump_deepdeepdebugf("searchconnection_quic_cids source %s", spindump_connection_quicconnectionid_tostring(sourceCid));
  spindump_deepdeepdebugf("searchconnection_quic_cids destination %s", spindump_connection_quicconnectionid_tostring(destinationCid));
  struct spindump_connection_searchcriteria criteria;
  memset(&criteria,0,sizeof(criteria));
  
  criteria.matchType = 1;
  criteria.type = spindump_connection_transport_quic;
  
  criteria.matchQuicCids = spindump_connection_searchcriteria_srcdst_both;
  criteria.side1connectionId = *sourceCid;
  criteria.side2connectionId = *destinationCid;
  
  int fromResponder;
  
  return(spindump_connections_search(&criteria,
                                     table,
                                     &fromResponder));
  
}

//
// Search for a QUIC connection, based on the destination QUIC
// vonnection ID. Return the found object, or 0 if not found.
//

struct spindump_connection*
spindump_connections_searchconnection_quic_destcid(struct spindump_quic_connectionid* destinationCid,
                                                   struct spindump_connectionstable* table) {

  spindump_assert(destinationCid != 0);
  spindump_assert(table != 0);
  
  spindump_deepdeepdebugf("searchconnection_quic_destcid %s",
                          spindump_connection_quicconnectionid_tostring(destinationCid));
  struct spindump_connection_searchcriteria criteria;
  memset(&criteria,0,sizeof(criteria));
  
  criteria.matchType = 1;
  criteria.type = spindump_connection_transport_quic;
  
  criteria.matchQuicCids = spindump_connection_searchcriteria_srcdst_destinationonly;
  criteria.side2connectionId = *destinationCid;
  
  int fromResponder;
  
  return(spindump_connections_search(&criteria,
                                     table,
                                     &fromResponder));
}

//
// Search for a QUIC connection, based on partial information about a
// connection ID. Return the found object, or 0 if not found.
//

struct spindump_connection*
spindump_connections_searchconnection_quic_partialcid(const unsigned char* destinationCid,
                                                      struct spindump_connectionstable* table) {

  spindump_assert(destinationCid != 0);
  spindump_assert(table != 0);
  
  spindump_deepdeepdebugf("searchconnection_quic_partialcid");
  struct spindump_connection_searchcriteria criteria;
  memset(&criteria,0,sizeof(criteria));
  
  criteria.matchType = 1;
  criteria.type = spindump_connection_transport_quic;
  
  criteria.matchPartialDestinationCid = 1;
  criteria.partialDestinationCid = destinationCid;
  
  int fromResponder;
  
  return(spindump_connections_search(&criteria,
                                     table,
                                     &fromResponder));
}

//
// Search for a TCP connection, based on partial information abnout a
// connection ID that needs to be the source of the initial
// connection. Return the found object, or 0 if not found.
//

struct spindump_connection*
spindump_connections_searchconnection_quic_partialcid_source(const unsigned char* destinationCid,
                                                             struct spindump_connectionstable* table) {

  spindump_assert(destinationCid != 0);
  spindump_assert(table != 0);
  
  spindump_deepdeepdebugf("searchconnection_quic_partialcid_source");
  struct spindump_connection_searchcriteria criteria;
  memset(&criteria,0,sizeof(criteria));
  
  criteria.matchType = 1;
  criteria.type = spindump_connection_transport_quic;
  
  criteria.matchPartialSourceCid = 1;
  criteria.partialSourceCid = destinationCid;
  
  int fromResponder;
  
  return(spindump_connections_search(&criteria,
                                     table,
                                     &fromResponder));
}

//
// Search for a QUIC connection, based on addresses and ports; allow
// finding either direction object. Return the found object, or 0 if
// not found.
//

struct spindump_connection*
spindump_connections_searchconnection_quic_5tuple_either(const spindump_address* side1address,
                                                         const spindump_address* side2address,
                                                         spindump_port side1port,
                                                         spindump_port side2port,
                                                         struct spindump_connectionstable* table,
                                                         int* fromResponder) {
  
  spindump_assert(side1address != 0);
  spindump_assert(side2address != 0);
  spindump_assert(table != 0);

  spindump_deepdeepdebugf("searchconnection_quic_5tuple_either port %u:%u", side1port, side2port);
  struct spindump_connection_searchcriteria criteria;
  memset(&criteria,0,sizeof(criteria));
  
  criteria.matchType = 1;
  criteria.type = spindump_connection_transport_quic;
  
  criteria.matchPorts = spindump_connection_searchcriteria_srcdst_both_allowreverse;
  criteria.side1port = side1port;
  criteria.side2port = side2port;
  
  criteria.matchAddresses = spindump_connection_searchcriteria_srcdst_both_allowreverse;
  criteria.side1address = *side1address;
  criteria.side2address = *side2address;
  
  return(spindump_connections_search(&criteria,
                                     table,
                                     fromResponder));
}

//
// Search for a TCP connection, based on QUIC connection IDs; allow
// finding either direction object. Return the found object, or 0 if
// not found.
//

struct spindump_connection*
spindump_connections_searchconnection_quic_cids_either(struct spindump_quic_connectionid* destinationCid,
                                                       struct spindump_quic_connectionid* sourceCid,
                                                       struct spindump_connectionstable* table,
                                                       int* fromResponder) {
  spindump_assert(destinationCid != 0);
  spindump_assert(sourceCid != 0);
  spindump_assert(table != 0);
  
  spindump_deepdeepdebugf("searchconnection_quic_cids_either source %s", spindump_connection_quicconnectionid_tostring(sourceCid));
  spindump_deepdeepdebugf("searchconnection_quic_cids_either destination %s", spindump_connection_quicconnectionid_tostring(destinationCid));
  struct spindump_connection_searchcriteria criteria;
  memset(&criteria,0,sizeof(criteria));
  
  criteria.matchType = 1;
  criteria.type = spindump_connection_transport_quic;
  
  criteria.matchQuicCids = spindump_connection_searchcriteria_srcdst_both_allowreverse;
  criteria.side1connectionId = *sourceCid;
  criteria.side2connectionId = *destinationCid;
  
  return(spindump_connections_search(&criteria,
                                     table,
                                     fromResponder));
  
}

//
// Search for a TCP connection, based on partial matching of a QUIC
// connection ID; allow finding either direction object. Return the
// found object, or 0 if not found.
//

struct spindump_connection*
spindump_connections_searchconnection_quic_partialcid_either(const unsigned char* destinationCid,
                                                             struct spindump_connectionstable* table,
                                                             int* fromResponder) {
  spindump_deepdeepdebugf("searchconnection_quic_partialcid_either");
  struct spindump_connection* connection =
    spindump_connections_searchconnection_quic_partialcid(destinationCid,
                                                          table);
  if (connection != 0) {
    *fromResponder = 0;
    return(connection);
  }
  
  connection = spindump_connections_searchconnection_quic_partialcid_source(destinationCid,
                                                                            table);
  
  if (connection != 0) {
    *fromResponder = 1;
    return(connection);
  }
  
  return(0);
}

struct spindump_connection*
spindump_connections_searchconnection_aggregate_hostpair(const spindump_address* side1address,
                                                         const spindump_address* side2address,
                                                         struct spindump_connectionstable* table) {
  spindump_assert(side1address != 0);
  spindump_assert(side2address != 0);
  spindump_assert(table != 0);
  
  struct spindump_connection_searchcriteria criteria;
  memset(&criteria,0,sizeof(criteria));
  
  criteria.matchType = 1;
  criteria.type = spindump_connection_aggregate_hostpair;
  
  criteria.matchAddresses = spindump_connection_searchcriteria_srcdst_both;
  criteria.side1address = *side1address;
  criteria.side2address = *side2address;
  
  int fromResponder;
  
  return(spindump_connections_search(&criteria,
                                     table,
                                     &fromResponder));
}

struct spindump_connection*
spindump_connections_searchconnection_aggregate_hostnetwork(const spindump_address* side1address,
                                                            const spindump_network* side2network,
                                                            struct spindump_connectionstable* table) {
  spindump_assert(side1address != 0);
  spindump_assert(side2network != 0);
  spindump_assert(table != 0);
  
  struct spindump_connection_searchcriteria criteria;
  memset(&criteria,0,sizeof(criteria));
  
  criteria.matchType = 1;
  criteria.type = spindump_connection_aggregate_hostnetwork;
  
  criteria.matchAddresses = spindump_connection_searchcriteria_srcdst_both_hostnetwork;
  criteria.side1address = *side1address;
  criteria.side2network = *side2network;
  
  int fromResponder;
  
  return(spindump_connections_search(&criteria,
                                     table,
                                     &fromResponder));
}

struct spindump_connection*
spindump_connections_searchconnection_aggregate_networknetwork(const spindump_network* side1network,
                                                               const spindump_network* side2network,
                                                               struct spindump_connectionstable* table) {
  spindump_assert(side1network != 0);
  spindump_assert(side2network != 0);
  spindump_assert(table != 0);
  
  struct spindump_connection_searchcriteria criteria;
  memset(&criteria,0,sizeof(criteria));
  
  criteria.matchType = 1;
  criteria.type = spindump_connection_aggregate_networknetwork;
  
  criteria.matchAddresses = spindump_connection_searchcriteria_srcdst_both_networknetwork;
  criteria.side1network = *side1network;
  criteria.side2network = *side2network;
  
  int fromResponder;
  
  return(spindump_connections_search(&criteria,
                                     table,
                                     &fromResponder));
}

struct spindump_connection*
spindump_connections_searchconnection_aggregate_multicastgroup(const spindump_address* address,
                                                               struct spindump_connectionstable* table) {
  spindump_assert(address != 0);
  spindump_assert(table != 0);
  
  struct spindump_connection_searchcriteria criteria;
  memset(&criteria,0,sizeof(criteria));
  
  criteria.matchType = 1;
  criteria.type = spindump_connection_aggregate_multicastgroup;
  
  criteria.matchAddresses = spindump_connection_searchcriteria_srcdst_sourceonly;
  criteria.side1address = *address;
  
  int fromResponder;
  
  return(spindump_connections_search(&criteria,
                                     table,
                                     &fromResponder));
}
