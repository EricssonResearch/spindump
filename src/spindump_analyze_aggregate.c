
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

#include "spindump_util.h"
#include "spindump_connections.h"
#include "spindump_analyze.h"
#include "spindump_analyze_aggregate.h"

//
// Actual code --------------------------------------------------------------------------------
//

//
// This function is called when an input packet matches only an
// aggregate connection and nothing else. Note that there are both
// packets that match a built-in traffic type (e.g., TCP) and packets
// that only match aggregate connections if those (e.g., a protocol
// not supported by Spindump). The former class of packets gets
// processed at the specific connection, and then aggregates get to
// know of these packets through the spindump_analyze_process_pakstats
// and spindump_connections_newrttmeasurement functions. But latter
// class of packets is directly passed to the aggregate connection
// from spindump_analyze_decodeippayload and
// spindump_analyze_otherippayload.
//

void
spindump_analyze_process_aggregate(struct spindump_analyze* state,
				   struct spindump_connection* connection,
				   struct spindump_packet* packet,
				   unsigned int ipHeaderPosition,
				   unsigned int ipHeaderSize,
				   uint8_t ipVersion,
				   uint8_t ecnFlags,
				   unsigned int ipPacketLength,
				   struct spindump_stats* stats) {
  
  //
  // Some sanity checks
  //

  spindump_assert(connection != 0);
  spindump_assert(spindump_connections_isaggregate(connection));
  spindump_assert(packet != 0);
  spindump_assert(stats != 0);
  
  //
  // First, determine whether this packet is from the side1, which we
  // mark as the "initiator" and the other as "responder".
  //
  
  spindump_address source;
  spindump_analyze_getsource(packet,ipVersion,ipHeaderPosition,&source);
  int fromResponder;
  switch (connection->type) {
  case spindump_connection_aggregate_hostpair:
    fromResponder = spindump_address_equal(&source,
					   &connection->u.aggregatehostpair.side1peerAddress);
    break;
  case spindump_connection_aggregate_hostnetwork:
    fromResponder = spindump_address_equal(&source,
					   &connection->u.aggregatehostnetwork.side1peerAddress);
    break;
  case spindump_connection_aggregate_networknetwork:
    fromResponder = spindump_address_innetwork(&source,
					       &connection->u.aggregatenetworknetwork.side1Network);
    break;
  case spindump_connection_aggregate_multicastgroup:
    fromResponder = spindump_address_equal(&source,
					   &connection->u.aggregatemulticastgroup.group);
    break;
  case spindump_connection_transport_udp:
  case spindump_connection_transport_tcp:
  case spindump_connection_transport_quic:
  case spindump_connection_transport_dns:
  case spindump_connection_transport_coap:
  case spindump_connection_transport_icmp:
    spindump_errorf("expected an aggregate connection type");
    return;
  default:
    spindump_errorf("invalid connection type");
    return;
  }
  spindump_assert(spindump_isbool(fromResponder));
  
  //
  // There's little to do than note that we had a packet on this
  // aggregate connection, and increase stats.
  //
  
  spindump_analyze_process_pakstats(state,
				    connection,
				    fromResponder,
				    packet,
				    ipPacketLength,
				    ecnFlags);
  
  //
  // Done.
  //
}
