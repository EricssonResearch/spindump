

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
//  SPINDUMP (C) 2018-2021 BY ERICSSON RESEARCH
//  AUTHOR: JARI ARKKO
//
//

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include "spindump_util.h"
#include "spindump_connections.h"

//
// Actual code --------------------------------------------------------------------------------
//

int
spindump_connection_typehasports(enum spindump_connection_type type) {
  switch (type) {
  case spindump_connection_transport_tcp:
  case spindump_connection_transport_udp:
  case spindump_connection_transport_dns:
  case spindump_connection_transport_coap:
  case spindump_connection_transport_quic:
  case spindump_connection_transport_sctp:
    return(1);
  case spindump_connection_transport_icmp:
  case spindump_connection_aggregate_hostpair:
  case spindump_connection_aggregate_hostnetwork:
  case spindump_connection_aggregate_networknetwork:
  case spindump_connection_aggregate_multicastgroup:
  case spindump_connection_aggregate_hostmultinet:
  case spindump_connection_aggregate_networkmultinet:
    return(0);
  default:
    spindump_assert(0);
    return(0);
  }
}

  
