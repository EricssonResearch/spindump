
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

#include <ctype.h>
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
#include "spindump_connections_set_iterator.h"
#include "spindump_table.h"
#include "spindump_stats.h"
#include "spindump_analyze_quic_parser.h"
#include "spindump_analyze_tls_parser.h"
#include "spindump_analyze.h"
#include "spindump_spin.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static const char*
spindump_icmptype_tostring(u_int8_t type);
static const char*
spindump_connection_address_tostring(int anonymize,
                                     spindump_address* address,
                                     struct spindump_reverse_dns* querier);
static void
spindump_connection_addtobuf(char* buf,
                             unsigned int bufsize,
                             const char* text,
                             const char* value,
                             int compress);
static const char*
spindump_connection_report_brief_notefieldval(struct spindump_connection* connection);
static void
spindump_connection_report_udp(struct spindump_connection* connection,
                               FILE* file,
                               int anonymize,
                               struct spindump_reverse_dns* querier);
static void
spindump_connection_report_tcp(struct spindump_connection* connection,
                               FILE* file,
                               int anonymize,
                               struct spindump_reverse_dns* querier);
static void
spindump_connection_report_quic(struct spindump_connection* connection,
                                FILE* file,
                                int anonymize,
                                struct spindump_reverse_dns* querier);
static void
spindump_connection_report_dns(struct spindump_connection* connection,
                               FILE* file,
                               int anonymize,
                               struct spindump_reverse_dns* querier);
static void
spindump_connection_report_coap(struct spindump_connection* connection,
                                FILE* file,
                                int anonymize,
                                struct spindump_reverse_dns* querier);
static void
spindump_connection_report_icmp(struct spindump_connection* connection,
                                FILE* file,
                                int anonymize,
                                struct spindump_reverse_dns* querier);
static void
spindump_connection_report_hostpair(struct spindump_connection* connection,
                                    FILE* file,
                                    int anonymize,
                                    struct spindump_reverse_dns* querier);
static void
spindump_connection_report_hostnetwork(struct spindump_connection* connection,
                                       FILE* file,
                                       int anonymize,
                                       struct spindump_reverse_dns* querier);
static void
spindump_connection_report_networknetwork(struct spindump_connection* connection,
                                          FILE* file,
                                          int anonymize,
                                          struct spindump_reverse_dns* querier);
static void
spindump_connection_report_multicastgroup(struct spindump_connection* connection,
                                          FILE* file,
                                          int anonymize,
                                          struct spindump_reverse_dns* querier);

//
// Actual code --------------------------------------------------------------------------------
//

//
// Return the connection type as a string. The returned string is a
// static value, and need not be deallocated.
//

const char*
spindump_connection_type_to_string(enum spindump_connection_type type) {
  switch (type) {
  case spindump_connection_transport_tcp: return("TCP");
  case spindump_connection_transport_udp: return("UDP");
  case spindump_connection_transport_dns: return("DNS");
  case spindump_connection_transport_coap: return("COAP");
  case spindump_connection_transport_quic: return("QUIC");
  case spindump_connection_transport_icmp: return("ICMP");
  case spindump_connection_aggregate_hostpair: return("HOSTS");
  case spindump_connection_aggregate_hostnetwork: return("H2NET");
  case spindump_connection_aggregate_networknetwork: return("NET2NET");
  case spindump_connection_aggregate_multicastgroup: return("MCAST");
  default: return("INVALID");
  }
}

//
// Return 1 if a string can be mapped to a connection type. And set
// the output parameter type to the specific connection type. Return 0
// otherwise.
//

int
spindump_connection_string_to_connectiontype(const char* string,
                                             enum spindump_connection_type* type) {
  spindump_assert(string != 0);
  spindump_assert(type != 0);
  if (strcasecmp(string,"TCP") == 0) {
    *type = spindump_connection_transport_tcp;
    return(1);
  } else if (strcasecmp(string,"UDP") == 0) {
    *type = spindump_connection_transport_udp;
    return(1);
  } else if (strcasecmp(string,"DNS") == 0) {
    *type = spindump_connection_transport_dns;
    return(1);
  } else if (strcasecmp(string,"COAP") == 0) {
    *type = spindump_connection_transport_coap;
    return(1);
  } else if (strcasecmp(string,"QUIC") == 0) {
    *type = spindump_connection_transport_quic;
    return(1);
  } else if (strcasecmp(string,"ICMP") == 0) {
    *type = spindump_connection_transport_icmp;
    return(1);
  } else if (strcasecmp(string,"HOSTS") == 0) {
    *type = spindump_connection_aggregate_hostpair;
    return(1);
  } else if (strcasecmp(string,"H2NET") == 0) {
    *type = spindump_connection_aggregate_hostnetwork;
    return(1);
  } else if (strcasecmp(string,"NET2NET") == 0) {
    *type = spindump_connection_aggregate_networknetwork;
    return(1);
  } else if (strcasecmp(string,"MCAST") == 0) {
    *type = spindump_connection_aggregate_multicastgroup;
    return(1);
  } else {
    return(0);
  }
}

//
// Return 1 if a string can be mapped to a connection state. And set
// the output parameter "state" to the specific state. Return 0
// otherwise.
//

int
spindump_connection_statestring_to_state(const char* string,
                                         enum spindump_connection_state* state) {
  spindump_assert(string != 0);
  spindump_assert(state != 0);
  if (strcasecmp(string,"starting") == 0) {
    *state = spindump_connection_state_establishing;
    return(1);
  } else if (strcasecmp(string,"up") == 0) {
    *state = spindump_connection_state_established;
    return(1);
  } else if (strcasecmp(string,"closing") == 0) {
    *state = spindump_connection_state_closing;
    return(1);
  } else if (strcasecmp(string,"closed") == 0) {
    *state = spindump_connection_state_closed;
    return(1);
  } else if (strcasecmp(string,"static") == 0) {
    *state = spindump_connection_state_static;
    return(1);
  } else {
    return(0);
  }
}

//
// Print a report of a TCP connection
//

static void
spindump_connection_report_tcp(struct spindump_connection* connection,
                               FILE* file,
                               int anonymize,
                               struct spindump_reverse_dns* querier) {
  fprintf(file,"  host & port 1:         %10s:%u\n",
          spindump_connection_address_tostring(anonymize,&connection->u.tcp.side1peerAddress,querier),
          connection->u.tcp.side1peerPort);
  fprintf(file,"  host 2:                %10s:%u\n",
          spindump_connection_address_tostring(anonymize,&connection->u.tcp.side2peerAddress,querier),
          connection->u.tcp.side2peerPort);
}

//
// Print a report of a UDP connection
//

static void
spindump_connection_report_udp(struct spindump_connection* connection,
                               FILE* file,
                               int anonymize,
                               struct spindump_reverse_dns* querier) {
  fprintf(file,"  host & port 1:         %10s:%u\n",
          spindump_connection_address_tostring(anonymize,&connection->u.udp.side1peerAddress,querier),
          connection->u.udp.side1peerPort);
  fprintf(file,"  host 2:                %10s:%u\n",
          spindump_connection_address_tostring(anonymize,&connection->u.udp.side2peerAddress,querier),
          connection->u.udp.side2peerPort);
}

//
// Print a report of a DNS connection
//

static void
spindump_connection_report_dns(struct spindump_connection* connection,
                               FILE* file,
                               int anonymize,
                               struct spindump_reverse_dns* querier) {
  fprintf(file,"  host & port 1:         %10s:%u\n",
          spindump_connection_address_tostring(anonymize,&connection->u.dns.side1peerAddress,querier),
          connection->u.dns.side1peerPort);
  fprintf(file,"  host 2:                %10s:%u\n",
          spindump_connection_address_tostring(anonymize,&connection->u.dns.side2peerAddress,querier),
          connection->u.dns.side2peerPort);
}

//
// Print a report of a COAP connection
//

static void
spindump_connection_report_coap(struct spindump_connection* connection,
                                FILE* file,
                                int anonymize,
                                struct spindump_reverse_dns* querier) {
  fprintf(file,"  host & port 1:         %10s:%u\n",
          spindump_connection_address_tostring(anonymize,&connection->u.coap.side1peerAddress,querier),
          connection->u.coap.side1peerPort);
  fprintf(file,"  host 2:                %10s:%u\n",
          spindump_connection_address_tostring(anonymize,&connection->u.coap.side2peerAddress,querier),
          connection->u.coap.side2peerPort);
}

//
// Convert a QUIC connection ID to a string. The returned string need
// not be freed, but will not survive the next call to this function.
//
// Note: This function is not thread safe.
//

const char*
spindump_connection_quicconnectionid_tostring(struct spindump_quic_connectionid* id) {
  spindump_assert(id != 0);
  spindump_assert(id->len <= 18);
  static char buf[50];
  memset(buf,0,sizeof(buf));
  if (id->len == 0) return("null");
  unsigned int sizeRemains = sizeof(buf)-1;
  unsigned int position = 0;
  for (unsigned int i = 0; i < id->len; i++) {
    spindump_assert(position < sizeof(buf));
    int ans = snprintf(buf + position, sizeRemains, "%02x", id->id[i]);
    unsigned int howmuch = (unsigned int)ans;
    position += howmuch;
    sizeRemains -= howmuch;
  }
  return(buf);
}

//
// Print a report of a QUIC connection
//

static void
spindump_connection_report_quic(struct spindump_connection* connection,
                                FILE* file,
                                int anonymize,
                                struct spindump_reverse_dns* querier) {
  fprintf(file,"  host & port 1:         %10s:%u\n",
          spindump_connection_address_tostring(anonymize,&connection->u.quic.side1peerAddress,querier),
          connection->u.quic.side1peerPort);
  fprintf(file,"  host 2:                %10s:%u\n",
          spindump_connection_address_tostring(anonymize,&connection->u.quic.side2peerAddress,querier),
          connection->u.quic.side2peerPort);
  fprintf(file,"  peer 1 connection ID:  %40s\n",
          spindump_connection_quicconnectionid_tostring(&connection->u.quic.peer1ConnectionID));
  fprintf(file,"  peer 2 connection ID:  %40s\n",
          spindump_connection_quicconnectionid_tostring(&connection->u.quic.peer2ConnectionID));
  fprintf(file,"  initial right RTT:     %40s\n",
          spindump_rtt_tostring(connection->u.quic.initialRightRTT));
  fprintf(file,"  initial left RTT:      %40s\n",
          spindump_rtt_tostring(connection->u.quic.initialLeftRTT));
}

//
// Map an ICMP type value to a string
//

static const char*
spindump_icmptype_tostring(u_int8_t type) {
  switch (type) {
  case ICMP_ECHO: return("ECHO");
  case ICMP6_ECHO_REQUEST: return("ECHO");
  case ICMP_ECHOREPLY: return("ECHO REPLY");
  case ICMP6_ECHO_REPLY: return("ECHO REPLY");
  default: return("UNKNOWN");
  }
}

//
// Print a report of an ICMP connection
//

static void
spindump_connection_report_icmp(struct spindump_connection* connection,
                                FILE* file,
                                int anonymize,
                                struct spindump_reverse_dns* querier) {
  fprintf(file,"  host 1:                %40s\n", spindump_connection_address_tostring(anonymize,&connection->u.icmp.side1peerAddress,querier));
  fprintf(file,"  host 2:                %40s\n", spindump_connection_address_tostring(anonymize,&connection->u.icmp.side2peerAddress,querier));
  fprintf(file,"  icmp type:             %40s\n", spindump_icmptype_tostring(connection->u.icmp.side1peerType));
  fprintf(file,"  id:                      %38u\n", ntohs(connection->u.icmp.side1peerId));
  fprintf(file,"  last sequence #:         %38u\n", ntohs(connection->u.icmp.side1peerLatestSequence));
}

//
// Print a report of a host pair aggregate connection
//

static void
spindump_connection_report_hostpair(struct spindump_connection* connection,
                                    FILE* file,
                                    int anonymize,
                                    struct spindump_reverse_dns* querier) {
  fprintf(file,"  host 1:                %40s\n",
          spindump_connection_address_tostring(anonymize,
                                               &connection->u.aggregatehostpair.side1peerAddress,
                                               querier));
  fprintf(file,"  host 2:                %40s\n",
          spindump_connection_address_tostring(anonymize,
                                               &connection->u.aggregatehostpair.side2peerAddress,
                                               querier));
  fprintf(file,"  aggregates:            %40s\n",
          spindump_connections_set_listids(&connection->u.aggregatehostpair.connections));
}

//
// Print a report of a host - network aggregate connection
//

static void
spindump_connection_report_hostnetwork(struct spindump_connection* connection,
                                       FILE* file,
                                       int anonymize,
                                       struct spindump_reverse_dns* querier) {
  fprintf(file,"  host:                  %40s\n",
          spindump_connection_address_tostring(anonymize,
                                               &connection->u.aggregatehostnetwork.side1peerAddress,
                                               querier));
  fprintf(file,"  network:               %40s\n",
          spindump_network_tostring(&connection->u.aggregatehostnetwork.side2Network));
  fprintf(file,"  aggregates:            %40s\n",
          spindump_connections_set_listids(&connection->u.aggregatehostnetwork.connections));
}

//
// Print a report of a network pair aggregate connection
//

static void
spindump_connection_report_networknetwork(struct spindump_connection* connection,
                                          FILE* file,
                                          int anonymize,
                                          struct spindump_reverse_dns* querier) {
  fprintf(file,"  network 1:               %40s\n",
          spindump_network_tostring(&connection->u.aggregatenetworknetwork.side1Network));
  fprintf(file,"  network 2:               %40s\n",
          spindump_network_tostring(&connection->u.aggregatenetworknetwork.side2Network));
  fprintf(file,"  aggregates:            %40s\n",
          spindump_connections_set_listids(&connection->u.aggregatenetworknetwork.connections));
}

//
// Print a report of a multicast group aggregate connection
//

static void
spindump_connection_report_multicastgroup(struct spindump_connection* connection,
                                          FILE* file,
                                          int anonymize,
                                          struct spindump_reverse_dns* querier) {
  fprintf(file,"  group:                 %40s\n",
          spindump_address_tostring(&connection->u.aggregatemulticastgroup.group));
  fprintf(file,"  aggregates:            %40s\n",
          spindump_connections_set_listids(&connection->u.aggregatemulticastgroup.connections));
}

//
// Make a report of a connection (i.e., print out the data we have on it)
//

void
spindump_connection_report(struct spindump_connection* connection,
                           FILE* file,
                           int anonymize,
                           struct spindump_reverse_dns* querier) {

  //
  // Sanity checks
  //
  
  spindump_assert(connection != 0);
  spindump_assert(spindump_isbool(anonymize));

  //
  // Print connection identifier (a running number, an id)
  //
  
  fprintf(file,"CONNECTION %u (%s):\n",
          connection->id,
          spindump_connection_type_to_string(connection->type));

  //
  // For the rest, branch out based on what type of connection this is
  //
  
  switch (connection->type) {
  case spindump_connection_transport_tcp:
    spindump_connection_report_tcp(connection,file,anonymize,querier);
    break;
  case spindump_connection_transport_udp:
    spindump_connection_report_udp(connection,file,anonymize,querier);
    break;
  case spindump_connection_transport_dns:
    spindump_connection_report_dns(connection,file,anonymize,querier);
    break;
  case spindump_connection_transport_coap:
    spindump_connection_report_coap(connection,file,anonymize,querier);
    break;
  case spindump_connection_transport_quic:
    spindump_connection_report_quic(connection,file,anonymize,querier);
    break;
  case spindump_connection_transport_icmp:
    spindump_connection_report_icmp(connection,file,anonymize,querier);
    break;
  case spindump_connection_aggregate_hostpair:
    spindump_connection_report_hostpair(connection,file,anonymize,querier);
    break;
  case spindump_connection_aggregate_hostnetwork:
    spindump_connection_report_hostnetwork(connection,file,anonymize,querier);
    break;
  case spindump_connection_aggregate_networknetwork:
    spindump_connection_report_networknetwork(connection,file,anonymize,querier);
    break;
  case spindump_connection_aggregate_multicastgroup:
    spindump_connection_report_multicastgroup(connection,file,anonymize,querier);
    break;
  default:
    spindump_errorf("invalid connection type in spindump_connection_report");
    break;
  }

  //
  // Finally, print out some basic information common to all connections
  //
  
  fprintf(file,"  aggregated in:           %38s\n",
          spindump_connections_set_listids(&connection->aggregates));
  fprintf(file,"  packets 1->2:            %38u\n", connection->packetsFromSide1);
  fprintf(file,"  packets 2->1:            %38u\n", connection->packetsFromSide2);
  fprintf(file,"  bytes 1->2:              %38u\n", connection->bytesFromSide1);
  fprintf(file,"  bytes 2->1:              %38u\n", connection->bytesFromSide2);
  char rttbuf1[50];
  char rttbuf2[50];
  spindump_strlcpy(rttbuf1,
                   spindump_rtt_tostring(connection->leftRTT.lastRTT),
                   sizeof(rttbuf1));
  spindump_strlcpy(rttbuf2,
                   spindump_rtt_tostring(spindump_rtt_calculateLastMovingAvgRTT(&connection->leftRTT)),
                   sizeof(rttbuf2));
  fprintf(file,"  last left RTT:           %38s\n", rttbuf1);
  fprintf(file,"  moving avg left RTT:     %38s\n", rttbuf2);
  spindump_strlcpy(rttbuf1,
                   spindump_rtt_tostring(connection->rightRTT.lastRTT),
                   sizeof(rttbuf1));
  spindump_strlcpy(rttbuf2,
                   spindump_rtt_tostring(spindump_rtt_calculateLastMovingAvgRTT(&connection->rightRTT)),
                   sizeof(rttbuf2));
  fprintf(file,"  last right RTT:          %38s\n", rttbuf1);
  fprintf(file,"  moving avg right RTT:    %38s\n", rttbuf2);
}

//
// Map a connection address to a string, handling anonymisation,
// reverse DNS, etc.
//

static const char*
spindump_connection_address_tostring(int anonymize,
                                     spindump_address* address,
                                     struct spindump_reverse_dns* querier) {
  if (anonymize) {
    return(spindump_address_tostring_anon(1,address));
  } else {
    const char* name = spindump_reverse_dns_query(address,querier);
    if (name != 0) {
      return(name);
    } else {
      return(spindump_address_tostring(address));
    }
  }
}

//
// Return a string representation of the addresses in a connection
// object. The returned string need not be freed.
//
// Note: This function is not thread safe.
//

const char*
spindump_connection_addresses(struct spindump_connection* connection,
                              unsigned int maxlen,
                              int anonymizeLeft,
                              int anonymizeRight,
                              int json,
                              struct spindump_reverse_dns* querier) {

  //
  // Checks
  //

  spindump_assert(connection != 0);
  spindump_assert(spindump_isbool(anonymizeLeft));
  spindump_assert(spindump_isbool(anonymizeRight));
  spindump_assert(spindump_isbool(json));
  spindump_assert(querier != 0);
  
  //
  // Reserve buffer space, check there's enough space to print
  //
  
  static char buf[200];
  memset(buf,0,sizeof(buf));
  if (maxlen <= 2) {
    buf[0] = 0;
    return(buf);
  }
  
  //
  // Add the start of the JSON as needed
  //
  
  const char* middle = json ? "\",\"" : " <-> ";
  if (json) {
    spindump_strlcat(buf,"[",sizeof(buf));
  }
  
  //
  // Branch based on connection type
  //

  switch (connection->type) {
  case spindump_connection_transport_tcp:
    spindump_strlcpy(buf,
                     spindump_connection_address_tostring(anonymizeLeft,&connection->u.tcp.side1peerAddress,querier),
                     sizeof(buf));
    spindump_strlcat(buf,middle,sizeof(buf));
    spindump_strlcat(buf,
                     spindump_connection_address_tostring(anonymizeRight,&connection->u.tcp.side2peerAddress,querier),
                     sizeof(buf));
    break;
  case spindump_connection_transport_udp:
    spindump_strlcpy(buf,
                     spindump_connection_address_tostring(anonymizeLeft,&connection->u.udp.side1peerAddress,querier),
                     sizeof(buf));
    spindump_strlcat(buf,middle,sizeof(buf));
    spindump_strlcat(buf,
                     spindump_connection_address_tostring(anonymizeRight,&connection->u.udp.side2peerAddress,querier),
                     sizeof(buf));
    break;
  case spindump_connection_transport_dns:
    spindump_strlcpy(buf,
                     spindump_connection_address_tostring(anonymizeLeft,&connection->u.dns.side1peerAddress,querier),
                     sizeof(buf));
    spindump_strlcat(buf,middle,sizeof(buf));
    spindump_strlcat(buf,
                     spindump_connection_address_tostring(anonymizeRight,&connection->u.dns.side2peerAddress,querier),
                     sizeof(buf));
    break;
  case spindump_connection_transport_coap:
    spindump_strlcpy(buf,
                     spindump_connection_address_tostring(anonymizeLeft,&connection->u.coap.side1peerAddress,querier),
                     sizeof(buf));
    spindump_strlcat(buf,middle,sizeof(buf));
    spindump_strlcat(buf,
                     spindump_connection_address_tostring(anonymizeRight,&connection->u.coap.side2peerAddress,querier),
                     sizeof(buf));
    break;
  case spindump_connection_transport_quic:
    spindump_strlcpy(buf,
                     spindump_connection_address_tostring(anonymizeLeft,&connection->u.quic.side1peerAddress,querier),
                     sizeof(buf));
    spindump_strlcat(buf,middle,sizeof(buf));
    spindump_strlcat(buf,
                     spindump_connection_address_tostring(anonymizeRight,&connection->u.quic.side2peerAddress,querier),
                     sizeof(buf));
    break;
  case spindump_connection_transport_icmp:
    spindump_strlcpy(buf,
                     spindump_connection_address_tostring(anonymizeLeft,&connection->u.icmp.side1peerAddress,querier),
                     sizeof(buf));
    spindump_strlcat(buf,middle,sizeof(buf));
    spindump_strlcat(buf,
                     spindump_connection_address_tostring(anonymizeRight,&connection->u.icmp.side2peerAddress,querier),
                     sizeof(buf));
    break;
  case spindump_connection_aggregate_hostpair:
    spindump_strlcpy(buf,
                     spindump_connection_address_tostring(anonymizeLeft,&connection->u.aggregatehostpair.side1peerAddress,querier),
                     sizeof(buf));
    spindump_strlcat(buf,middle,sizeof(buf));
    spindump_strlcat(buf,
                     spindump_connection_address_tostring(anonymizeRight,&connection->u.aggregatehostpair.side2peerAddress,querier),
                     sizeof(buf));
    break;
  case spindump_connection_aggregate_hostnetwork:
    spindump_strlcpy(buf,
                     spindump_connection_address_tostring(anonymizeLeft,&connection->u.aggregatehostnetwork.side1peerAddress,querier),
                     sizeof(buf));
    spindump_strlcat(buf,middle,sizeof(buf));
    spindump_strlcat(buf,spindump_network_tostring(&connection->u.aggregatehostnetwork.side2Network),sizeof(buf));
    break;
  case spindump_connection_aggregate_networknetwork:
    spindump_strlcpy(buf,spindump_network_tostring(&connection->u.aggregatenetworknetwork.side1Network),sizeof(buf));
    spindump_strlcat(buf,middle,sizeof(buf));
    spindump_strlcat(buf,spindump_network_tostring(&connection->u.aggregatenetworknetwork.side2Network),sizeof(buf));
    break;
  case spindump_connection_aggregate_multicastgroup:
    spindump_strlcpy(buf,spindump_address_tostring(&connection->u.aggregatemulticastgroup.group),sizeof(buf));
    break;
  default:
    spindump_errorf("invalid connection type");
    spindump_strlcpy(buf,"invalid",sizeof(buf));
  }
  
  if (json) {
    spindump_strlcat(buf,"]",sizeof(buf));
  }
  
  if (strlen(buf) > maxlen) {
    buf[maxlen-2] = '.';
    buf[maxlen-1] = '.';
    buf[maxlen-0] = 0;
  }
  
  return(buf);
}

//
// Map a state of a connection to a string that can be used outputs
// and the UI
//

const char*
spindump_connection_statestring_plain(enum spindump_connection_state state) {
  switch (state) {
  case spindump_connection_state_establishing: return("Starting");
  case spindump_connection_state_established: return("Up");
  case spindump_connection_state_closing: return("Closing");
  case spindump_connection_state_closed: return("Closed");
  case spindump_connection_state_static: return("Static");
  default:
    spindump_errorf("invalid connection state");
    return("invalid");
  }
}

//
// Map a state of a connection to a string that can be used outputs
// and the UI
//

const char*
spindump_connection_statestring(struct spindump_connection* connection) {
  spindump_assert(connection != 0);
  return(spindump_connection_statestring_plain(connection->state));
}

//
// Construct a string describing a session. The string space is given
// by the caller in "buffer" parameter. The maximum size of the buffer
// (including the nul character in the end) is given by the "maxlen"
// parameter.
//

void
spindump_connection_sessionstring(struct spindump_connection* connection,
                                  char* buffer,
                                  size_t maxlen) {
  
  spindump_assert(connection != 0);

  if (maxlen <= 2) {
    buffer[0] = 0;
    return;
  }
  
  memset(buffer,0,maxlen);
  
  switch (connection->type) {
  case spindump_connection_transport_tcp:
    snprintf(buffer,maxlen-1,"%u:%u",
             connection->u.tcp.side1peerPort,
             connection->u.tcp.side2peerPort);
    break;
    
  case spindump_connection_transport_udp:
    snprintf(buffer,maxlen-1,"%u:%u",
             connection->u.udp.side1peerPort,
             connection->u.udp.side2peerPort);
    break;
    
  case spindump_connection_transport_dns:
    snprintf(buffer,maxlen-1,"%u:%u",
             connection->u.dns.side1peerPort,
             connection->u.dns.side2peerPort);
    break;
    
  case spindump_connection_transport_coap:
    snprintf(buffer,maxlen-1,"%u:%u",
             connection->u.coap.side1peerPort,
             connection->u.coap.side2peerPort);
    break;
    
  case spindump_connection_transport_quic:
    snprintf(buffer,maxlen-1,"%s-",
             spindump_connection_quicconnectionid_tostring(&connection->u.quic.peer1ConnectionID));
    snprintf(buffer+strlen(buffer),maxlen-strlen(buffer)-1,"%s",
             spindump_connection_quicconnectionid_tostring(&connection->u.quic.peer2ConnectionID));
    snprintf(buffer+strlen(buffer),maxlen-strlen(buffer)-1," (%u:%u)",
             connection->u.quic.side1peerPort,
             connection->u.quic.side2peerPort);
    break;
    
  case spindump_connection_transport_icmp:
    snprintf(buffer,maxlen-1,"%u",ntohs(connection->u.icmp.side1peerId));
    break;
    
  case spindump_connection_aggregate_hostpair:
    snprintf(buffer,maxlen-1,"%u sessions",
             connection->u.aggregatehostpair.connections.nConnections);
    break;
    
  case spindump_connection_aggregate_hostnetwork:
    snprintf(buffer,maxlen-1,"%u sessions",
             connection->u.aggregatehostnetwork.connections.nConnections);
    break;

  case spindump_connection_aggregate_networknetwork:
    snprintf(buffer,maxlen-1,"%u sessions",
             connection->u.aggregatenetworknetwork.connections.nConnections);
    break;

  case spindump_connection_aggregate_multicastgroup:
    snprintf(buffer,maxlen-1,"%u sessions",
             connection->u.aggregatemulticastgroup.connections.nConnections);
    break;
    
  default:
    spindump_errorf("invalid connection type");
    return;
  }
  
  if (strlen(buffer) >= maxlen - 1) {
    buffer[maxlen-3] = '.';
    buffer[maxlen-2] = '.';
    buffer[maxlen-1] = 0;
  }
}

//
// Determine what should be the field size of the session field, given
// a particular number of characters available per line.
//

unsigned int
spindump_connection_report_brief_sessionsize(unsigned int linelen) {
  if (linelen >= 140)
    return(55);
  else if (linelen >= 120)
    return(42);
  else if (linelen >= 100)
    return(30);
  else if (linelen >= 80)
    return(20);
  else
    return(12);
}

//
// Determine whether we have space for a note field, given a
// particular number of characters available per line.
//

int
spindump_connection_report_brief_isnotefield(unsigned int linelen) {
  return(linelen >= 130);
}

//
// Determine what should be the field size of the note field.
//

#define spindump_connection_report_brief_notefieldval_length_val 24

unsigned int
spindump_connection_report_brief_notefieldval_length(void) {
  return(spindump_connection_report_brief_notefieldval_length_val);
}

//
// Determine what should be the size of all the fixed-length fields,
// given a particular number of characters available per line.
//

unsigned int
spindump_connection_report_brief_fixedsize(unsigned int linelen) {
  return(7+1+spindump_connection_report_brief_sessionsize(linelen)+
         1+8+1+6+1+10+1+10+1+
         (spindump_connection_report_brief_isnotefield(linelen) ?
          spindump_connection_report_brief_notefieldval_length_val+2 :
          0));
}

//
// Determine what should be the size of all variable-length fields,
// given a particular number of characters available per line.
//

unsigned int
spindump_connection_report_brief_variablesize(unsigned int linelen) {
  unsigned int fixed = spindump_connection_report_brief_fixedsize(linelen);
  return(linelen > fixed ? linelen - fixed : 0);
}

//
// Add material to a buffer
//

static void
spindump_connection_addtobuf(char* buf,
                             unsigned int bufsize,
                             const char* text,
                             const char* value,
                             int compress) {
  spindump_assert(spindump_isbool(compress));
  if (buf[0] != 0) {
    snprintf(buf+strlen(buf),bufsize-1-strlen(buf),",");
    if (!compress) snprintf(buf+strlen(buf),bufsize-1-strlen(buf)," ");
    snprintf(buf+strlen(buf),bufsize-1-strlen(buf),"%s",text);
    snprintf(buf+strlen(buf),bufsize-1-strlen(buf),"%s",value);
  } else {
    if (isalpha(*text)) {
      snprintf(buf+strlen(buf),bufsize-1-strlen(buf),"%c",toupper(*text));
      snprintf(buf+strlen(buf),bufsize-1-strlen(buf),"%s",text+1);
    } else {
      snprintf(buf+strlen(buf),bufsize-1-strlen(buf),"%s",text);
    }
    snprintf(buf+strlen(buf),bufsize-1-strlen(buf),"%s",value);
  }
}

//
// Return the value of the note field in the spindump --visual mode.
//
// Note: This function is not thread safe.
//

static const char*
spindump_connection_report_brief_notefieldval(struct spindump_connection* connection) {

  //
  // Checks
  // 
  
  spindump_assert(connection != 0);

  //
  // Setup a buffer to hold the note
  // 

  spindump_deepdeepdebugf("report_brief_notefieldval point 1");
  static char buf[spindump_connection_report_brief_notefieldval_length_val+1];
  memset(buf,0,sizeof(buf));
  
  //
  // Check connection status
  // 

  if (connection->packetsFromSide2 == 0) {
    if (connection->type == spindump_connection_transport_quic ||
        connection->type == spindump_connection_transport_dns ||
        connection->type == spindump_connection_transport_coap) {
      spindump_deepdeepdebugf("report_brief_notefieldval point 2");
      spindump_connection_addtobuf(buf,sizeof(buf),"no rsp","",1);
    } else {
      spindump_deepdeepdebugf("report_brief_notefieldval point 3");
      spindump_connection_addtobuf(buf,sizeof(buf),"no response","",0);
    }
  }

  //
  // QUIC-specific notes
  // 
  
  if (connection->type == spindump_connection_transport_quic) {
    spindump_deepdeepdebugf("report_brief_notefieldval point 4");
    if (connection->u.quic.version == connection->u.quic.originalVersion ||
        spindump_quic_version_isforcenegot(connection->u.quic.originalVersion)) {
      spindump_connection_addtobuf(buf,sizeof(buf),
                                   spindump_analyze_quic_parser_versiontostring(connection->u.quic.version),
                                   "",
                                   1);
    } else {
      char vbuf[50];
      const char* orig = spindump_analyze_quic_parser_versiontostring(connection->u.quic.originalVersion);
      if (strncmp(orig,"v.",2) == 0) orig += 2;
      memset(vbuf,0,sizeof(vbuf));
      snprintf(vbuf,sizeof(vbuf)-1,"%s(%s)",
               spindump_analyze_quic_parser_versiontostring(connection->u.quic.version),
               orig);
      spindump_connection_addtobuf(buf,sizeof(buf),
                                   vbuf,
                                   "",
                                   1);
    }
    if (connection->u.quic.spinFromPeer1to2.totalSpins == 0 &&
        connection->u.quic.spinFromPeer2to1.totalSpins == 0) {
      spindump_deepdeepdebugf("report_brief_notefieldval point 5");
      spindump_connection_addtobuf(buf,sizeof(buf),"no spin","",1);
    } else if (connection->u.quic.spinFromPeer1to2.totalSpins != 0 &&
               connection->u.quic.spinFromPeer2to1.totalSpins == 0) {
      spindump_deepdeepdebugf("report_brief_notefieldval point 6");
      spindump_connection_addtobuf(buf,sizeof(buf),"no R-spin","",1);
    } else if (connection->u.quic.spinFromPeer1to2.totalSpins == 0 &&
               connection->u.quic.spinFromPeer2to1.totalSpins != 0) {
      spindump_deepdeepdebugf("report_brief_notefieldval point 7");
      spindump_connection_addtobuf(buf,sizeof(buf),"no I-spin","",1);
    } else {
      spindump_deepdeepdebugf("report_brief_notefieldval point 8");
      spindump_connection_addtobuf(buf,sizeof(buf),"spinning","",1);
    }
  }

  //
  // DNS-specific notes
  // 
  
  if (connection->type == spindump_connection_transport_dns) {
    if (connection->u.dns.lastQueriedName[0] != 0) {
      spindump_deepdeepdebugf("report_brief_notefieldval point 9");
      spindump_connection_addtobuf(buf,sizeof(buf),"Q ",connection->u.dns.lastQueriedName,1);
    }
  }
  
  //
  // COAP-specific notes
  // 
  
  if (connection->type == spindump_connection_transport_coap) {
    if (connection->u.coap.dtls) {
      spindump_deepdeepdebugf("report_brief_notefieldval point 10");
      const char* versionString = spindump_analyze_tls_parser_versiontostring(connection->u.coap.dtlsVersion);
      spindump_connection_addtobuf(buf,sizeof(buf),"DTLS ",versionString,1);
    }
  }
  
  //
  // Done. Return the result.
  // 
  
  spindump_deepdeepdebugf("report_brief_notefieldval point 999");
  return(buf);
}

//
// This is the main entry point for the connection-printing function
// in the Spindump UI. This function prints one line of a report for
// one connection
//

void
spindump_connection_report_brief(struct spindump_connection* connection,
                                 char* buf,
                                 unsigned int bufsiz,
                                 int avg,
                                 unsigned int linelen,
                                 int anonymizeLeft,
                                 int anonymizeRight,
                                 struct spindump_reverse_dns* querier) {
  char paksbuf[20];
  char rttbuf1[20];
  char rttbuf2[20];
  
  spindump_assert(connection != 0);
  spindump_assert(buf != 0);
  spindump_assert(spindump_isbool(avg));
  spindump_assert(spindump_isbool(anonymizeLeft));
  spindump_assert(spindump_isbool(anonymizeRight));

  spindump_deepdeepdebugf("report_brief point 1");
  memset(paksbuf,0,sizeof(paksbuf));
  snprintf(paksbuf,sizeof(paksbuf)-1,"%s",
           spindump_meganumber_tostring(connection->packetsFromSide1 + connection->packetsFromSide2));
  memset(rttbuf1,0,sizeof(rttbuf1));
  memset(rttbuf2,0,sizeof(rttbuf2));
  spindump_deepdeepdebugf("report_brief point 2");
  if (avg) {
    spindump_strlcpy(rttbuf1,spindump_rtt_tostring(spindump_rtt_calculateLastMovingAvgRTT(&connection->leftRTT)),sizeof(rttbuf1));
    spindump_strlcpy(rttbuf2,spindump_rtt_tostring(spindump_rtt_calculateLastMovingAvgRTT(&connection->rightRTT)),sizeof(rttbuf2));
  } else {
    spindump_strlcpy(rttbuf1,spindump_rtt_tostring(connection->leftRTT.lastRTT),sizeof(rttbuf1));
    spindump_strlcpy(rttbuf2,spindump_rtt_tostring(connection->rightRTT.lastRTT),sizeof(rttbuf2));
  }
  spindump_deepdeepdebugf("report_brief point 3");
  unsigned int addrsiz = spindump_connection_report_brief_variablesize(linelen);
  unsigned int maxsessionlen = spindump_connection_report_brief_sessionsize(linelen);
  spindump_deepdeepdebugf("report_brief point 4");
  char sessionbuf[120];
  size_t maxsessionbuflen = spindump_min(sizeof(sessionbuf),maxsessionlen);
  spindump_connection_sessionstring(connection,sessionbuf,maxsessionbuflen);
  snprintf(buf,bufsiz,"%-7s %-*s %-*s %8s %6s %10s %10s",
           spindump_connection_type_to_string(connection->type),
           addrsiz,
           spindump_connection_addresses(connection,addrsiz,anonymizeLeft,anonymizeRight,0,querier),
           maxsessionlen,
           sessionbuf,
           spindump_connection_statestring(connection),
           paksbuf,
           rttbuf1,
           rttbuf2);
  spindump_deepdeepdebugf("report_brief point 5");
  if (spindump_connection_report_brief_isnotefield(linelen)) {
    spindump_deepdeepdebugf("report_brief point 5b");
    snprintf(buf + strlen(buf),bufsiz - strlen(buf),"  %-*s",
             spindump_connection_report_brief_notefieldval_length_val,
             spindump_connection_report_brief_notefieldval(connection));
  }
  spindump_deepdeepdebugf("report_brief point 6");
}
