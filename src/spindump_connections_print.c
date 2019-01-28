
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

void
spindump_connection_report_tcp(struct spindump_connection* connection,
			       FILE* file,
			       struct spindump_reverse_dns* querier) {
  fprintf(file,"  host & port 1:         %10s:%u\n",
	  spindump_address_tostring(&connection->u.tcp.side1peerAddress),
	  connection->u.tcp.side1peerPort);
  fprintf(file,"  host 2:                %10s:%u\n",
	  spindump_address_tostring(&connection->u.tcp.side2peerAddress),
	  connection->u.tcp.side2peerPort);
}

void
spindump_connection_report_udp(struct spindump_connection* connection,
			       FILE* file,
			       struct spindump_reverse_dns* querier) {
  fprintf(file,"  host & port 1:         %10s:%u\n",
	  spindump_address_tostring(&connection->u.udp.side1peerAddress),
	  connection->u.udp.side1peerPort);
  fprintf(file,"  host 2:                %10s:%u\n",
	  spindump_address_tostring(&connection->u.udp.side2peerAddress),
	  connection->u.udp.side2peerPort);
}

void
spindump_connection_report_dns(struct spindump_connection* connection,
			       FILE* file,
			       struct spindump_reverse_dns* querier) {
  fprintf(file,"  host & port 1:         %10s:%u\n",
	  spindump_address_tostring(&connection->u.dns.side1peerAddress),
	  connection->u.dns.side1peerPort);
  fprintf(file,"  host 2:                %10s:%u\n",
	  spindump_address_tostring(&connection->u.dns.side2peerAddress),
	  connection->u.dns.side2peerPort);
}

void
spindump_connection_report_coap(struct spindump_connection* connection,
				FILE* file,
				struct spindump_reverse_dns* querier) {
  fprintf(file,"  host & port 1:         %10s:%u\n",
	  spindump_address_tostring(&connection->u.coap.side1peerAddress),
	  connection->u.coap.side1peerPort);
  fprintf(file,"  host 2:                %10s:%u\n",
	  spindump_address_tostring(&connection->u.coap.side2peerAddress),
	  connection->u.coap.side2peerPort);
}

const char*
spindump_connection_quicconnectionid_tostring(struct spindump_quic_connectionid* id) {
  spindump_assert(id != 0);
  spindump_assert(id->len <= 18);
  static char buf[50];
  memset(buf,0,sizeof(buf));
  if (id->len == 0) return("null");
  for (unsigned int i = 0; i < id->len; i++) {
    sprintf(buf + strlen(buf), "%02x", id->id[i]);
  }
  return(buf);
}

void
spindump_connection_report_quic(struct spindump_connection* connection,
				FILE* file,
				struct spindump_reverse_dns* querier) {
  fprintf(file,"  host & port 1:         %10s:%u\n",
	  spindump_address_tostring(&connection->u.quic.side1peerAddress),
	  connection->u.quic.side1peerPort);
  fprintf(file,"  host 2:                %10s:%u\n",
	  spindump_address_tostring(&connection->u.quic.side2peerAddress),
	  connection->u.quic.side2peerPort);
  fprintf(file,"  peer 1 connection ID:  %40s\n",
	  spindump_connection_quicconnectionid_tostring(&connection->u.quic.peer1ConnectionID));
  fprintf(file,"  peer 2 connection ID:  %40s\n",
	  spindump_connection_quicconnectionid_tostring(&connection->u.quic.peer2ConnectionID));
  fprintf(file,"  initial right RTT:     %40s\n",
	  spindump_rtt_tostring(connection->u.quic.initialRightRTT));
  fprintf(file,"  initial left RTT:     %40s\n",
	  spindump_rtt_tostring(connection->u.quic.initialLeftRTT));
}

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

void
spindump_connection_report_icmp(struct spindump_connection* connection,
				FILE* file,
				struct spindump_reverse_dns* querier) {
  fprintf(file,"  host 1:                %40s\n", spindump_address_tostring(&connection->u.icmp.side1peerAddress));
  fprintf(file,"  host 2:                %40s\n", spindump_address_tostring(&connection->u.icmp.side2peerAddress));
  fprintf(file,"  icmp type:             %40s\n", spindump_icmptype_tostring(connection->u.icmp.side1peerType));
  fprintf(file,"  id:                      %38u\n", ntohs(connection->u.icmp.side1peerId));
  fprintf(file,"  last sequence #:         %38u\n", ntohs(connection->u.icmp.side1peerLatestSequence));
}

void
spindump_connection_report_hostpair(struct spindump_connection* connection,
				    FILE* file,
				    struct spindump_reverse_dns* querier) {
  fprintf(file,"  host 1:                %40s\n", spindump_address_tostring(&connection->u.aggregatehostpair.side1peerAddress));
  fprintf(file,"  host 2:                %40s\n", spindump_address_tostring(&connection->u.aggregatehostpair.side2peerAddress));
  fprintf(file,"  aggregates:            %40s\n",
	  spindump_connections_set_listids(&connection->u.aggregatehostpair.connections));
}

void
spindump_connection_report_hostnetwork(struct spindump_connection* connection,
				       FILE* file,
				       struct spindump_reverse_dns* querier) {
  fprintf(file,"  host:                  %40s\n", spindump_address_tostring(&connection->u.aggregatehostnetwork.side1peerAddress));
  fprintf(file,"  network:               %40s\n", spindump_network_tostring(&connection->u.aggregatehostnetwork.side2Network));
  fprintf(file,"  aggregates:            %40s\n",
	  spindump_connections_set_listids(&connection->u.aggregatehostnetwork.connections));
}

void
spindump_connection_report_networknetwork(struct spindump_connection* connection,
					  FILE* file,
					  struct spindump_reverse_dns* querier) {
  fprintf(file,"  network 1:               %40s\n", spindump_network_tostring(&connection->u.aggregatenetworknetwork.side1Network));
  fprintf(file,"  network 2:               %40s\n", spindump_network_tostring(&connection->u.aggregatenetworknetwork.side2Network));
  fprintf(file,"  aggregates:            %40s\n",
	  spindump_connections_set_listids(&connection->u.aggregatenetworknetwork.connections));
}

void
spindump_connection_report_multicastgroup(struct spindump_connection* connection,
					  FILE* file,
					  struct spindump_reverse_dns* querier) {
  fprintf(file,"  group:                 %40s\n", spindump_address_tostring(&connection->u.aggregatemulticastgroup.group));
  fprintf(file,"  aggregates:            %40s\n",
	  spindump_connections_set_listids(&connection->u.aggregatemulticastgroup.connections));
}

void
spindump_connection_report(struct spindump_connection* connection,
			   FILE* file,
			   struct spindump_reverse_dns* querier) {
  spindump_assert(connection != 0);
  fprintf(file,"CONNECTION %u (%s):\n",
	  connection->id,
	  spindump_connection_type_to_string(connection->type));
  switch (connection->type) {
  case spindump_connection_transport_tcp:
    spindump_connection_report_tcp(connection,file,querier);
    break;
  case spindump_connection_transport_udp:
    spindump_connection_report_udp(connection,file,querier);
    break;
  case spindump_connection_transport_dns:
    spindump_connection_report_dns(connection,file,querier);
    break;
  case spindump_connection_transport_coap:
    spindump_connection_report_coap(connection,file,querier);
    break;
  case spindump_connection_transport_quic:
    spindump_connection_report_quic(connection,file,querier);
    break;
  case spindump_connection_transport_icmp:
    spindump_connection_report_icmp(connection,file,querier);
    break;
  case spindump_connection_aggregate_hostpair:
    spindump_connection_report_hostpair(connection,file,querier);
    break;
  case spindump_connection_aggregate_hostnetwork:
    spindump_connection_report_hostnetwork(connection,file,querier);
    break;
  case spindump_connection_aggregate_networknetwork:
    spindump_connection_report_networknetwork(connection,file,querier);
    break;
  case spindump_connection_aggregate_multicastgroup:
    spindump_connection_report_multicastgroup(connection,file,querier);
    break;
  default:
    spindump_errorf("invalid connection type in spindump_connection_report");
    break;
  }
  fprintf(file,"  aggregated in:           %38s\n",
	  spindump_connections_set_listids(&connection->aggregates));
  fprintf(file,"  packets 1->2:            %38u\n", connection->packetsFromSide1);
  fprintf(file,"  packets 2->1:            %38u\n", connection->packetsFromSide2);
  fprintf(file,"  bytes 1->2:              %38u\n", connection->bytesFromSide1);
  fprintf(file,"  bytes 2->1:              %38u\n", connection->bytesFromSide2);
  char rttbuf1[50];
  char rttbuf2[50];
  strcpy(rttbuf1,spindump_rtt_tostring(connection->leftRTT.lastRTT));
  strcpy(rttbuf2,spindump_rtt_tostring(spindump_rtt_calculateLastMovingAvgRTT(&connection->leftRTT)));
  fprintf(file,"  last left RTT:           %38s\n", rttbuf1);
  fprintf(file,"  moving avg left RTT:     %38s\n", rttbuf2);
  strcpy(rttbuf1,spindump_rtt_tostring(connection->rightRTT.lastRTT));
  strcpy(rttbuf2,spindump_rtt_tostring(spindump_rtt_calculateLastMovingAvgRTT(&connection->rightRTT)));
  fprintf(file,"  last right RTT:          %38s\n", rttbuf1);
  fprintf(file,"  moving avg right RTT:    %38s\n", rttbuf2);
}

static const char*
spindump_connection_address_tostring(int anonymize,
				     spindump_address* address,
				     struct spindump_reverse_dns* querier) {
  if (anonymize) {
    return(spindump_address_tostring_anon(1,address));
  } else {
    const char* name = spindump_reverse_dns_query(address,querier);
    if (name != 0) return(name);
    else return(spindump_address_tostring(address));
  }
}

const char*
spindump_connection_addresses(struct spindump_connection* connection,
			      unsigned int maxlen,
			      int anonymizeLeft,
			      int anonymizeRight,
			      struct spindump_reverse_dns* querier) {

  //
  // Checks
  //

  spindump_assert(connection != 0);
  spindump_assert(maxlen > 2);
  spindump_assert(spindump_isbool(anonymizeLeft));
  spindump_assert(spindump_isbool(anonymizeRight));
  spindump_assert(querier != 0);
  
  //
  // Reserve buffer space
  //
  
  static char buf[200];

  //
  // Branch based on connection type
  //
  
  switch (connection->type) {
  case spindump_connection_transport_tcp:
    strcpy(buf,spindump_connection_address_tostring(anonymizeLeft,&connection->u.tcp.side1peerAddress,querier));
    strcat(buf," <-> ");
    strcat(buf,spindump_connection_address_tostring(anonymizeRight,&connection->u.tcp.side2peerAddress,querier));
    break;
  case spindump_connection_transport_udp:
    strcpy(buf,spindump_connection_address_tostring(anonymizeLeft,&connection->u.udp.side1peerAddress,querier));
    strcat(buf," <-> ");
    strcat(buf,spindump_connection_address_tostring(anonymizeRight,&connection->u.udp.side2peerAddress,querier));
    break;
  case spindump_connection_transport_dns:
    strcpy(buf,spindump_connection_address_tostring(anonymizeLeft,&connection->u.dns.side1peerAddress,querier));
    strcat(buf," <-> ");
    strcat(buf,spindump_connection_address_tostring(anonymizeRight,&connection->u.dns.side2peerAddress,querier));
    break;
  case spindump_connection_transport_coap:
    strcpy(buf,spindump_connection_address_tostring(anonymizeLeft,&connection->u.coap.side1peerAddress,querier));
    strcat(buf," <-> ");
    strcat(buf,spindump_connection_address_tostring(anonymizeRight,&connection->u.coap.side2peerAddress,querier));
    break;
  case spindump_connection_transport_quic:
    strcpy(buf,spindump_connection_address_tostring(anonymizeLeft,&connection->u.quic.side1peerAddress,querier));
    strcat(buf," <-> ");
    strcat(buf,spindump_connection_address_tostring(anonymizeRight,&connection->u.quic.side2peerAddress,querier));
    break;
  case spindump_connection_transport_icmp:
    strcpy(buf,spindump_connection_address_tostring(anonymizeLeft,&connection->u.icmp.side1peerAddress,querier));
    strcat(buf," <-> ");
    strcat(buf,spindump_connection_address_tostring(anonymizeRight,&connection->u.icmp.side2peerAddress,querier));
    break;
  case spindump_connection_aggregate_hostpair:
    strcpy(buf,spindump_connection_address_tostring(anonymizeLeft,&connection->u.aggregatehostpair.side1peerAddress,querier));
    strcat(buf," <-> ");
    strcat(buf,spindump_connection_address_tostring(anonymizeRight,&connection->u.aggregatehostpair.side2peerAddress,querier));
    break;
  case spindump_connection_aggregate_hostnetwork:
    strcpy(buf,spindump_connection_address_tostring(anonymizeLeft,&connection->u.aggregatehostnetwork.side1peerAddress,querier));
    strcat(buf," <-> ");
    strcat(buf,spindump_network_tostring(&connection->u.aggregatehostnetwork.side2Network));
    break;
  case spindump_connection_aggregate_networknetwork:
    strcpy(buf,spindump_network_tostring(&connection->u.aggregatenetworknetwork.side1Network));
    strcat(buf," <-> ");
    strcat(buf,spindump_network_tostring(&connection->u.aggregatenetworknetwork.side2Network));
    break;
  case spindump_connection_aggregate_multicastgroup:
    strcpy(buf,spindump_address_tostring(&connection->u.aggregatemulticastgroup.group));
    break;
  default:
    spindump_errorf("invalid connection type");
    strcpy(buf,"invalid");
  }
  
  if (strlen(buf) > maxlen) {
    buf[maxlen-2] = '.';
    buf[maxlen-1] = '.';
    buf[maxlen-0] = 0;
  }
  
  return(buf);
}

const char*
spindump_connection_statestring_aux(enum spindump_connection_state state) {
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

const char*
spindump_connection_statestring(struct spindump_connection* connection) {
  spindump_assert(connection != 0);
  return(spindump_connection_statestring_aux(connection->state));
}

const char*
spindump_connection_sessionstring(struct spindump_connection* connection,
				  unsigned int maxlen) {
  static char buf[100];
  
  spindump_assert(connection != 0);
  spindump_assert(maxlen > 2);
  memset(buf,0,sizeof(buf));
  
  switch (connection->type) {
  case spindump_connection_transport_tcp:
    snprintf(buf,sizeof(buf)-1,"%u:%u",
	     connection->u.tcp.side1peerPort,
	     connection->u.tcp.side2peerPort);
    break;
    
  case spindump_connection_transport_udp:
    snprintf(buf,sizeof(buf)-1,"%u:%u",
	     connection->u.udp.side1peerPort,
	     connection->u.udp.side2peerPort);
    break;
    
  case spindump_connection_transport_dns:
    snprintf(buf,sizeof(buf)-1,"%u:%u",
	     connection->u.dns.side1peerPort,
	     connection->u.dns.side2peerPort);
    break;
    
  case spindump_connection_transport_coap:
    snprintf(buf,sizeof(buf)-1,"%u:%u",
	     connection->u.coap.side1peerPort,
	     connection->u.coap.side2peerPort);
    break;
    
  case spindump_connection_transport_quic:
    snprintf(buf,sizeof(buf)-1,"%s-",spindump_connection_quicconnectionid_tostring(&connection->u.quic.peer1ConnectionID));
    snprintf(buf+strlen(buf),sizeof(buf)-strlen(buf)-1,"%s",spindump_connection_quicconnectionid_tostring(&connection->u.quic.peer2ConnectionID));
    break;
    
  case spindump_connection_transport_icmp:
    snprintf(buf,sizeof(buf)-1,"%u",ntohs(connection->u.icmp.side1peerId));
    break;
    
  case spindump_connection_aggregate_hostpair:
    snprintf(buf,sizeof(buf)-1,"%u sessions",
	     connection->u.aggregatehostpair.connections.nConnections);
    break;
    
  case spindump_connection_aggregate_hostnetwork:
    snprintf(buf,sizeof(buf)-1,"%u sessions",
	     connection->u.aggregatehostnetwork.connections.nConnections);
    break;

  case spindump_connection_aggregate_networknetwork:
    snprintf(buf,sizeof(buf)-1,"%u sessions",
	     connection->u.aggregatenetworknetwork.connections.nConnections);
    break;

  case spindump_connection_aggregate_multicastgroup:
    snprintf(buf,sizeof(buf)-1,"%u sessions",
	     connection->u.aggregatemulticastgroup.connections.nConnections);
    break;
    
  default:
    spindump_errorf("invalid connection type");
    return("");
  }
  
  if (strlen(buf) > maxlen) {
    buf[maxlen-2] = '.';
    buf[maxlen-1] = '.';
    buf[maxlen-0] = 0;
  }
  
  return(buf);
}

unsigned int
spindump_connection_report_brief_sessionsize(unsigned int linelen) {
  if (linelen >= 100)
    return(27);
  else if (linelen >= 80)
    return(18);
  else
    return(12);
}

int
spindump_connection_report_brief_isnotefield(unsigned int linelen) {
  return(linelen >= 100);
}

#define spindump_connection_report_brief_notefieldval_length_val 24

unsigned int
spindump_connection_report_brief_notefieldval_length() {
  return(spindump_connection_report_brief_notefieldval_length_val);
}

unsigned int
spindump_connection_report_brief_fixedsize(unsigned int linelen) {
  return(7+1+spindump_connection_report_brief_sessionsize(linelen)+
	 1+8+1+6+1+10+1+10+1+
	 (spindump_connection_report_brief_isnotefield(linelen) ? spindump_connection_report_brief_notefieldval_length_val+2 : 0));
}

unsigned int
spindump_connection_report_brief_variablesize(unsigned int linelen) {
  return(linelen - spindump_connection_report_brief_fixedsize(linelen));
}

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

static const char*
spindump_connection_report_brief_notefieldval(struct spindump_connection* connection) {

  //
  // Checks
  // 
  
  spindump_assert(connection != 0);

  //
  // Setup a buffer to hold the note
  // 

  spindump_deepdebugf("report_brief_notefieldval point 1");
  static char buf[spindump_connection_report_brief_notefieldval_length_val+1];
  memset(buf,0,sizeof(buf));
  
  //
  // Check connection status
  // 

  if (connection->packetsFromSide2 == 0) {
    if (connection->type == spindump_connection_transport_quic ||
	connection->type == spindump_connection_transport_dns ||
	connection->type == spindump_connection_transport_coap) {
      spindump_deepdebugf("report_brief_notefieldval point 2");
      spindump_connection_addtobuf(buf,sizeof(buf),"no rsp","",1);
    } else {
      spindump_deepdebugf("report_brief_notefieldval point 3");
      spindump_connection_addtobuf(buf,sizeof(buf),"no response","",0);
    }
  }

  //
  // QUIC-specific notes
  // 
  
  if (connection->type == spindump_connection_transport_quic) {
    spindump_deepdebugf("report_brief_notefieldval point 4");
    if (connection->u.quic.version == connection->u.quic.originalVersion) {
      spindump_connection_addtobuf(buf,sizeof(buf),
				   spindump_analyze_quic_parser_versiontostring(connection->u.quic.version),
				   "",
				   1);
    } else {
      char vbuf[40];
      const char* orig = spindump_analyze_quic_parser_versiontostring(connection->u.quic.originalVersion);
      if (strncmp(orig,"v.",2) == 0) orig += 2;
      sprintf(vbuf,"%s(%s)",
	      spindump_analyze_quic_parser_versiontostring(connection->u.quic.version),
	      orig);
      spindump_connection_addtobuf(buf,sizeof(buf),
				   vbuf,
				   "",
				   1);
    }
    if (connection->u.quic.spinFromPeer1to2.totalSpins == 0 &&
	connection->u.quic.spinFromPeer2to1.totalSpins == 0) {
      spindump_deepdebugf("report_brief_notefieldval point 5");
      spindump_connection_addtobuf(buf,sizeof(buf),"no spin","",1);
    } else if (connection->u.quic.spinFromPeer1to2.totalSpins != 0 &&
	       connection->u.quic.spinFromPeer2to1.totalSpins == 0) {
      spindump_deepdebugf("report_brief_notefieldval point 6");
      spindump_connection_addtobuf(buf,sizeof(buf),"no R-spin","",1);
    } else if (connection->u.quic.spinFromPeer1to2.totalSpins == 0 &&
	       connection->u.quic.spinFromPeer2to1.totalSpins != 0) {
      spindump_deepdebugf("report_brief_notefieldval point 7");
      spindump_connection_addtobuf(buf,sizeof(buf),"no I-spin","",1);
    } else {
      spindump_deepdebugf("report_brief_notefieldval point 8");
      spindump_connection_addtobuf(buf,sizeof(buf),"spinning","",1);
    }
  }

  //
  // DNS-specific notes
  // 
  
  if (connection->type == spindump_connection_transport_dns) {
    if (connection->u.dns.lastQueriedName[0] != 0) {
      spindump_deepdebugf("report_brief_notefieldval point 9");
      spindump_connection_addtobuf(buf,sizeof(buf),"Q ",connection->u.dns.lastQueriedName,1);
    }
  }
  
  //
  // COAP-specific notes
  // 
  
  if (connection->type == spindump_connection_transport_coap) {
    if (connection->u.coap.dtls) {
      spindump_deepdebugf("report_brief_notefieldval point 10");
      const char* versionString = spindump_analyze_tls_parser_versiontostring(connection->u.coap.dtlsVersion);
      spindump_connection_addtobuf(buf,sizeof(buf),"DTLS ",versionString,1);
    }
  }
  
  //
  // Done. Return the result.
  // 
  
  spindump_deepdebugf("report_brief_notefieldval point 999");
  return(buf);
}

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

  spindump_deepdebugf("report_brief point 1");
  memset(paksbuf,0,sizeof(paksbuf));
  snprintf(paksbuf,sizeof(paksbuf)-1,"%s",
	   spindump_meganumber_tostring(connection->packetsFromSide1 + connection->packetsFromSide2));
  memset(rttbuf1,0,sizeof(rttbuf1));
  memset(rttbuf2,0,sizeof(rttbuf2));
  spindump_deepdebugf("report_brief point 2");
  if (avg) {
    strcpy(rttbuf1,spindump_rtt_tostring(spindump_rtt_calculateLastMovingAvgRTT(&connection->leftRTT)));
    strcpy(rttbuf2,spindump_rtt_tostring(spindump_rtt_calculateLastMovingAvgRTT(&connection->rightRTT)));
  } else {
    strcpy(rttbuf1,spindump_rtt_tostring(connection->leftRTT.lastRTT));
    strcpy(rttbuf2,spindump_rtt_tostring(connection->rightRTT.lastRTT));
  }
  spindump_deepdebugf("report_brief point 3");
  unsigned int addrsiz = spindump_connection_report_brief_variablesize(linelen);
  unsigned int maxsessionlen = spindump_connection_report_brief_sessionsize(linelen);
  spindump_deepdebugf("report_brief point 4");
  snprintf(buf,bufsiz,"%-7s %-*s %-*s %8s %6s %10s %10s",
	   spindump_connection_type_to_string(connection->type),
	   addrsiz,
	   spindump_connection_addresses(connection,addrsiz,anonymizeLeft,anonymizeRight,querier),
	   maxsessionlen,
	   spindump_connection_sessionstring(connection,maxsessionlen),
	   spindump_connection_statestring(connection),
	   paksbuf,
	   rttbuf1,
	   rttbuf2);
  spindump_deepdebugf("report_brief point 5");
  if (spindump_connection_report_brief_isnotefield(linelen)) {
    spindump_deepdebugf("report_brief point 5b");
    snprintf(buf + strlen(buf),bufsiz - strlen(buf),"  %-*s",
	     spindump_connection_report_brief_notefieldval_length_val,
	     spindump_connection_report_brief_notefieldval(connection));
  }
  spindump_deepdebugf("report_brief point 6");
}
