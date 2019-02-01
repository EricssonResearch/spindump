
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
#include "spindump_analyze.h"
#include "spindump_spin.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static int
spindump_connections_setisclosed(struct spindump_connection_set* set);
static int
spindump_connections_setisestablishing(struct spindump_connection_set* set);

//
// Actual code --------------------------------------------------------------------------------
//

//
// Calculate when was the last action on a given connection. This is
// useful when determining whether an idle connection should be
// deleted, etc.
//

unsigned long long
spindump_connections_lastaction(struct spindump_connection* connection,
				const struct timeval* now) {
  spindump_assert(now->tv_sec > 0);
  spindump_assert(now->tv_usec < 1000 * 1000);
  unsigned long long diff;
  if (spindump_iszerotime(&connection->latestPacketFromSide1)) {
    return(0);
  } else if (spindump_iszerotime(&connection->latestPacketFromSide2)) {
    spindump_assert(!spindump_iszerotime(&connection->latestPacketFromSide1));
#if 0
    spindump_deepdebugf("spindump_connections_lastaction now %lu:%lu, latestside1 %lu:%lu",
			now->tv_sec,
			now->tv_usec,
			connection->latestPacketFromSide1.tv_sec,
			connection->latestPacketFromSide1.tv_usec);
#endif
    diff = spindump_timediffinusecs(now,&connection->latestPacketFromSide1);
    return(diff);
  } else {
    unsigned long long diff1 = spindump_timediffinusecs(now,&connection->latestPacketFromSide1);
    unsigned long long diff2 = spindump_timediffinusecs(now,&connection->latestPacketFromSide2);
    diff = diff1 > diff2 ? diff2 : diff1;
    return(diff);
  }
}

//
// Mark a connection for later deletion (e.g., based on being closed
// in the protocol). It is not immediately dweleted, because there may
// be still packets in flight related to the connection.
//

void
spindump_connections_markconnectiondeleted(struct spindump_connection* connection) {
  //
  // Do some checks & print debugs
  //

  spindump_assert(connection != 0);
  spindump_debugf("marking connection %u deleted", connection->id);

  //
  // Set the mark
  //

  connection->deleted = 1;
}

//
// Determine the addresses associated with the connection. The outputs
// are in the two output parameters. There is no address associated
// with all connections, or not both addresses. In those cases the
// output is set to a null pointer.
//

void
spindump_connections_getaddresses(struct spindump_connection* connection,
				  spindump_address** p_side1address,
				  spindump_address** p_side2address) {

  spindump_assert(connection != 0);
  spindump_assert(p_side1address != 0);
  spindump_assert(p_side2address != 0);

  switch (connection->type) {
  case spindump_connection_transport_tcp:
    *p_side1address = &connection->u.tcp.side1peerAddress;
    *p_side2address = &connection->u.tcp.side2peerAddress;
    break;
  case spindump_connection_transport_udp:
    *p_side1address = &connection->u.udp.side1peerAddress;
    *p_side2address = &connection->u.udp.side2peerAddress;
    break;
  case spindump_connection_transport_dns:
    *p_side1address = &connection->u.dns.side1peerAddress;
    *p_side2address = &connection->u.dns.side2peerAddress;
    break;
  case spindump_connection_transport_coap:
    *p_side1address = &connection->u.coap.side1peerAddress;
    *p_side2address = &connection->u.coap.side2peerAddress;
    break;
  case spindump_connection_transport_quic:
    *p_side1address = &connection->u.quic.side1peerAddress;
    *p_side2address = &connection->u.quic.side2peerAddress;
    break;
  case spindump_connection_transport_icmp:
    *p_side1address = &connection->u.icmp.side1peerAddress;
    *p_side2address = &connection->u.icmp.side2peerAddress;
    break;
  case spindump_connection_aggregate_hostpair:
    *p_side1address = &connection->u.aggregatehostpair.side1peerAddress;
    *p_side2address = &connection->u.aggregatehostpair.side2peerAddress;
    break;
  case spindump_connection_aggregate_hostnetwork:
    *p_side1address = &connection->u.aggregatehostnetwork.side1peerAddress;
    *p_side2address = 0;
    break;
  case spindump_connection_aggregate_networknetwork:
    *p_side1address = 0;
    *p_side2address = 0;
    break;
  case spindump_connection_aggregate_multicastgroup:
    *p_side1address = 0;
    *p_side2address = &connection->u.aggregatemulticastgroup.group;
    break;
  default:
    spindump_errorf("invalid connection type %u in spindump_connections_getaddresses",
		    connection->type);
    *p_side1address = 0;
    *p_side2address = 0;
    break;
  }
}

//
// Determine the ports associated with the connection. The outputs
// are in the two output parameters. There are no ports associated
// with all connections, of course. In those cases the
// output is set to a null pointer.
//

void
spindump_connections_getports(struct spindump_connection* connection,
			      spindump_port* p_side1port,
			      spindump_port* p_side2port) {

  spindump_assert(connection != 0);
  spindump_assert(p_side1port != 0);
  spindump_assert(p_side2port != 0);

  switch (connection->type) {
  case spindump_connection_transport_tcp:
    *p_side1port = connection->u.tcp.side1peerPort;
    *p_side2port = connection->u.tcp.side2peerPort;
    break;
  case spindump_connection_transport_udp:
    *p_side1port = connection->u.udp.side1peerPort;
    *p_side2port = connection->u.udp.side2peerPort;
    break;
  case spindump_connection_transport_dns:
    *p_side1port = connection->u.dns.side1peerPort;
    *p_side2port = connection->u.dns.side2peerPort;
    break;
  case spindump_connection_transport_coap:
    *p_side1port = connection->u.coap.side1peerPort;
    *p_side2port = connection->u.coap.side2peerPort;
    break;
  case spindump_connection_transport_quic:
    *p_side1port = connection->u.quic.side1peerPort;
    *p_side2port = connection->u.quic.side2peerPort;
    break;
  case spindump_connection_transport_icmp:
    *p_side1port = 0;
    *p_side2port = 0;
    break;
  case spindump_connection_aggregate_hostpair:
    *p_side1port = 0;
    *p_side2port = 0;
    break;
  case spindump_connection_aggregate_hostnetwork:
    *p_side1port = 0;
    *p_side2port = 0;
    break;
  case spindump_connection_aggregate_networknetwork:
    *p_side1port = 0;
    *p_side2port = 0;
    break;
  case spindump_connection_aggregate_multicastgroup:
    *p_side1port = 0;
    *p_side2port = 0;
    break;
  default:
    spindump_errorf("invalid connection type %u in spindump_connections_getports",
		    connection->type);
    *p_side1port = 0;
    *p_side2port = 0;
    break;
  }
}

//
// Report a new RTT measurement. This could have been determined in
// many ways, by way of the initial packet exchange, looking at QUIC
// spin bit or TCP sequence numbers.
//
// In any case, the new measurement is recorded, proper averages etc
// are counted, and also any handlers associated with this connection
// are called.
//
// In the end, the same updates are propagated to any aggregate
// connection this connection may belong to.
//

unsigned long
spindump_connections_newrttmeasurement(struct spindump_analyze* state,
				       struct spindump_packet* packet,
				       struct spindump_connection* connection,
				       const int right,
				       const int unidirectional,
				       const struct timeval* sent,
				       const struct timeval* rcvd,
				       const char* why) {

  //
  // Sanity checks
  //
  
  spindump_assert(state != 0);
  spindump_assert(packet != 0);
  spindump_assert(connection != 0);
  spindump_assert(spindump_isbool(right));
  spindump_assert(spindump_isbool(unidirectional));
  spindump_assert(sent != 0);
  spindump_assert(rcvd != 0);
  spindump_assert(why != 0);
  
  //
  // Calculate the RTT
  //

  spindump_deepdebugf("spindump_connections_newrttmeasurement due to %s", why);
  spindump_deepdebugf("matching packet sent at %u:%u, response received %u:%u",
		      sent->tv_sec, sent->tv_usec,
		      rcvd->tv_sec, rcvd->tv_usec);
  unsigned long long diff = spindump_timediffinusecs(rcvd,sent);
  unsigned long ret;

  //
  // Store in connection in suitable form
  //
  
  if (unidirectional) {
    if (right) {
      ret = spindump_rtt_newmeasurement(&connection->respToInitFullRTT,diff);
      spindump_debugf("due to %s new calculated full RTT from responder = %lu us for connection %u",
		      why, connection->respToInitFullRTT.lastRTT, connection->id);
    } else {
      ret = spindump_rtt_newmeasurement(&connection->initToRespFullRTT,diff);
      spindump_debugf("due to %s new calculated full RTT from initiator = %lu us for connection %u",
		      why, connection->initToRespFullRTT.lastRTT, connection->id);
    }
  } else {
    if (right) {
      ret = spindump_rtt_newmeasurement(&connection->rightRTT,diff);
      spindump_debugf("due to %s new calculated right RTT = %lu us for connection %u",
		      why, connection->rightRTT.lastRTT, connection->id);
    } else {
      ret = spindump_rtt_newmeasurement(&connection->leftRTT,diff);
      spindump_debugf("due to %s new calculated left RTT = %lu us for connection %u",
		      why, connection->leftRTT.lastRTT, connection->id);
    }
  }
  
  //
  // Call some handlers, if any, for the new measurements
  //
  
  if (unidirectional) {
    spindump_analyze_process_handlers(state,
				      right ? spindump_analyze_event_newrespinitfullrttmeasurement :
				      spindump_analyze_event_newinitrespfullrttmeasurement,
				      packet,
				      connection);
  } else {
    spindump_analyze_process_handlers(state,
				      right ? spindump_analyze_event_newrightrttmeasurement :
				      spindump_analyze_event_newleftrttmeasurement,
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
    spindump_connections_newrttmeasurement(state,packet,aggregate,right,unidirectional,sent,rcvd,why);

  }

  //
  // Done. Return.
  //

  return(ret);
}

//
// Is a given set of connections all closed?
//

static int
spindump_connections_setisclosed(struct spindump_connection_set* set) {
  unsigned int i;

  for (i = 0; i < set->nConnections; i++) {
    struct spindump_connection* other = set->set[i];
    if (other != 0) {
      if (!spindump_connections_isclosed(other)) {
				return(0);
      }
    }
  }
  return(1);
}

//
// Is a given connection closed?
//

int
spindump_connections_isclosed(struct spindump_connection* connection) {

  //
  // Sanity checks
  //

  spindump_assert(connection != 0);

  //
  // Just look at the state. Note that static/manually created
  // aggregates cannot be closed, so for them we need to check if all
  // connections within the aggregate are closed.
  //

  if (spindump_connections_isaggregate(connection))
    return(spindump_connections_setisclosed(spindump_connections_aggregateset(connection)));
  else
    return(connection->state == spindump_connection_state_closed);
}

//
// Is a given set of connections all in the establishing state?
//

static int
spindump_connections_setisestablishing(struct spindump_connection_set* set) {
  unsigned int i;

  for (i = 0; i < set->nConnections; i++) {
    struct spindump_connection* other = set->set[i];
    if (other != 0) {
      if (!spindump_connections_isestablishing(other)) {
	return(0);
      }
    }
  }
  return(1);
}

//
// Is a given connection in the establishing state?
//

int
spindump_connections_isestablishing(struct spindump_connection* connection) {

  //
  // Sanity checks
  //

  spindump_assert(connection != 0);

  //
  // Just look at the state Note that static/manually created
  // aggregates cannot be establishing, so for them we need to check if all
  // connections within the aggregate are establishing.
  //

  if (spindump_connections_isaggregate(connection))
    return(spindump_connections_setisestablishing(spindump_connections_aggregateset(connection)));
  else
    return(connection->state == spindump_connection_state_establishing);
}

//
// Is a given connection an aggregate connection? E.g., a TCP flow on
// 5-tuple is not, but a host pair is an aggregate connection.
//

int
spindump_connections_isaggregate(struct spindump_connection* connection) {
  spindump_assert(connection != 0);
  switch (connection->type) {
  case spindump_connection_aggregate_hostpair: return(1);
  case spindump_connection_aggregate_hostnetwork: return(1);
  case spindump_connection_aggregate_networknetwork: return(1);
  case spindump_connection_aggregate_multicastgroup: return(1);
  default: return(0);
  }
}

//
// Return the set of connections that this aggregate connection
// consists of.
//
// Note: This function is not thread safe.
//

struct spindump_connection_set*
spindump_connections_aggregateset(struct spindump_connection* connection) {

  //
  // Sanity checks
  //

  spindump_assert(connection != 0);

  //
  // In some cases we need to return an empty set. For that we have a
  // static variable that we can return.
  //

  static struct spindump_connection_set empty;
  static int emptyInitialized = 0;
  if (!emptyInitialized) {
    spindump_connections_set_initialize(&empty);
    emptyInitialized = 1;
  }

  //
  // Based on type, return the relevant set.
  //

  switch (connection->type) {
  case spindump_connection_aggregate_hostpair:
    return(&connection->u.aggregatehostpair.connections);
  case spindump_connection_aggregate_hostnetwork:
    return(&connection->u.aggregatehostnetwork.connections);
  case spindump_connection_aggregate_networknetwork:
    return(&connection->u.aggregatenetworknetwork.connections);
  case spindump_connection_aggregate_multicastgroup:
    return(&connection->u.aggregatemulticastgroup.connections);
  default:
    return(&empty);
  }
}

//
// Determine if a given new connection matches an aggregate
// connection. If so, this connection can be marked as "belonging" to
// the aggregate.
//

int
spindump_connections_matches_aggregate_connection(struct spindump_connection* connection,
						  struct spindump_connection* aggregate) {

  spindump_address* side1address = 0;
  spindump_address* side2address = 0;
  spindump_connections_getaddresses(connection,
				    &side1address,
				    &side2address);
  if (side1address == 0 || side2address == 0) {
    spindump_deepdebugf("  can't figure out addresses from connection %u", connection->id);
    return(0);
  }

  switch (aggregate->type) {

  case spindump_connection_aggregate_hostpair:
    spindump_deepdebugf("comparing addresses");
    spindump_deepdebugf("  side1address %s",spindump_address_tostring(side1address));
    spindump_deepdebugf("  side2address %s",spindump_address_tostring(side2address));
    spindump_deepdebugf("  hostpair side1 address %s",
			spindump_address_tostring(&aggregate->u.aggregatehostpair.side1peerAddress));
    spindump_deepdebugf("  hostpair side2 address %s",
			spindump_address_tostring(&aggregate->u.aggregatehostpair.side2peerAddress));
    return((spindump_address_equal(side1address,&aggregate->u.aggregatehostpair.side1peerAddress) &&
	    spindump_address_equal(side2address,&aggregate->u.aggregatehostpair.side2peerAddress)) ||
	   (spindump_address_equal(side1address,&aggregate->u.aggregatehostpair.side2peerAddress) &&
	    spindump_address_equal(side2address,&aggregate->u.aggregatehostpair.side1peerAddress)));

  case spindump_connection_aggregate_hostnetwork:
    return((spindump_address_equal(side1address,&aggregate->u.aggregatehostnetwork.side1peerAddress) &&
	    spindump_address_innetwork(side2address,&aggregate->u.aggregatehostnetwork.side2Network)) ||
	   (spindump_address_innetwork(side1address,&aggregate->u.aggregatehostnetwork.side2Network) &&
	    spindump_address_equal(side2address,&aggregate->u.aggregatehostnetwork.side1peerAddress)));

  case spindump_connection_aggregate_networknetwork:
    return((spindump_address_innetwork(side1address,&aggregate->u.aggregatenetworknetwork.side1Network) &&
	    spindump_address_innetwork(side2address,&aggregate->u.aggregatenetworknetwork.side2Network)) ||
	   (spindump_address_innetwork(side1address,&aggregate->u.aggregatenetworknetwork.side2Network) &&
	    spindump_address_innetwork(side2address,&aggregate->u.aggregatenetworknetwork.side1Network)));

  case spindump_connection_aggregate_multicastgroup:
    return(spindump_address_equal(side1address,&aggregate->u.aggregatemulticastgroup.group) ||
	   spindump_address_equal(side2address,&aggregate->u.aggregatemulticastgroup.group));

  default:
    spindump_errorf("invalid connection type %u in spindump_connections_matches_aggregate_connection",
		    aggregate->type);
    return(0);

  }
}

//
// Do the addresses match an aggregate?
//

int
spindump_connections_matches_aggregate_srcdst(spindump_address* source,
					      spindump_address* destination,
					      struct spindump_connection* aggregate) {
  spindump_assert(aggregate != 0);
  spindump_assert(spindump_connections_isaggregate(aggregate));

  switch (aggregate->type) {

  case spindump_connection_aggregate_hostpair:
    return((spindump_address_equal(source,&aggregate->u.aggregatehostpair.side1peerAddress) &&
	    spindump_address_equal(destination,&aggregate->u.aggregatehostpair.side2peerAddress)) ||
	   (spindump_address_equal(destination,&aggregate->u.aggregatehostpair.side1peerAddress) &&
	    spindump_address_equal(source,&aggregate->u.aggregatehostpair.side2peerAddress)));

  case spindump_connection_aggregate_hostnetwork:
    return((spindump_address_equal(source,&aggregate->u.aggregatehostnetwork.side1peerAddress) &&
	    spindump_address_innetwork(destination,&aggregate->u.aggregatehostnetwork.side2Network)) ||
	   (spindump_address_equal(destination,&aggregate->u.aggregatehostnetwork.side1peerAddress) &&
	    spindump_address_innetwork(source,&aggregate->u.aggregatehostnetwork.side2Network)));

  case spindump_connection_aggregate_networknetwork:
    return((spindump_address_innetwork(source,&aggregate->u.aggregatenetworknetwork.side1Network) &&
	    spindump_address_innetwork(destination,&aggregate->u.aggregatenetworknetwork.side2Network)) ||
	   (spindump_address_innetwork(destination,&aggregate->u.aggregatenetworknetwork.side1Network) &&
	    spindump_address_innetwork(source,&aggregate->u.aggregatenetworknetwork.side2Network)));

  case spindump_connection_aggregate_multicastgroup:
    return(spindump_address_equal(source,&aggregate->u.aggregatemulticastgroup.group) ||
	   spindump_address_equal(destination,&aggregate->u.aggregatemulticastgroup.group));

  default:
    spindump_errorf("invalid connection type %u in spindump_connections_matches_aggregate_srcdst", aggregate->type);
    return(0);

  }
}

//
// Report a changed state for a connection. This may involve calling
// handlers associated with state change events.
//

void
spindump_connections_changestate(struct spindump_analyze* state,
				 struct spindump_packet* packet,
				 struct spindump_connection* connection,
				 enum spindump_connection_state newState) {

  //
  // Sanity checks
  //

  spindump_assert(connection != 0);

  //
  // Set the new state
  //

  connection->state = newState;

  //
  // Let all interested handlers know about this change
  //

  spindump_analyze_process_handlers(state,
				    spindump_analyze_event_statechange,
				    packet,
				    connection);
}
