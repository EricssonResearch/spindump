
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

#include <ctype.h>
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
spindump_analyze_processevent_new_connection(struct spindump_analyze* state,
                                             const struct spindump_event* event,
                                             struct spindump_connection** p_connection);
static void
spindump_analyze_processevent_change_connection(struct spindump_analyze* state,
                                                const struct spindump_event* event,
                                                struct spindump_connection** p_connection);
static void
spindump_analyze_processevent_connection_delete(struct spindump_analyze* state,
                                                const struct spindump_event* event,
                                                struct spindump_connection** p_connection);
static void
spindump_analyze_processevent_new_rtt_measurement(struct spindump_analyze* state,
                                                  const struct spindump_event* event,
                                                  struct spindump_connection** p_connection);
static void
spindump_analyze_processevent_spin_flip(struct spindump_analyze* state,
                                        const struct spindump_event* event,
                                        struct spindump_connection** p_connection);
static void
spindump_analyze_processevent_spin_value(struct spindump_analyze* state,
                                         const struct spindump_event* event,
                                         struct spindump_connection** p_connection);
static void
spindump_analyze_processevent_ecn_congestion_event(struct spindump_analyze* state,
                                                   const struct spindump_event* event,
                                                   struct spindump_connection** p_connection);
static void
spindump_analyze_processevent_rtloss_measurement(struct spindump_analyze* state,
                                                 const struct spindump_event* event,
                                                 struct spindump_connection** p_connection);
static void
spindump_analyze_processevent_qrloss_measurement(struct spindump_analyze* state,
                                                 const struct spindump_event* event,
                                                 struct spindump_connection** p_connection);
static int
spindump_analyze_event_parseicmpsessionid(const struct spindump_event* event,
                                          uint16_t* p_peerId);
static int
spindump_analyze_event_parsehostpair(const struct spindump_event* event);
static int
spindump_analyze_event_parseside1host(const struct spindump_event* event);
static int
spindump_analyze_event_parseportpair(const struct spindump_event* event,
                                     spindump_port* p_side1port,
                                     spindump_port* p_side2port);
static int
spindump_analyze_event_parsecidpair(const struct spindump_event* event,
                                    struct spindump_quic_connectionid* p_side1cid,
                                    struct spindump_quic_connectionid* p_side2cid,
                                    spindump_port* side1port,
                                    spindump_port* side2port);
static struct spindump_connection*
spindump_analyze_processevent_find_connection(struct spindump_analyze* state,
                                              const struct spindump_event* event);
static void
spindump_analyze_event_updateinfo(struct spindump_analyze* state,
                                  struct spindump_connection* connection,
                                  const struct spindump_event* event);
static void
spindump_analyze_event_updateinfo_aggregate(struct spindump_analyze* state,
                                            struct spindump_connection* connection,
                                            spindump_counter_64bit fromSide1Diff,
                                            spindump_counter_64bit fromSide2Diff,
                                            spindump_counter_64bit bytesFromSide1Diff,
                                            spindump_counter_64bit bytesFromSide2Diff,
                                            struct timeval* when);
static int
spindump_analyze_event_charbytetobyte(char ch1,
                                      char ch2,
                                      uint8_t* byte);
static int
spindump_analyze_event_string_to_quicconnectionid(const char* buf,
                                                  unsigned int nchars,
                                                  struct spindump_quic_connectionid* id);

//
// Actual code --------------------------------------------------------------------------------
//

//
// Process an event from another instance of Spindump somewhere
// else. This may lead to the creation of new connection objects,
// updating statistics, etc.
//
// The parameter state is the analyzer data structure, event is the
// incoming event, and p_connection is an output parameter, in the end
// pointing to either 0 if no affected connection could be identified,
// or a pointer to the connection object from the connection table of
// the analyzer.
//

void
spindump_analyze_processevent(struct spindump_analyze* state,
                              const struct spindump_event* event,
                              struct spindump_connection** p_connection) {
  //
  // Sanity checks and debugs
  //
  
  spindump_assert(state != 0);
  spindump_assert(event != 0);
  spindump_assert(p_connection != 0);
  spindump_deepdeepdebugf("spindump_analyze_processevent type %u", event->eventType);
  
  *p_connection = 0;
  switch (event->eventType) {
  case spindump_event_type_new_connection:
    spindump_analyze_processevent_new_connection(state,event,p_connection);
    break;
  case spindump_event_type_change_connection:
    spindump_analyze_processevent_change_connection(state,event,p_connection);
    break;
  case spindump_event_type_connection_delete:
    spindump_analyze_processevent_connection_delete(state,event,p_connection);
    break;
  case spindump_event_type_new_rtt_measurement:
    spindump_analyze_processevent_new_rtt_measurement(state,event,p_connection);
    break;
  case spindump_event_type_spin_flip:
    spindump_analyze_processevent_spin_flip(state,event,p_connection);
    break;
  case spindump_event_type_spin_value:
    spindump_analyze_processevent_spin_value(state,event,p_connection);
    break;
  case spindump_event_type_ecn_congestion_event:
    spindump_analyze_processevent_ecn_congestion_event(state,event,p_connection);
    break;
  case spindump_event_type_qrloss_measurement:
    spindump_analyze_processevent_qrloss_measurement(state,event,p_connection);
    break;
  case spindump_event_type_rtloss_measurement:
    spindump_analyze_processevent_rtloss_measurement(state, event, p_connection);
    break;
  default:
    spindump_errorf("invalid event type %u", event->eventType);
    return;
  }
}

//
// Parse the session id of an event representing an ICMP connection.
//

static int
spindump_analyze_event_parseicmpsessionid(const struct spindump_event* event,
                                          uint16_t* p_peerId) {
  unsigned long x;
  if (sscanf(event->session,"%lu",&x) < 1) {
    spindump_errorf("cannot parse ICMP session identifier");
    return(0);
  }
  if (x > 65535) {
    spindump_errorf("ICMP session identifier must be 16 bits");
    return(0);
  }
  *p_peerId = (uint16_t)x;
  return(1);
}

//
// Check that the given event addresses/networks are indeed hosts not
// networks
//

static int
spindump_analyze_event_parsehostpair(const struct spindump_event* event) {
  int hostPair = (spindump_network_ishost(&event->initiatorAddress) &&
                  spindump_network_ishost(&event->responderAddress));
  if (!hostPair) {
    spindump_errorf("a non-aggregate connection must be between hosts");
    return(0);
  }
  return(1);
}

//
// Check that the given event side1 address/network is indeed a host
// not a network
//

static int
spindump_analyze_event_parseside1host(const struct spindump_event* event) {
  int host = spindump_network_ishost(&event->initiatorAddress);
  if (!host) {
    spindump_errorf("initiator in this aggregate connection must be a host address");
    return(0);
  }
  return(1);
}

//
// Parse the session id of an event representing an TCP/UDP/etc
// connection that has two ports.
//

static int
spindump_analyze_event_parseportpair(const struct spindump_event* event,
                                     spindump_port* p_side1port,
                                     spindump_port* p_side2port) {
  unsigned long x,y;
  if (sscanf(event->session,"%lu:%lu",&x,&y) < 2) {
    spindump_errorf("cannot parse event port pair session identifier");
    return(0);
  }
  if (x > 65535 || y > 65535) {
    spindump_errorf("port values cannot be more than 16 bits");
    return(0);
  }
  *p_side1port = (uint16_t)x;
  *p_side2port = (uint16_t)y;
  return(1);
}

//
// Convert a two char textual hex byte to an actual byte
// (uint8_t). Returns 1 upon success, 0 upon failure.
//

static int
spindump_analyze_event_charbytetobyte(char ch1,
                                      char ch2,
                                      uint8_t* byte) {
  char buf[3];
  buf[0] = ch1;
  buf[1] = ch2;
  buf[2] = 0;
  unsigned int x;
  if (sscanf(buf,"%x",&x) < 1) {
    spindump_errorf("Invalid char in a QUIC connection id");
    return(0);
  }
  *byte = (uint8_t)x;
  return(1);
}

//
// Convert a string to a QUIC connection ID. Returns 1 upon success, 0
// upon failure.
//

static int
spindump_analyze_event_string_to_quicconnectionid(const char* buf,
                                                  unsigned int nchars,
                                                  struct spindump_quic_connectionid* id) {
  if ((nchars) % 2 != 0) {
    spindump_errorf("QUIC connection id string cannot have odd length");
    return(0);
  }
  if ((nchars / 2) > spindump_connection_quic_cid_maxlen) {
    spindump_errorf("QUIC connection id string cannot be longer than %u bytes",
                    spindump_connection_quic_cid_maxlen);
    return(0);
  }
  memset(id,0,sizeof(*id));
  id->len = 0;
  while (nchars >= 2) {
    uint8_t byte;
    if (!spindump_analyze_event_charbytetobyte(buf[0],
                                               buf[1],
                                               &byte)) {
      return(0);
    }
    nchars -= 2;
    buf += 2;
    id->id[id->len++] = byte;
  }
  spindump_deepdeepdebugf("successfully parsed quicconnectionid %s",
                          spindump_connection_quicconnectionid_tostring(id));
  return(1);
}

//
// Parse the session id of an event representing an TCP/UDP/etc
// connection that has two ports.
//

static int
spindump_analyze_event_parsecidpair(const struct spindump_event* event,
                                    struct spindump_quic_connectionid* p_side1cid,
                                    struct spindump_quic_connectionid* p_side2cid,
                                    spindump_port* side1port,
                                    spindump_port* side2port) {

  //
  // Sanity checks
  //
  
  spindump_assert(event != 0);
  spindump_assert(p_side1cid != 0);
  spindump_assert(p_side2cid != 0);
  spindump_deepdeepdebugf("spindump_analyze_event_parsecidpair(%s)", event->session);
  
  //
  // Find out where the separator (hyphen) is in a "nnnnn-mmmmm" CID
  // pair.
  //
  
  const char* separator = index(event->session,'-');
  if (separator == 0) {
    spindump_errorf("QUIC connection id pair %s does not have a separator",
                    event->session);
    return(0);
  }
  
  //
  // Find out where the separator (space and an opening paranthesis)
  // is after the "nnnnn-mmmmm" CID pair, as " (port:port)" follows.
  //
  
  const char* spaceseparator = index(separator,' ');
  if (spaceseparator == 0 ||
      spaceseparator[1] != '(') {
    spindump_errorf("QUIC connection id pair %s is not followed by a port pair",
                    event->session);
    return(0);
  }

  //
  // Find out where the separator (colon) is between the port pair.
  //
  
  const char* colonseparator = index(spaceseparator,':');
  if (colonseparator == 0) {
    spindump_errorf("QUIC connection id pair %s is not followed by a port pair with a colon",
                    event->session);
    return(0);
  }
  
  //
  // Find out where the separator (colon) is between the port pair.
  //
  
  const char* closingseparator = index(colonseparator,')');
  if (closingseparator == 0) {
    spindump_errorf("QUIC connection id pair %s is not followed by a port pair that ends with a closing paranthesis",
                    event->session);
    return(0);
  }
  
  //
  // Parse first CID in a nnnnn-mmmmm CID pair
  //
  
  if (!spindump_analyze_event_string_to_quicconnectionid(event->session,
                                                         (unsigned int)(separator - event->session),
                                                         p_side1cid)) {
    return(0);
  }

  //
  // Parse second CID in a nnnnn-mmmmm CID pair
  //
  
  if (!spindump_analyze_event_string_to_quicconnectionid(separator + 1,
                                                         (unsigned int)(spaceseparator - (separator + 1)),
                                                         p_side2cid)) {
    return(0);
  }

  //
  // Parse the first port
  //

  const char* port1begin = spaceseparator+2;
  if (!isdigit(*port1begin)) {
    spindump_errorf("QUIC connection id pair %s is not followed by a parseable port number",
                    event->session);
    return(0);
  }
  *side1port = (spindump_port)atoi(port1begin);
  spindump_deepdeepdebugf("successfully parsed port %u", *side1port);
  
  //
  // Parse the second port
  //
  
  const char* port2begin = colonseparator+1;
  if (!isdigit(*port2begin)) {
    spindump_errorf("QUIC connection id pair %s is not followed by a second parseable port number",
                    event->session);
    return(0);
  }
  *side2port = (spindump_port)atoi(port2begin);
  spindump_deepdeepdebugf("successfully parsed port %u", *side2port);
  
  //
  // Ok
  //
  
  return(1);
}

//
// Process an event of type "new connection" from another instance of
// Spindump somewhere else. Update statistics and make any other
// necessary changes in the local database of connections.
//
// The parameter state is the analyzer data structure, event is the
// incoming event, and p_connection is an output parameter, in the end
// pointing to either 0 if no affected connection could be identified,
// or a pointer to the connection object from the connection table of
// the analyzer.
//

static void
spindump_analyze_processevent_new_connection(struct spindump_analyze* state,
                                             const struct spindump_event* event,
                                             struct spindump_connection** p_connection) {
  struct timeval when;
  spindump_deepdeepdebugf("spindump_analyze_processevent_new_connection");
  spindump_timestamp_to_timeval(event->timestamp,&when);
  spindump_port side1port;
  spindump_port side2port;
  struct spindump_quic_connectionid side1cid;
  struct spindump_quic_connectionid side2cid;
  uint16_t peerid;

  spindump_deepdeepdebugf("spindump_analyze_processevent_new_connection");
  
  switch (event->connectionType) {
    
  case spindump_connection_transport_tcp:
    if (!spindump_analyze_event_parsehostpair(event)) return;
    if (!spindump_analyze_event_parseportpair(event,&side1port,&side2port)) return;
    *p_connection =
      spindump_connections_newconnection_tcp(&event->initiatorAddress.address,
                                             &event->responderAddress.address,
                                             side1port,
                                             side2port,
                                             &when,
                                             state->table);
    break;
    
  case spindump_connection_transport_udp:
    if (!spindump_analyze_event_parsehostpair(event)) return;
    if (!spindump_analyze_event_parseportpair(event,&side1port,&side2port)) return;
    *p_connection =
      spindump_connections_newconnection_udp(&event->initiatorAddress.address,
                                             &event->responderAddress.address,
                                             side1port,
                                             side2port,
                                             &when,
                                             state->table);
    break;
    
  case spindump_connection_transport_dns:
    if (!spindump_analyze_event_parsehostpair(event)) return;
    if (!spindump_analyze_event_parseportpair(event,&side1port,&side2port)) return;
    *p_connection =
      spindump_connections_newconnection_dns(&event->initiatorAddress.address,
                                             &event->responderAddress.address,
                                             side1port,
                                             side2port,
                                             &when,
                                             state->table);
    break;
    
  case spindump_connection_transport_coap:
    if (!spindump_analyze_event_parsehostpair(event)) return;
    if (!spindump_analyze_event_parseportpair(event,&side1port,&side2port)) return;
    *p_connection =
      spindump_connections_newconnection_dns(&event->initiatorAddress.address,
                                             &event->responderAddress.address,
                                             side1port,
                                             side2port,
                                             &when,
                                             state->table);
    break;
    
  case spindump_connection_transport_quic:
    if (!spindump_analyze_event_parsehostpair(event)) return;
    if (!spindump_analyze_event_parsecidpair(event,&side1cid,&side2cid,&side1port,&side2port)) return;
    *p_connection =
      spindump_connections_newconnection_quic_5tupleandcids(&event->initiatorAddress.address,
                                                            &event->responderAddress.address,
                                                            side1port,
                                                            side2port,
                                                            &side2cid,
                                                            &side1cid, // ... check that these are in right order! TBD
                                                            &when,
                                                            state->table);
    break;
    
  case spindump_connection_transport_icmp:
    if (!spindump_analyze_event_parsehostpair(event)) return;
    if (!spindump_analyze_event_parseicmpsessionid(event,&peerid)) return;
    *p_connection =
      spindump_connections_newconnection_icmp(&event->initiatorAddress.address,
                                              &event->responderAddress.address,
                                              ICMP_ECHOREPLY,
                                              peerid,
                                              &when,
                                              state->table);
    break;
    
  case spindump_connection_aggregate_hostpair:
    if (!spindump_analyze_event_parsehostpair(event)) return;
    *p_connection =
      spindump_connections_newconnection_aggregate_hostpair(&event->initiatorAddress.address,
                                                            &event->responderAddress.address,
                                                            &when,
                                                            0,
                                                            state->table);
    break;
    
  case spindump_connection_aggregate_hostnetwork:
    if (!spindump_analyze_event_parseside1host(event)) return;
    *p_connection =
      spindump_connections_newconnection_aggregate_hostnetwork(&event->initiatorAddress.address,
                                                               &event->responderAddress,
                                                               &when,
                                                               0,
                                                               state->table);
    break;
    
  case spindump_connection_aggregate_networknetwork:
    *p_connection =
      spindump_connections_newconnection_aggregate_networknetwork(&event->initiatorAddress,
                                                                  &event->responderAddress,
                                                                  &when,
                                                                  0,
                                                                  state->table);
    break;
    
  case spindump_connection_aggregate_multicastgroup:
    if (!spindump_analyze_event_parseside1host(event)) return;
    *p_connection =
      spindump_connections_newconnection_aggregate_multicastgroup(&event->initiatorAddress.address,
                                                                  &when,
                                                                  0,
                                                                  state->table);
    break;
    
  default:
    spindump_errorf("invalid connection type %u", event->connectionType);
    return;
  }

  //
  // Did we get to create a connection in the end? If yes, update
  // other information (statistics, state) from the event to the
  // connection object.
  //

  spindump_deepdeepdebugf("spindump_analyze_processevent_new_connection update");
  
  if (*p_connection != 0) {
    (*p_connection)->remote = 1;
    spindump_analyze_event_updateinfo(state,*p_connection,event);
  }
  
  spindump_deepdeepdebugf("spindump_analyze_processevent_new_connection done");
}

//
// Process an event of type "change connection" from another instance
// of Spindump somewhere else. Update statistics and make any other
// necessary changes in the local database of connections.
//
// The parameter state is the analyzer data structure, event is the
// incoming event, and p_connection is an output parameter, in the end
// pointing to either 0 if no affected connection could be identified,
// or a pointer to the connection object from the connection table of
// the analyzer.
//

static void
spindump_analyze_processevent_change_connection(struct spindump_analyze* state,
                                                const struct spindump_event* event,
                                                struct spindump_connection** p_connection) {
  // ... TBD

  *p_connection = spindump_analyze_processevent_find_connection(state,event);
  if (*p_connection == 0) return;
  
  //
  // Did we find a connection in the end? If yes, update other
  // information (statistics, state) from the event to the connection
  // object.
  //

  spindump_analyze_event_updateinfo(state,*p_connection,event);
}

//
// Process an event of type "connection delete" from another instance
// of Spindump somewhere else. Update statistics and make any other
// necessary changes in the local database of connections.
//
// The parameter state is the analyzer data structure, event is the
// incoming event, and p_connection is an output parameter, in the end
// pointing to either 0 if no affected connection could be identified,
// or a pointer to the connection object from the connection table of
// the analyzer.
//

static void
spindump_analyze_processevent_connection_delete(struct spindump_analyze* state,
                                                const struct spindump_event* event,
                                                struct spindump_connection** p_connection) {
  *p_connection = spindump_analyze_processevent_find_connection(state,event);
  if (*p_connection == 0) return;
  
  //
  // Update other information (statistics, state) from the event to
  // the connection object.
  //

  spindump_analyze_event_updateinfo(state,*p_connection,event);

  //
  // Mark the connection deleted
  //

  // ... TBD mark closed
}

//
// Process an event of type "new RTT measurement" from another
// instance of Spindump somewhere else. Update statistics and make any
// other necessary changes in the local database of connections.
//
// The parameter state is the analyzer data structure, event is the
// incoming event, and p_connection is an output parameter, in the end
// pointing to either 0 if no affected connection could be identified,
// or a pointer to the connection object from the connection table of
// the analyzer.
//

static void
spindump_analyze_processevent_new_rtt_measurement(struct spindump_analyze* state,
                                                  const struct spindump_event* event,
                                                  struct spindump_connection** p_connection) {

  *p_connection = spindump_analyze_processevent_find_connection(state,event);
  if (*p_connection == 0) return;
  
  //
  // Did we find a connection in the end? If yes, update other
  // information (statistics, state) from the event to the connection
  // object.
  //

  spindump_analyze_event_updateinfo(state,*p_connection,event);
  
  //
  // And update RTT statistics as well
  //
  
  unsigned long long timestamp = event->timestamp;
  unsigned long long timestampEarlier =
    timestamp >= event->u.newRttMeasurement.rtt ?
    timestamp - event->u.newRttMeasurement.rtt :
    0;
  struct timeval sent;
  struct timeval rcvd;
  spindump_deepdeepdebugf("spindump_analyze_processevent_new_rttmeasurement 1");
  spindump_timestamp_to_timeval(timestampEarlier,&sent);
  spindump_deepdeepdebugf("spindump_analyze_processevent_new_rttmeasurement 2");
  spindump_timestamp_to_timeval(timestamp,&rcvd);
  int right = (event->u.newRttMeasurement.direction == spindump_direction_fromresponder);
  int unidirectional = (event->u.newRttMeasurement.measurement == spindump_measurement_type_unidirectional);
  spindump_connections_newrttmeasurement(state,
                                         0,
                                         *p_connection,
                                         right,
                                         unidirectional,
                                         &sent,
                                         &rcvd,
                                         "remote update");
}

//
// Process an event of type "spin flip" from another instance of
// Spindump somewhere else. Update statistics and make any other
// necessary changes in the local database of connections.
//
// The parameter state is the analyzer data structure, event is the
// incoming event, and p_connection is an output parameter, in the end
// pointing to either 0 if no affected connection could be identified,
// or a pointer to the connection object from the connection table of
// the analyzer.
//

static void
spindump_analyze_processevent_spin_flip(struct spindump_analyze* state,
                                        const struct spindump_event* event,
                                        struct spindump_connection** p_connection) {
  
  //
  // This event is ignored otherwise than for stats, nothing to report
  // in the connection object locally
  //
  
  *p_connection = spindump_analyze_processevent_find_connection(state,event);
  if (*p_connection == 0) return;
  
  //
  // Did we find a connection in the end? If yes, update other
  // information (statistics, state) from the event to the connection
  // object.
  //

  spindump_analyze_event_updateinfo(state,*p_connection,event);
}

//
// Process an event of type "spin value" from another instance of
// Spindump somewhere else. Update statistics and make any other
// necessary changes in the local database of connections.
//
// The parameter state is the analyzer data structure, event is the
// incoming event, and p_connection is an output parameter, in the end
// pointing to either 0 if no affected connection could be identified,
// or a pointer to the connection object from the connection table of
// the analyzer.
//

static void
spindump_analyze_processevent_spin_value(struct spindump_analyze* state,
                                         const struct spindump_event* event,
                                         struct spindump_connection** p_connection) {
  
  // This event is ignored except for stats update, nothing to report in the connection object locally
  
  *p_connection = spindump_analyze_processevent_find_connection(state,event);
  if (*p_connection == 0) return;
  
  //
  // Did we find a connection in the end? If yes, update other
  // information (statistics, state) from the event to the connection
  // object.
  //

  spindump_analyze_event_updateinfo(state,*p_connection,event);
}

//
// Process an event of type "ECN congestion event" from another
// instance of Spindump somewhere else. Update statistics and make any
// other necessary changes in the local database of connections.
//
// The parameter state is the analyzer data structure, event is the
// incoming event, and p_connection is an output parameter, in the end
// pointing to either 0 if no affected connection could be identified,
// or a pointer to the connection object from the connection table of
// the analyzer.
//

static void
spindump_analyze_processevent_ecn_congestion_event(struct spindump_analyze* state,
                                                   const struct spindump_event* event,
                                                   struct spindump_connection** p_connection) {
  // ... TBD
  
  *p_connection = spindump_analyze_processevent_find_connection(state,event);
  if (*p_connection == 0) return;
  
  //
  // Did we find a connection in the end? If yes, update other
  // information (statistics, state) from the event to the connection
  // object.
  //

  spindump_analyze_event_updateinfo(state,*p_connection,event);
}

//
// Process an event of type "RT Loss1 Measurement" from another
// instance of Spindump somewhere else. Update statistics and make any
// other necessary changes in the local database of connections.
//
// The parameter state is the analyzer data structure, event is the
// incoming event, and p_connection is an output parameter, in the end
// pointing to either 0 if no affected connection could be identified,
// or a pointer to the connection object from the connection table of
// the analyzer.
//

static void
spindump_analyze_processevent_rtloss_measurement(struct spindump_analyze* state,
                                                 const struct spindump_event* event,
                                                 struct spindump_connection** p_connection) {
  // ... TBD
  
  *p_connection = spindump_analyze_processevent_find_connection(state,event);
  if (*p_connection == 0) return;
  
  //
  // Did we find a connection in the end? If yes, update other
  // information (statistics, state) from the event to the connection
  // object.
  //

  spindump_analyze_event_updateinfo(state,*p_connection,event);
}

//
// Process an event of type "QR Loss Measurement" from another
// instance of Spindump somewhere else. Update statistics and make any
// other necessary changes in the local database of connections.
//
// The parameter state is the analyzer data structure, event is the
// incoming event, and p_connection is an output parameter, in the end
// pointing to either 0 if no affected connection could be identified,
// or a pointer to the connection object from the connection table of
// the analyzer.
//

static void
spindump_analyze_processevent_qrloss_measurement(struct spindump_analyze* state,
                                                 const struct spindump_event* event,
                                                 struct spindump_connection** p_connection) {
  // ... TBD
  
  *p_connection = spindump_analyze_processevent_find_connection(state,event);
  if (*p_connection == 0) return;
  
  //
  // Did we find a connection in the end? If yes, update other
  // information (statistics, state) from the event to the connection
  // object.
  //

  spindump_analyze_event_updateinfo(state,*p_connection,event);
}

//
// Find the already existing connection pointed to by the
// event. Return that connection object, or 0 if not found. If the
// connection is not found, also give an error message.
//

static struct spindump_connection*
spindump_analyze_processevent_find_connection(struct spindump_analyze* state,
                                              const struct spindump_event* event) {
  struct spindump_connection* connection = 0;
  spindump_port side1port;
  spindump_port side2port;
  struct spindump_quic_connectionid side1cid;
  struct spindump_quic_connectionid side2cid;
  uint16_t peerid;
  
  switch (event->connectionType) {
    
  case spindump_connection_transport_tcp:
    if (!spindump_analyze_event_parsehostpair(event)) return(0);
    if (!spindump_analyze_event_parseportpair(event,&side1port,&side2port)) return(0);
    connection =
      spindump_connections_searchconnection_tcp(&event->initiatorAddress.address,
                                                &event->responderAddress.address,
                                                side1port,
                                                side2port,
                                                state->table);
    break;
    
  case spindump_connection_transport_udp:
    if (!spindump_analyze_event_parsehostpair(event)) return(0);
    if (!spindump_analyze_event_parseportpair(event,&side1port,&side2port)) return(0);
    connection =
      spindump_connections_searchconnection_udp(&event->initiatorAddress.address,
                                             &event->responderAddress.address,
                                             side1port,
                                             side2port,
                                             state->table);
    break;
    
  case spindump_connection_transport_dns:
    if (!spindump_analyze_event_parsehostpair(event)) return(0);
    if (!spindump_analyze_event_parseportpair(event,&side1port,&side2port)) return(0);
    connection =
      spindump_connections_searchconnection_dns(&event->initiatorAddress.address,
                                             &event->responderAddress.address,
                                             side1port,
                                             side2port,
                                             state->table);
    break;
    
  case spindump_connection_transport_coap:
    if (!spindump_analyze_event_parsehostpair(event)) return(0);
    if (!spindump_analyze_event_parseportpair(event,&side1port,&side2port)) return(0);
    connection =
      spindump_connections_searchconnection_coap(&event->initiatorAddress.address,
                                                 &event->responderAddress.address,
                                                 side1port,
                                                 side2port,
                                                 state->table);
    break;
    
  case spindump_connection_transport_quic:
    if (!spindump_analyze_event_parsehostpair(event)) return(0);
    if (!spindump_analyze_event_parsecidpair(event,&side1cid,&side2cid,&side1port,&side2port)) return(0);
    connection =
      spindump_connections_searchconnection_quic_cids(&side1cid,
                                                      &side2cid,
                                                      state->table);
    if (connection == 0) {
      connection =
        spindump_connections_searchconnection_quic_5tuple(&event->initiatorAddress.address,
                                                          &event->responderAddress.address,
                                                          side1port,
                                                          side2port,
                                                          state->table);
    }
    break;
    
  case spindump_connection_transport_icmp:
    if (!spindump_analyze_event_parsehostpair(event)) return(0);
    if (!spindump_analyze_event_parseicmpsessionid(event,&peerid)) return(0);
    connection =
      spindump_connections_searchconnection_icmp(&event->initiatorAddress.address,
                                                 &event->responderAddress.address,
                                                 ICMP_ECHOREPLY,
                                                 peerid,
                                                 state->table);
    break;
    
  case spindump_connection_aggregate_hostpair:
    if (!spindump_analyze_event_parsehostpair(event)) return(0);
    connection =
      spindump_connections_searchconnection_aggregate_hostpair(&event->initiatorAddress.address,
                                                               &event->responderAddress.address,
                                                               state->table);
    break;
    
  case spindump_connection_aggregate_hostnetwork:
    if (!spindump_analyze_event_parseside1host(event)) return(0);
    connection =
      spindump_connections_searchconnection_aggregate_hostnetwork(&event->initiatorAddress.address,
                                                                  &event->responderAddress,
                                                                  state->table);
    break;
    
  case spindump_connection_aggregate_networknetwork:
    connection =
      spindump_connections_searchconnection_aggregate_networknetwork(&event->initiatorAddress,
                                                                     &event->responderAddress,
                                                                     state->table);
    break;
    
  case spindump_connection_aggregate_multicastgroup:
    if (!spindump_analyze_event_parseside1host(event)) return(0);
    connection =
      spindump_connections_searchconnection_aggregate_multicastgroup(&event->initiatorAddress.address,
                                                                     state->table);
    break;
    
  default:
    spindump_errorf("invalid connection type %u", event->connectionType);
    return(0);
    
  }

  //
  // Check if we got a connection
  //

  if (connection == 0) {
    spindump_errorf("cannot find the connection referred to by the event");
    return(0);
  }

  //
  // We're good. Return the object
  //
  
  return(connection);
}

//
// Process the packet counter and other general statistics present in
// every event. Make the information available in the local connection
// object, copied from the event.
//

static void
spindump_analyze_event_updateinfo(struct spindump_analyze* state,
                                  struct spindump_connection* connection,
                                  const struct spindump_event* event) {
  
  //
  // Sanity checks
  //

  spindump_assert(state != 0);
  spindump_assert(connection != 0);
  spindump_assert(event != 0);

  //
  // Update timestamps
  //

  struct timeval* tv = 0;
  if (connection->packetsFromSide1 < event->packetsFromSide1) {
    tv = &connection->latestPacketFromSide1;
    spindump_deepdeepdebugf("spindump_analyze_processevent_updateinfo 1");
    spindump_timestamp_to_timeval(event->timestamp,tv);
  }
  if (connection->packetsFromSide2 < event->packetsFromSide2) {
    tv = &connection->latestPacketFromSide2;
    spindump_deepdeepdebugf("spindump_analyze_processevent_updateinfo 2");
    spindump_timestamp_to_timeval(event->timestamp,tv);
  }
  
  //
  // Update packet counters
  //

  spindump_counter_64bit fromSide1Diff = event->packetsFromSide1 - connection->packetsFromSide1;
  spindump_counter_64bit fromSide2Diff = event->packetsFromSide2 - connection->packetsFromSide2;
  connection->packetsFromSide1 = event->packetsFromSide1;
  connection->packetsFromSide2 = event->packetsFromSide2;
  if (tv == 0) {
    tv = &connection->creationTime;
  }

  //
  // Update bandwidth numbers
  //

  spindump_counter_64bit bytesFromSide1Diff = event->bytesFromSide1 - connection->bytesFromSide1.bytes;
  spindump_counter_64bit bytesFromSide2Diff = event->bytesFromSide2 - connection->bytesFromSide2.bytes;
  spindump_bandwidth_setcounter(&connection->bytesFromSide1,event->bytesFromSide1,tv);
  spindump_bandwidth_setcounter(&connection->bytesFromSide2,event->bytesFromSide2,tv);
  connection->bytesFromSide1.bytesInLastPeriod = event->bandwidthFromSide1;
  connection->bytesFromSide2.bytesInLastPeriod = event->bandwidthFromSide2;
  
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
    struct timeval when;
    spindump_timestamp_to_timeval(event->timestamp,&when);
    spindump_analyze_event_updateinfo_aggregate(state,
                                                aggregate,
                                                fromSide1Diff,fromSide2Diff,
                                                bytesFromSide1Diff,bytesFromSide2Diff,
                                                &when);
    
  }

}

//
// Process the packet counter and other general statistics for each
// aggregate of a connection. The additional packet and byte counter
// data and event timestamp are given as input, as the event for a
// specific connection does not carry the total amount of packets and
// bytes for the entire aggregate.
//

static void
spindump_analyze_event_updateinfo_aggregate(struct spindump_analyze* state,
                                            struct spindump_connection* connection,
                                            spindump_counter_64bit fromSide1Diff,
                                            spindump_counter_64bit fromSide2Diff,
                                            spindump_counter_64bit bytesFromSide1Diff,
                                            spindump_counter_64bit bytesFromSide2Diff,
                                            struct timeval* when) {
  
  //
  // Sanity checks
  //

  spindump_assert(state != 0);
  spindump_assert(connection != 0);
  spindump_assert(when != 0);

  //
  // Update timestamps
  //
  
  if (fromSide1Diff > 0) connection->latestPacketFromSide1 = *when;
  if (fromSide2Diff > 0) connection->latestPacketFromSide2 = *when;
  
  //
  // Update packet counters
  //
  
  connection->packetsFromSide1 += fromSide1Diff;
  connection->packetsFromSide2 += fromSide2Diff;
  
  //
  // Update bandwidth numbers
  //
  
  spindump_bandwidth_newpacket(&connection->bytesFromSide1,(unsigned int)bytesFromSide1Diff,when);
  spindump_bandwidth_newpacket(&connection->bytesFromSide2,(unsigned int)bytesFromSide2Diff,when);
  
  //
  // Loop through any possible aggregated connections this aggregate
  // connection belongs to, and report the same measurement udpates
  // there.
  //
  
  struct spindump_connection_set_iterator iter;
  for (spindump_connection_set_iterator_initialize(&connection->aggregates,&iter);
       !spindump_connection_set_iterator_end(&iter);
       ) {
    
    struct spindump_connection* aggregate = spindump_connection_set_iterator_next(&iter);
    spindump_assert(aggregate != 0);
    spindump_analyze_event_updateinfo_aggregate(state,
                                                aggregate,
                                                fromSide1Diff,fromSide2Diff,
                                                bytesFromSide1Diff,bytesFromSide2Diff,
                                                when);
    
  }
}
