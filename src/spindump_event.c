
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "spindump_util.h"
#include "spindump_event.h"
#include "spindump_connections.h"

//
// Actual code --------------------------------------------------------------------------------
//

void
spindump_event_initialize(enum spindump_event_type eventType,
                          enum spindump_connection_type connectionType,
                          unsigned int id,
                          enum spindump_connection_state state,
                          const spindump_network* initiatorAddress,
                          const spindump_network* responderAddress,
                          const char* session,
                          unsigned long long timestamp,
                          spindump_counter_64bit packetsFromSide1,
                          spindump_counter_64bit packetsFromSide2,
                          spindump_counter_64bit bytesFromSide1,
                          spindump_counter_64bit bytesFromSide2,
                          spindump_counter_64bit bandwidthFromSide1,
                          spindump_counter_64bit bandwidthFromSide2,
                          const spindump_tags* tags,
                          const char* notes,
                          struct spindump_event* event) {

  //
  // Sanity checks
  //

  spindump_deepdeepdebugf("spindump_event_initialize(%s,%s,%s)",
                          spindump_event_type_tostring(eventType),
                          spindump_connection_type_to_string(connectionType),
                          tags->string);
  spindump_assert(initiatorAddress != 0);
  spindump_assert(responderAddress != 0);
  spindump_assert(session != 0);
  spindump_assert(strlen(session) < spindump_event_sessionidmaxlength);
  spindump_assert(event != 0);

  //
  // Construct the event
  //
  
  memset(event,0,sizeof(*event));
  event->eventType = eventType;
  event->connectionType = connectionType;
  event->id = id;
  event->state = state;
  event->initiatorAddress = *initiatorAddress;
  event->responderAddress = *responderAddress;
  strncpy(&event->session[0],session,sizeof(event->session));
  event->timestamp = timestamp;
  event->packetsFromSide1 = packetsFromSide1;
  event->packetsFromSide2 = packetsFromSide2;
  event->bytesFromSide1 = bytesFromSide1;
  event->bytesFromSide2 = bytesFromSide2;
  event->bandwidthFromSide1 = bandwidthFromSide1;
  event->bandwidthFromSide2 = bandwidthFromSide2;
  if (notes != 0) {
    spindump_deepdeepdebugf("notes field pt 2 = %s", notes);
    strncpy(event->notes,notes,sizeof(event->notes)-1);
    spindump_deepdeepdebugf("notes field pt 3 = %s", event->notes);
  }
  if (tags != 0) {
    spindump_tags_copy(&event->tags,tags);
  } else {
    spindump_tags_initialize(&event->tags);
  }
  spindump_deepdeepdebugf("new event bandwidths %llu %llu from bytes %llu %llu",
                          bandwidthFromSide1, bandwidthFromSide2,
                          bytesFromSide1, bytesFromSide2);
}

//
// Get the name of the event as a string. The returned string is
// static, ie. should not be deallocated by the caller.
//
// The mapping in this function needs to match what's given for the
// reverse mapping in function
// spindump_event_parser_json_converteventtype in
// spindump_event_parser_json.c.
//

const char*
spindump_event_type_tostring(enum spindump_event_type type) {
  switch (type) {
  case spindump_event_type_new_connection: return("new");
  case spindump_event_type_change_connection: return("change");
  case spindump_event_type_connection_delete: return("delete");
  case spindump_event_type_new_rtt_measurement: return("measurement");
  case spindump_event_type_periodic: return("periodic");
  case spindump_event_type_spin_flip: return("spinflip");
  case spindump_event_type_spin_value: return("spinvalue");
  case spindump_event_type_ecn_congestion_event: return("ecnce");
  case spindump_event_type_rtloss_measurement: return("rtloss");
  case spindump_event_type_qrloss_measurement: return("qrloss");
  case spindump_event_type_qlloss_measurement: return("qlloss");
  case spindump_event_type_packet: return("packet");
  default:
    spindump_errorf("invalid event type");
    return("UNKNOWN");
  }
}

//
// Compare two events for equality
//

int
spindump_event_equal(const struct spindump_event* event1,
                     const struct spindump_event* event2) {

  //
  // Sanity checks
  //

  spindump_assert(event1 != 0);
  spindump_assert(event2 != 0);

  //
  // Basic type compare
  //

  if (event1->eventType != event2->eventType) return(0);

  //
  // Compare common fields
  //

  if (event1->connectionType != event2->connectionType) return(0);
  if (event1->id != event2->id) return(0);
  if (event1->state != event2->state) return(0);
  if (!spindump_network_equal(&event1->initiatorAddress,&event2->initiatorAddress)) return(0);
  if (!spindump_network_equal(&event1->responderAddress,&event2->responderAddress)) return(0);
  if (strcmp(event1->session,event2->session) != 0) return(0);
  if (event1->timestamp != event2->timestamp) return(0);
  if (event1->packetsFromSide1 != event2->packetsFromSide1) return(0);
  if (event1->packetsFromSide2 != event2->packetsFromSide2) return(0);
  if (event1->bytesFromSide1 != event2->bytesFromSide1) return(0);
  if (event1->bytesFromSide2 != event2->bytesFromSide2) return(0);
  if (event1->bandwidthFromSide1 != event2->bandwidthFromSide1) return(0);
  if (event1->bandwidthFromSide2 != event2->bandwidthFromSide2) return(0);
  if (spindump_tags_compare(&event1->tags,&event2->tags) != 0) return(0);
  
  //
  // Compare type-specific fields
  //
  
  switch (event1->eventType) {
  case spindump_event_type_new_connection:
    break;
  case spindump_event_type_change_connection:
    break;
  case spindump_event_type_connection_delete:
    break;
  case spindump_event_type_new_rtt_measurement:
    if (event1->u.newRttMeasurement.measurement != event2->u.newRttMeasurement.measurement) return(0);
    if (event1->u.newRttMeasurement.direction != event2->u.newRttMeasurement.direction) return(0);
    if (event1->u.newRttMeasurement.rtt != event2->u.newRttMeasurement.rtt) return(0);
    if (event1->u.newRttMeasurement.avgRtt != event2->u.newRttMeasurement.avgRtt) return(0);
    if (event1->u.newRttMeasurement.devRtt != event2->u.newRttMeasurement.devRtt) return(0);
    if (event1->u.newRttMeasurement.filtAvgRtt != event2->u.newRttMeasurement.filtAvgRtt) return(0);
    break;
  case spindump_event_type_periodic:
    if (event1->u.periodic.rttRight != event2->u.periodic.rttRight) return(0);
    if (event1->u.periodic.avgRttRight != event2->u.periodic.avgRttRight) return(0);
    if (event1->u.periodic.devRttRight != event2->u.periodic.devRttRight) return(0);
    break;
  case spindump_event_type_spin_flip:
    if (event1->u.spinFlip.direction != event2->u.spinFlip.direction) return(0);
    if (event1->u.spinFlip.spin0to1 != event2->u.spinFlip.spin0to1) return(0);
    break;
  case spindump_event_type_spin_value:
    if (event1->u.spinValue.direction != event2->u.spinValue.direction) return(0);
    if (event1->u.spinValue.value != event2->u.spinValue.value) return(0);
    break;
  case spindump_event_type_ecn_congestion_event:
    if (event1->u.ecnCongestionEvent.direction != event2->u.ecnCongestionEvent.direction) return(0);
    if (event1->u.ecnCongestionEvent.ecn0 != event2->u.ecnCongestionEvent.ecn0) return(0);
    if (event1->u.ecnCongestionEvent.ecn1 != event2->u.ecnCongestionEvent.ecn1) return(0);
    if (event1->u.ecnCongestionEvent.ce != event2->u.ecnCongestionEvent.ce) return(0);
    break;
  case spindump_event_type_rtloss_measurement:
    if (event1->u.rtlossMeasurement.direction != event2->u.rtlossMeasurement.direction) return(0);
    if (strcmp(event1->u.rtlossMeasurement.avgLoss, event2->u.rtlossMeasurement.avgLoss) != 0) return(0);
    if (strcmp(event1->u.rtlossMeasurement.totLoss, event2->u.rtlossMeasurement.totLoss) != 0) return(0);
    break;
  case spindump_event_type_qrloss_measurement:
    if (event1->u.qrlossMeasurement.direction != event2->u.qrlossMeasurement.direction) return(0);
    if (strcmp(event1->u.qrlossMeasurement.avgLoss, event2->u.qrlossMeasurement.avgLoss) != 0) return(0);
    if (strcmp(event1->u.qrlossMeasurement.totLoss, event2->u.qrlossMeasurement.totLoss) != 0) return(0);
    if (strcmp(event1->u.qrlossMeasurement.avgRefLoss, event2->u.qrlossMeasurement.avgRefLoss) != 0) return(0);
    if (strcmp(event1->u.qrlossMeasurement.totRefLoss, event2->u.qrlossMeasurement.totRefLoss) != 0) return(0);
    break;
  case spindump_event_type_qlloss_measurement:
    if (event1->u.qllossMeasurement.direction != event2->u.qllossMeasurement.direction) return(0);
    if (strcmp(event1->u.qllossMeasurement.qLoss, event2->u.qllossMeasurement.qLoss) != 0) return(0);
    if (strcmp(event1->u.qllossMeasurement.lLoss, event2->u.qllossMeasurement.lLoss) != 0) return(0);
    break;
  case spindump_event_type_packet:
    if (event1->u.packet.length != event2->u.packet.length) return(0);
    if (event1->u.packet.direction != event2->u.packet.direction) return(0);
    break;
  default:
    spindump_errorf("unrecognised event type %u", event1->eventType);
    return(0);
  }
  
  //
  // Done. Everything compared the same
  //
  
  return(1);
}

