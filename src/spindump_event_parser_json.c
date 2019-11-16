
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
#include "spindump_event_parser_json.h"
#include "spindump_connections.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static int
spindump_event_parser_json_converteventtype(const char* string,
                                            enum spindump_event_type* type);
static int
spindump_event_parser_json_parse_aux_new_connection(const struct spindump_json_value* json,
                                                    struct spindump_event* event);
static int
spindump_event_parser_json_parse_aux_change_connection(const struct spindump_json_value* json,
                                                       struct spindump_event* event);
static int
spindump_event_parser_json_parse_aux_connection_delete(const struct spindump_json_value* json,
                                                       struct spindump_event* event);
static int
spindump_event_parser_json_parse_aux_new_rtt_measurement(const struct spindump_json_value* json,
                                                         struct spindump_event* event);
static int
spindump_event_parser_json_parse_aux_spin_flip(const struct spindump_json_value* json,
                                               struct spindump_event* event);
static int
spindump_event_parser_json_parse_aux_spin_value(const struct spindump_json_value* json,
                                                struct spindump_event* event);
static int
spindump_event_parser_json_parse_aux_ecn_congestion_event(const struct spindump_json_value* json,
                                                          struct spindump_event* event);
static int
spindump_event_parser_json_parse_aux_rtloss_measurement(const struct spindump_json_value* json,
                                                        struct spindump_event* event);
static int
spindump_event_parser_json_parse_aux_qrloss_measurement(const struct spindump_json_value* json,
                                                          struct spindump_event* event);

//
// Actual code --------------------------------------------------------------------------------
//

//
// Take a buffer of data in "buffer" (whose length is given in
// "length") and parse it as a JSON-formatted event description from
// Spindump, placing the result in the output parqmeter "event".
//
// If successful, return 1, upon no non-whitespace input to read in
// the buffer, return 0 for EOF, and upon parsing error return -1.
//
// In any case, set the output parameter "consumed" to the number of
// bytes consumed from the buffer.
//

int
spindump_event_parser_json_parse(const struct spindump_json_value* json,
                                 struct spindump_event* event) {

  //
  // Sanity checks
  //

  spindump_assert(json != 0);
  spindump_assert(json->type == spindump_json_value_type_record);
  spindump_assert(event != 0);

  //
  // Get the mandatory fields
  //

  const char* eventType = spindump_json_value_getstring(spindump_json_value_getrequiredfield("Event",json));
  spindump_deepdeepdebugf("spindump_event_parser_json_parse %s", eventType);
  if (!spindump_event_parser_json_converteventtype(eventType,&event->eventType)) {
    spindump_errorf("Invalid event type %s", eventType);
    return(0);
  }
  const char* connectionType = spindump_json_value_getstring(spindump_json_value_getrequiredfield("Type",json));
  if (!spindump_connection_string_to_connectiontype(connectionType,&event->connectionType)) {
    spindump_errorf("Invalid connection type %s", connectionType);
    return(0);
  }
  const char* state = spindump_json_value_getstring(spindump_json_value_getrequiredfield("State",json));
  if (!spindump_connection_statestring_to_state(state,&event->state)) {
    spindump_errorf("Invalid state %s", state);
    return(0);
  }
  const struct spindump_json_value* addrs = spindump_json_value_getrequiredfield("Addrs",json);
  const struct spindump_json_value* addr1elem = spindump_json_value_getarrayelem(0,addrs);
  const struct spindump_json_value* addr2elem = spindump_json_value_getarrayelem(1,addrs);
  if (addr1elem == 0 || addr2elem == 0) {
    spindump_errorf("Missing addresses in an event");
    return(0);
  }
  const char* addr1 = spindump_json_value_getstring(addr1elem);
  if (!spindump_network_fromstringoraddr(&event->initiatorAddress,addr1)) {
    spindump_errorf("Cannot parse initiator address");
    return(0);
  }
  const char* addr2 = spindump_json_value_getstring(addr2elem);
  if (!spindump_network_fromstringoraddr(&event->responderAddress,addr2)) {
    spindump_errorf("Cannot parse responder address");
    return(0);
  }
  const char* session = spindump_json_value_getstring(spindump_json_value_getrequiredfield("Session",json));
  if (strlen(session) + 1 > sizeof(event->session)) {
    spindump_errorf("Session field is too long for the event");
    return(0);
  }
  strncpy(&event->session[0],session,sizeof(event->session));
  unsigned long long ts = spindump_json_value_getinteger(spindump_json_value_getrequiredfield("Ts",json));
  event->timestamp = ts;
  unsigned long long packets1 = spindump_json_value_getinteger(spindump_json_value_getrequiredfield("Packets1",json));
  event->packetsFromSide1 = (unsigned int)packets1;
  unsigned long long packets2 = spindump_json_value_getinteger(spindump_json_value_getrequiredfield("Packets2",json));
  event->packetsFromSide2 = (unsigned int)packets2;
  unsigned long long bytes1 = spindump_json_value_getinteger(spindump_json_value_getrequiredfield("Bytes1",json));
  event->bytesFromSide1 = (unsigned int)bytes1;
  unsigned long long bytes2 = spindump_json_value_getinteger(spindump_json_value_getrequiredfield("Bytes2",json));
  event->bytesFromSide2 = (unsigned int)bytes2;
  const struct spindump_json_value* bandwidth1Elem = spindump_json_value_getfield("Bandwidth1",json);
  if (bandwidth1Elem != 0) {
    unsigned long long bandwidth1 = spindump_json_value_getinteger(bandwidth1Elem);
    event->bandwidthFromSide1 = (unsigned int)bandwidth1;
  } else {
    event->bandwidthFromSide1 = 0;
  }
  const struct spindump_json_value* bandwidth2Elem = spindump_json_value_getfield("Bandwidth2",json);
  if (bandwidth2Elem != 0) {
    unsigned long long bandwidth2 = spindump_json_value_getinteger(bandwidth2Elem);
    event->bandwidthFromSide2 = (unsigned int)bandwidth2;
  } else {
    event->bandwidthFromSide2 = 0;
  }

  //
  // Get the optional fields
  //
  
  const struct spindump_json_value* notes = spindump_json_value_getfield("Notes",json);
  if (notes != 0) {
    const char* notesString = spindump_json_value_getstring(notes);
    strncpy(event->notes,notesString,sizeof(event->notes)-1);
  }
  
  //
  // Get the rest of the fields based on the type of event
  //

  switch (event->eventType) {
    
  case spindump_event_type_new_connection:
    if (!spindump_event_parser_json_parse_aux_new_connection(json,event)) {
      return(0);
    }
    break;
    
  case spindump_event_type_change_connection:
    if (!spindump_event_parser_json_parse_aux_change_connection(json,event)) {
      return(0);
    }
    break;
    
  case spindump_event_type_connection_delete:
    if (!spindump_event_parser_json_parse_aux_connection_delete(json,event)) {
      return(0);
    }
    break;
    
  case spindump_event_type_new_rtt_measurement:
    if (!spindump_event_parser_json_parse_aux_new_rtt_measurement(json,event)) {
      return(0);
    }
    break;
    
  case spindump_event_type_spin_flip:
    if (!spindump_event_parser_json_parse_aux_spin_flip(json,event)) {
      return(0);
    }
    break;
    
  case spindump_event_type_spin_value:
    if (!spindump_event_parser_json_parse_aux_spin_value(json,event)) {
      return(0);
    }
    break;
    
  case spindump_event_type_ecn_congestion_event:
    if (!spindump_event_parser_json_parse_aux_ecn_congestion_event(json,event)) {
      return(0);
    }
    break;

  case spindump_event_type_rtloss_measurement:
    if (!spindump_event_parser_json_parse_aux_rtloss_measurement(json, event)) {
      return(0);
    }
    break;

  case spindump_event_type_qrloss_measurement:
    if (!spindump_event_parser_json_parse_aux_qrloss_measurement(json,event)) {
      return(0);
    }
    break;
    
  default:
    spindump_errorf("Invalid event type %u", event->eventType);
    return(0);
  }
  
  return(1);
}

//
// Copy fields from JSON event to the event struct, for events of the
// type "". Return value is 0 upon error, 1 upon success.
//

static int
spindump_event_parser_json_parse_aux_new_connection(const struct spindump_json_value* json,
                                                    struct spindump_event* event) {
  //
  // This always succeeds
  //
  
  return(1);
}

//
// Copy fields from JSON event to the event struct, for events of the
// type "Change Connection". Return value is 0 upon error, 1 upon success.
//

static int
spindump_event_parser_json_parse_aux_change_connection(const struct spindump_json_value* json,
                                                       struct spindump_event* event) {
  //
  // This always succeeds
  //
  
  return(1);
}

//
// Copy fields from JSON event to the event struct, for events of the
// type "Connection Delete". Return value is 0 upon error, 1 upon
// success.
//

static int
spindump_event_parser_json_parse_aux_connection_delete(const struct spindump_json_value* json,
                                                       struct spindump_event* event) {
  //
  // This always succeeds
  //
  
  return(1);
}

//
// Copy fields from JSON event to the event struct, for events of the
// type "". Return value is 0 upon error, 1 upon success.
//

static int
spindump_event_parser_json_parse_aux_new_rtt_measurement(const struct spindump_json_value* json,
                                                         struct spindump_event* event) {
  const struct spindump_json_value* field = 0;
  const struct spindump_json_value* avgfield = 0;
  const struct spindump_json_value* devfield = 0;
  const struct spindump_json_value* filtavgfield = 0;
  if ((field = spindump_json_value_getfield("Left_rtt",json)) != 0) {
    event->u.newRttMeasurement.measurement = spindump_measurement_type_bidirectional;
    event->u.newRttMeasurement.direction = spindump_direction_frominitiator;
    avgfield = spindump_json_value_getfield("Avg_left_rtt",json);
    devfield = spindump_json_value_getfield("Dev_left_rtt",json);
    filtavgfield = spindump_json_value_getfield("Filt_avg_left_rtt",json);
  } else if ((field = spindump_json_value_getfield("Right_rtt",json)) != 0) {
    event->u.newRttMeasurement.measurement = spindump_measurement_type_bidirectional;
    event->u.newRttMeasurement.direction = spindump_direction_fromresponder;
    avgfield = spindump_json_value_getfield("Avg_right_rtt",json);
    devfield = spindump_json_value_getfield("Dev_right_rtt",json);
    filtavgfield = spindump_json_value_getfield("Filt_avg_right_rtt",json);
  } else if ((field = spindump_json_value_getfield("Full_rtt_initiator",json)) != 0) {
    event->u.newRttMeasurement.measurement = spindump_measurement_type_unidirectional;
    event->u.newRttMeasurement.direction = spindump_direction_frominitiator;
    avgfield = spindump_json_value_getfield("Avg_full_rtt_initiator",json);
    devfield = spindump_json_value_getfield("Dev_full_rtt_initiator",json);
    filtavgfield = spindump_json_value_getfield("Filt_avg_full_rtt_initiator",json);
  } else if ((field = spindump_json_value_getfield("Full_rtt_responder",json)) != 0) {
    event->u.newRttMeasurement.measurement = spindump_measurement_type_unidirectional;
    event->u.newRttMeasurement.direction = spindump_direction_fromresponder;
    avgfield = spindump_json_value_getfield("Avg_full_rtt_responder",json);
    devfield = spindump_json_value_getfield("Dev_full_rtt_responder",json);
    filtavgfield = spindump_json_value_getfield("Filt_avg_full_rtt_responder",json);
  } else {
    spindump_errorf("new RTT measurement event does not have the necessary JSON fields");
    return(0);
  }
  unsigned long long value = spindump_json_value_getinteger(field);
  unsigned long long avgValue;
  unsigned long long devValue;
  unsigned long long filtAvgValue;
  event->u.newRttMeasurement.rtt = (unsigned long)value;
  if (avgfield != 0 &&
      (avgValue = spindump_json_value_getinteger(avgfield)) > 0) {
    event->u.newRttMeasurement.avgRtt = (unsigned long)avgValue;
  }
  if (devfield != 0 &&
      (devValue = spindump_json_value_getinteger(devfield)) > 0) {
    event->u.newRttMeasurement.devRtt = (unsigned long)devValue;
  }
  if (filtavgfield != 0 &&
      (filtAvgValue = spindump_json_value_getinteger(filtavgfield)) > 0) {
    event->u.newRttMeasurement.filtAvgRtt = (unsigned long)filtAvgValue;
  }
  return(1);
}

//
// Copy fields from JSON event to the event struct, for events of the
// type "Spin Flip". Return value is 0 upon error, 1 upon success.
//

static int
spindump_event_parser_json_parse_aux_spin_flip(const struct spindump_json_value* json,
                                               struct spindump_event* event) {
  const struct spindump_json_value* transitionField = spindump_json_value_getfield("Transition",json);
  const struct spindump_json_value* whoField = spindump_json_value_getfield("Who",json);
  if (transitionField == 0 || whoField == 0) {
    spindump_errorf("spin flip event does not have the necessary JSON fields");
    return(0);
  }
  const char* transitionValue = spindump_json_value_getstring(transitionField);
  const char* whoValue = spindump_json_value_getstring(whoField);
  if (strcmp(transitionValue,"0-1") == 0) {
    event->u.spinFlip.spin0to1 = 1;
  } else if (strcmp(transitionValue,"1-0") == 0) {
    event->u.spinFlip.spin0to1 = 0;
  } else {
    spindump_errorf("spin flip transition value does not have the right value in JSON: %s", transitionValue);
    return(0);
  }
  if (strcasecmp(whoValue,"initiator") == 0) {
    event->u.spinFlip.direction = spindump_direction_frominitiator;
  } else if (strcasecmp(whoValue,"responder") == 0) {
    event->u.spinFlip.direction = spindump_direction_fromresponder;
  } else {
    spindump_errorf("spin flip direction does not have the right value in JSON: %s", whoValue);
    return(0);
  }
  return(1);
}

//
// Copy fields from JSON event to the event struct, for events of the
// type "Spin Value". Return value is 0 upon error, 1 upon success.
//

static int
spindump_event_parser_json_parse_aux_spin_value(const struct spindump_json_value* json,
                                                struct spindump_event* event) {
  const struct spindump_json_value* valueField = spindump_json_value_getfield("Value",json);
  const struct spindump_json_value* whoField = spindump_json_value_getfield("Who",json);
  if (valueField == 0 || whoField == 0) {
    spindump_errorf("spin value event does not have the necessary JSON fields");
    return(0);
  }
  unsigned long long valueValue = spindump_json_value_getinteger(valueField);
  const char* whoValue = spindump_json_value_getstring(whoField);
  if (valueValue == 0) {
    event->u.spinValue.value = 0;
  } else if (valueValue == 1) {
    event->u.spinValue.value = 1;
  } else {
    spindump_errorf("spin value bit value does not have the right value in JSON: %llu", valueValue);
    return(0);
  }
  if (strcasecmp(whoValue,"initiator") == 0) {
    event->u.spinValue.direction = spindump_direction_frominitiator;
  } else if (strcasecmp(whoValue,"responder") == 0) {
    event->u.spinValue.direction = spindump_direction_fromresponder;
  } else {
    spindump_errorf("spin value direction does not have the right value in JSON: %s", whoValue);
    return(0);
  }
  return(1);
}

//
// Copy fields from JSON event to the event struct, for events of the
// type "ECN Congestion Event". Return value is 0 upon error, 1 upon success.
//

static int
spindump_event_parser_json_parse_aux_ecn_congestion_event(const struct spindump_json_value* json,
                                                          struct spindump_event* event) {
  const struct spindump_json_value* whoField = spindump_json_value_getfield("Who",json);
  const struct spindump_json_value* ecn0Field = spindump_json_value_getfield("Ecn0",json);
  const struct spindump_json_value* ecn1Field = spindump_json_value_getfield("Ecn1",json);
  const struct spindump_json_value* ceField = spindump_json_value_getfield("Ce",json);
  if (whoField == 0 || ecn0Field == 0 || ecn1Field == 0 || ceField == 0) {
    spindump_errorf("congestion notification event does not have the necessary JSON fields");
    return(0);
  }
  const char* whoValue = spindump_json_value_getstring(whoField);
  unsigned long long ecn0Value = spindump_json_value_getinteger(ecn0Field);
  unsigned long long ecn1Value = spindump_json_value_getinteger(ecn1Field);
  unsigned long long ceValue = spindump_json_value_getinteger(ceField);
  event->u.ecnCongestionEvent.ecn0 = (unsigned int)ecn0Value;
  event->u.ecnCongestionEvent.ecn1 = (unsigned int)ecn1Value;
  event->u.ecnCongestionEvent.ce = (unsigned int)ceValue;
  if (strcasecmp(whoValue,"initiator") == 0) {
    event->u.ecnCongestionEvent.direction = spindump_direction_frominitiator;
  } else if (strcasecmp(whoValue,"responder") == 0) {
    event->u.ecnCongestionEvent.direction = spindump_direction_fromresponder;
  } else {
    spindump_errorf("congestion notification event direction does not have the right value in JSON: %s", whoValue);
    return(0);
  }
  return(1);
}

static int
spindump_event_parser_json_parse_aux_rtloss_measurement(const struct spindump_json_value* json,
                                                        struct spindump_event* event) {
  const struct spindump_json_value* whoField = spindump_json_value_getfield("Who",json);
  const struct spindump_json_value* avgField = spindump_json_value_getfield("Avg_loss",json);
  const struct spindump_json_value* totField = spindump_json_value_getfield("Tot_loss",json);
  
  if (whoField == 0 || avgField == 0 || totField == 0) {
    spindump_errorf("rtloss event does not have the necessary JSON fields");
    return(0);
  }

  const char* avgValue = spindump_json_value_getstring(avgField);
  const char* totValue = spindump_json_value_getstring(totField);
  const char* whoValue = spindump_json_value_getstring(whoField);

  // Implement validity check
  memset(event->u.rtlossMeasurement.avgLoss, '\0', sizeof(event->u.rtlossMeasurement.avgLoss));
  strcpy(event->u.rtlossMeasurement.avgLoss, avgValue);

  memset(event->u.rtlossMeasurement.totLoss, '\0', sizeof(event->u.rtlossMeasurement.totLoss));
  strcpy(event->u.rtlossMeasurement.totLoss, totValue);

  if (strcasecmp(whoValue,"initiator") == 0) {
    event->u.rtlossMeasurement.direction = spindump_direction_frominitiator;
  } else if (strcasecmp(whoValue,"responder") == 0) {
    event->u.rtlossMeasurement.direction = spindump_direction_fromresponder;
  } else {
    spindump_errorf("rtloss value direction does not have the right value in JSON: %s", whoValue);
    return(0);
  }
  return(1);
}

static int
spindump_event_parser_json_parse_aux_qrloss_measurement(const struct spindump_json_value* json,
                                                struct spindump_event* event) {
  const struct spindump_json_value* whoField = spindump_json_value_getfield("Who",json);
  const struct spindump_json_value* qField = spindump_json_value_getfield("Q_loss",json);
  const struct spindump_json_value* rField = spindump_json_value_getfield("R_loss",json);
  
  if (whoField == 0 || qField == 0 || rField == 0) {
    spindump_errorf("qrloss event does not have the necessary JSON fields");
    return(0);
  }

  const char* whoValue = spindump_json_value_getstring(whoField);
  const char* qValue = spindump_json_value_getstring(qField);
  const char* rValue = spindump_json_value_getstring(rField);

  // Implement validity check
  memset(event->u.qrlossMeasurement.qLoss, '\0', sizeof(event->u.qrlossMeasurement.qLoss));
  strcpy(event->u.qrlossMeasurement.qLoss, qValue);

  memset(event->u.qrlossMeasurement.rLoss, '\0', sizeof(event->u.qrlossMeasurement.rLoss));
  strcpy(event->u.qrlossMeasurement.rLoss, rValue);

  if (strcasecmp(whoValue,"initiator") == 0) {
    event->u.qrlossMeasurement.direction = spindump_direction_frominitiator;
  } else if (strcasecmp(whoValue,"responder") == 0) {
    event->u.qrlossMeasurement.direction = spindump_direction_fromresponder;
  } else {
    spindump_errorf("qrloss value direction does not have the right value in JSON: %s", whoValue);
    return(0);
  }
  return(1);
}

//
// Take an event description in the input parameter "event", and print
// it out as a JSON-formatted Spindump event. The printed version will
// be placed in the buffer "buffer" whose length is at most "length".
//
// If successful, in other words, if there was enough space in the
// buffer, return 1, otherwise 0. Set the output parameter "consumed" to
// the number of consumed bytes.
//

int
spindump_event_parser_json_print(const struct spindump_event* event,
                                 char* buffer,
                                 size_t length,
                                 size_t* consumed) {

  //
  // Check length
  //
  
  if (length < 2) return(0);
  memset(buffer,0,length);

  //
  // Some utilities to put strings onto the buffer
  //
  
#define addtobuffer1(x)     snprintf(buffer + strlen(buffer),length - 1 - strlen(buffer),x)
#define addtobuffer2(x,y)   snprintf(buffer + strlen(buffer),length - 1 - strlen(buffer),x,y)
#define addtobuffer3(x,y,z) snprintf(buffer + strlen(buffer),length - 1 - strlen(buffer),x,y,z)

  //
  // Basic information about the connection
  //
  
  addtobuffer3("{ \"Event\": \"%s\", \"Type\": \"%s\", ",
               spindump_event_type_tostring(event->eventType),
               spindump_connection_type_to_string(event->connectionType));
  addtobuffer2("\"Addrs\": [\"%s\",",
               spindump_network_tostringoraddr(&event->initiatorAddress));
  addtobuffer2("\"%s\"], ",
               spindump_network_tostringoraddr(&event->responderAddress));
  addtobuffer2("\"Session\": \"%s\", ",
               event->session);
  addtobuffer2("\"Ts\": %llu, ",
               event->timestamp);
  addtobuffer2("\"State\": \"%s\"",
               spindump_connection_statestring_plain(event->state));
  if (event->notes[0] != 0) {
    addtobuffer2(", \"Notes\": \"%s\"", event->notes);
  }
  
  //
  // The variable part that depends on which event we have
  //

  switch (event->eventType) {
    
  case spindump_event_type_new_connection:
    break;
    
  case spindump_event_type_change_connection:
    break;
    
  case spindump_event_type_connection_delete:
    break;
    
  case spindump_event_type_new_rtt_measurement:
    if (event->u.newRttMeasurement.measurement == spindump_measurement_type_bidirectional) {
      if (event->u.newRttMeasurement.direction == spindump_direction_frominitiator) {
        addtobuffer2(", \"Left_rtt\": %lu", event->u.newRttMeasurement.rtt);
        if (event->u.newRttMeasurement.avgRtt > 0) {
          addtobuffer2(", \"Avg_Left_rtt\": %lu", event->u.newRttMeasurement.avgRtt);
          addtobuffer2(", \"Dev_Left_rtt\": %lu", event->u.newRttMeasurement.devRtt);
        }
        if (event->u.newRttMeasurement.filtAvgRtt > 0) {
          addtobuffer2(", \"Filt_avg_Left_rtt\": %lu", event->u.newRttMeasurement.filtAvgRtt);
        }
      } else {
        addtobuffer2(", \"Right_rtt\": %lu", event->u.newRttMeasurement.rtt);
        if (event->u.newRttMeasurement.avgRtt > 0) {
          addtobuffer2(", \"Avg_right_rtt\": %lu", event->u.newRttMeasurement.avgRtt);
          addtobuffer2(", \"Dev_right_rtt\": %lu", event->u.newRttMeasurement.devRtt);
        }
        if (event->u.newRttMeasurement.filtAvgRtt > 0) {
          addtobuffer2(", \"Filt_avg_right_rtt\": %lu", event->u.newRttMeasurement.filtAvgRtt);
        }
      }
    } else {
      if (event->u.newRttMeasurement.direction == spindump_direction_frominitiator) {
        addtobuffer2(", \"Full_rtt_initiator\": %lu", event->u.newRttMeasurement.rtt);
        if (event->u.newRttMeasurement.avgRtt > 0) {
          addtobuffer2(", \"Avg_full_rtt_initiator\": %lu", event->u.newRttMeasurement.avgRtt);
          addtobuffer2(", \"Dev_full_rtt_initiator\": %lu", event->u.newRttMeasurement.devRtt);
        }
        if (event->u.newRttMeasurement.filtAvgRtt > 0) {
          addtobuffer2(", \"Filt_avg_full_rtt_initiator\": %lu", event->u.newRttMeasurement.filtAvgRtt);
        }
      } else {
        addtobuffer2(", \"Full_rtt_responder\": %lu", event->u.newRttMeasurement.rtt);
        if (event->u.newRttMeasurement.avgRtt > 0) {
          addtobuffer2(", \"Avg_full_rtt_responder\": %lu", event->u.newRttMeasurement.avgRtt);
          addtobuffer2(", \"Dev_full_rtt_responder\": %lu", event->u.newRttMeasurement.devRtt);
        }
        if (event->u.newRttMeasurement.filtAvgRtt > 0) {
          addtobuffer2(", \"Filt_avg_full_rtt_responder\": %lu", event->u.newRttMeasurement.filtAvgRtt);
        }
      }
    }
    break;
    
  case spindump_event_type_spin_flip:
    addtobuffer3(", \"Transition\": \"%s\", \"Who\": \"%s\"",
                 event->u.spinFlip.spin0to1 ? "0-1" : "1-0",
                 event->u.spinFlip.direction == spindump_direction_frominitiator ? "initiator" : "responder");
    break;
    
  case spindump_event_type_spin_value:
    addtobuffer3(", \"Value\": %u, \"Who\": \"%s\"",
                 event->u.spinValue.value,
                 event->u.spinValue.direction == spindump_direction_frominitiator ? "initiator" : "responder");
    break;
    
  case spindump_event_type_ecn_congestion_event:
    addtobuffer2(", \"Who\": \"%s\"",
                 event->u.ecnCongestionEvent.direction == spindump_direction_frominitiator ? "initiator" : "responder");
    addtobuffer2(", \"Ecn0\": \"%llu\"", event->u.ecnCongestionEvent.ecn0);
    addtobuffer2(", \"Ecn1\": \"%llu\"", event->u.ecnCongestionEvent.ecn1);
    addtobuffer2(", \"Ce\": \"%llu\"", event->u.ecnCongestionEvent.ce);
    break;

  case spindump_event_type_rtloss_measurement:
    addtobuffer2(", \"Who\": \"%s\"",
                 event->u.ecnCongestionEvent.direction == spindump_direction_frominitiator ? "initiator" : "responder");  
    addtobuffer2(", \"Avg_loss\": \"%s\"", event->u.rtlossMeasurement.avgLoss);
    addtobuffer2(", \"Tot_loss\": \"%s\"", event->u.rtlossMeasurement.totLoss);
    break;

  case spindump_event_type_qrloss_measurement:
    addtobuffer2(", \"Who\": \"%s\"",
                 event->u.ecnCongestionEvent.direction == spindump_direction_frominitiator ? "initiator" : "responder");  
    addtobuffer2(", \"Q_loss\": \"%s\"", event->u.qrlossMeasurement.qLoss);
    addtobuffer2(", \"R_loss\": \"%s\"", event->u.qrlossMeasurement.rLoss);
    break;
    
  default:
    spindump_errorf("invalid event type");
  }
  
  //
  // Additional information about the connection
  //
  
  addtobuffer2(", \"Packets1\": %llu",
               event->packetsFromSide1);
  addtobuffer2(", \"Packets2\": %llu",
               event->packetsFromSide2);
  addtobuffer2(", \"Bytes1\": %llu",
               event->bytesFromSide1);
  addtobuffer2(", \"Bytes2\": %llu",
               event->bytesFromSide2);
  if (event->bandwidthFromSide1 > 0 ||
      event->bandwidthFromSide2 > 0) {
    addtobuffer2(", \"Bandwidth1\": %llu",
                 event->bandwidthFromSide1);
    addtobuffer2(", \"Bandwidth2\": %llu",
                 event->bandwidthFromSide2);
  }
  
  //
  // The end of the record
  //
  
  addtobuffer1(" }");

  //
  // Done.
  //
  
  *consumed = strlen(buffer);
  return(strlen(buffer) < length - 1);
}

static int
spindump_event_parser_json_converteventtype(const char* string,
                                            enum spindump_event_type* type) {
  spindump_assert(string != 0);
  spindump_assert(type != 0);
  if (strcasecmp("new",string) == 0) {
    *type = spindump_event_type_new_connection;
    return(1);
  } else if (strcasecmp("change",string) == 0) {
    *type = spindump_event_type_change_connection;
    return(1);
  } else if (strcasecmp("delete",string) == 0) {
    *type = spindump_event_type_connection_delete;
    return(1);
  } else if (strcasecmp("spinflip",string) == 0) {
    *type = spindump_event_type_spin_flip;
    return(1);
  } else if (strcasecmp("spin",string) == 0) {
    *type = spindump_event_type_spin_value;
    return(1);
  } else if (strcasecmp("measurement" ,string) == 0) {
    *type = spindump_event_type_new_rtt_measurement;
    return(1);
  } else if (strcasecmp("ecnce",string) == 0) {
    *type = spindump_event_type_ecn_congestion_event;
    return(1);
  } else {
    return(0);
  }
}
