
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
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include "spindump_util.h"
#include "spindump_event.h"
#include "spindump_event_parser_text.h"
#include "spindump_connections.h"

//
// Actual code --------------------------------------------------------------------------------
//

//
// Take a buffer of data in "buffer" (whose length is given in
// "length") and parse it as a textual event description from
// Spindump, placing the result in the output parqmeter "event".
//
// If successful, return 1, upon no non-whitespace input to read in
// the buffer, return 0 for EOF, and upon parsing error return -1.
//
// In any case, set the output parameter "consumed" to the number of
// bytes consumed from the buffer.
//

int
spindump_event_parser_text_parse(const char* buffer,
                                 size_t length,
                                 struct spindump_event* event,
                                 size_t* consumed) {
  return(0); // ...
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
spindump_event_parser_text_print(const struct spindump_event* event,
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
  
#define addtobuffer1(x)       snprintf(buffer + strlen(buffer),length - 1 - strlen(buffer),x)
#define addtobuffer2(x,y)     snprintf(buffer + strlen(buffer),length - 1 - strlen(buffer),x,y)
#define addtobuffer3(x,y,z)   snprintf(buffer + strlen(buffer),length - 1 - strlen(buffer),x,y,z)
#define addtobuffer4(x,y,z,v) snprintf(buffer + strlen(buffer),length - 1 - strlen(buffer),x,y,z,v)

  //
  // Basic information about the connection
  //
  
  addtobuffer2("%s ",
               spindump_connection_type_to_string(event->connectionType));
  addtobuffer2("%s <-> ",
               spindump_network_tostringoraddr(&event->initiatorAddress));
  addtobuffer2("%s ",
               spindump_network_tostringoraddr(&event->responderAddress));
  addtobuffer2("%s ",
               event->session);
  addtobuffer2("at %llu ",
               event->timestamp);
  addtobuffer2("%s ",
               spindump_event_type_tostring(event->eventType));
  const char* stateString = spindump_connection_statestring_plain(event->state);
  spindump_assert(stateString != 0);
  spindump_assert(strlen(stateString) > 0);
  addtobuffer3("%c%s ",
               tolower(*stateString),
               stateString + 1);
  
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
        addtobuffer2("left %lu ", event->u.newRttMeasurement.rtt);
      } else {
        addtobuffer2("right %lu ", event->u.newRttMeasurement.rtt);
      }
    } else {
      if (event->u.newRttMeasurement.direction == spindump_direction_frominitiator) {
        addtobuffer2("full (initiator) %lu ", event->u.newRttMeasurement.rtt);
      } else {
        addtobuffer2("full (responder) %lu ", event->u.newRttMeasurement.rtt);
      }
    }
    if (event->u.newRttMeasurement.avgRtt > 0) {
      addtobuffer2("avg %lu ", event->u.newRttMeasurement.avgRtt);
    }
    break;
    
  case spindump_event_type_spin_flip:
    addtobuffer3("%s %s ",
                 event->u.spinFlip.spin0to1 ? "0-1" : "1-0",
                 event->u.spinFlip.direction == spindump_direction_frominitiator ? "initiator" : "responder");
    break;
    
  case spindump_event_type_spin_value:
    addtobuffer3("%u %s ",
                 event->u.spinValue.value,
                 event->u.spinValue.direction == spindump_direction_frominitiator ? "initiator" : "responder");
    break;
    
  case spindump_event_type_ecn_congestion_event:
    addtobuffer2("%s ",
                 event->u.ecnCongestionEvent.direction == spindump_direction_frominitiator ? "initiator" : "responder");
    break;

  case spindump_event_type_rtloss_measurement:
    if (event->u.rtlossMeasurement.direction == spindump_direction_frominitiator) {
      addtobuffer3("Moving avg loss %s, Session avg loss %s (initiator) ",
                   event->u.rtlossMeasurement.avgLoss,
                   event->u.rtlossMeasurement.totLoss);
    } else {
      addtobuffer3("Moving avg loss %s, Session avg loss %s (responder) ",
                   event->u.rtlossMeasurement.avgLoss,
                   event->u.rtlossMeasurement.totLoss);
    }
    break;

  case spindump_event_type_qrloss_measurement:
    if (event->u.qrlossMeasurement.direction == spindump_direction_frominitiator) {
      addtobuffer3("Upstream loss %s, E2E loss %s (initiator) ",
                   event->u.qrlossMeasurement.qLoss,
                   event->u.qrlossMeasurement.rLoss);  
    } else {
      addtobuffer3("Upstream loss %s, E2E loss %s (responder) ",
                   event->u.qrlossMeasurement.qLoss,
                   event->u.qrlossMeasurement.rLoss); 
    }
    break;
    
  default:
    spindump_errorf("invalid event type");
  }
  
  //
  // Additional information about the connection
  //
  
  addtobuffer3("packets %llu %llu ",
               event->packetsFromSide1,
               event->packetsFromSide2);
  addtobuffer3("bytes %llu %llu",
               event->bytesFromSide1,
               event->bytesFromSide2);
  if (event->bandwidthFromSide1 > 0 ||
      event->bandwidthFromSide2 > 0) {
    addtobuffer3(" bandwidth %llu %llu",
                 event->bandwidthFromSide1,
                 event->bandwidthFromSide2);
  }
  
  //
  // Notes, if so desired
  //

  if (event->notes[0] != 0) {
    addtobuffer4(" note %c%s%c", 34, event->notes, 34);
  }
  
  //
  // The end of the record
  //
  
  addtobuffer1("\n");

  //
  // Done.
  //
  
  *consumed = strlen(buffer);
  return(strlen(buffer) < length - 1);
}
