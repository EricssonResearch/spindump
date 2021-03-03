
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
#include "spindump_event_printer_json.h"
#include "spindump_connections.h"
#include "spindump_json.h"
#include "spindump_json_value.h"

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
spindump_event_printer_json_print(const struct spindump_event* event,
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
  if (event->tags.string[0] != 0) {
    addtobuffer2(", \"Tags\": \"%s\"", event->tags.string);
  }
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
          addtobuffer2(", \"Avg_left_rtt\": %lu", event->u.newRttMeasurement.avgRtt);
          addtobuffer2(", \"Dev_left_rtt\": %lu", event->u.newRttMeasurement.devRtt);
        }
        if (event->u.newRttMeasurement.filtAvgRtt > 0) {
          addtobuffer2(", \"Filt_avg_left_rtt\": %lu", event->u.newRttMeasurement.filtAvgRtt);
        }
       if (event->u.newRttMeasurement.minRtt > 0) {
          addtobuffer2(", \"Min_left_rtt\": %lu", event->u.newRttMeasurement.minRtt);
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
       if (event->u.newRttMeasurement.minRtt > 0) {
          addtobuffer2(", \"Min_right_rtt\": %lu", event->u.newRttMeasurement.minRtt);
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
       if (event->u.newRttMeasurement.minRtt > 0) {
          addtobuffer2(", \"Min_full_rtt_initiator\": %lu", event->u.newRttMeasurement.minRtt);
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
       if (event->u.newRttMeasurement.minRtt > 0) {
          addtobuffer2(", \"Min_full_rtt_responder\": %lu", event->u.newRttMeasurement.minRtt);
       }
      }
    }
    break;
    
  case spindump_event_type_periodic:
    if (event->u.periodic.rttRight != spindump_rtt_infinite) {
      addtobuffer2(", \"Right_rtt\": %lu", event->u.periodic.rttRight);
      if (event->u.periodic.avgRttRight > 0) {
        addtobuffer2(", \"Avg_right_rtt\": %lu", event->u.periodic.avgRttRight);
        addtobuffer2(", \"Dev_right_rtt\": %lu", event->u.periodic.devRttRight);
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
    addtobuffer2(", \"Avg_loss\": \"%s\"", event->u.qrlossMeasurement.avgLoss);
    addtobuffer2(", \"Tot_loss\": \"%s\"", event->u.qrlossMeasurement.totLoss);
    break;

  case spindump_event_type_qlloss_measurement:
    addtobuffer2(", \"Who\": \"%s\"",
                 event->u.ecnCongestionEvent.direction == spindump_direction_frominitiator ? "initiator" : "responder");  
    addtobuffer2(", \"Q_loss\": \"%s\"", event->u.qllossMeasurement.qLoss);
    addtobuffer2(", \"R_loss\": \"%s\"", event->u.qllossMeasurement.lLoss);
    break;
    
  case spindump_event_type_packet:
    addtobuffer2(", \"Dir\": \"%s\"",
                 event->u.packet.direction == spindump_direction_frominitiator ? "initiator" : "responder");
    addtobuffer2(", \"Length\": %lu", event->u.packet.length);
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
