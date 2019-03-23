
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

//
// Actual code --------------------------------------------------------------------------------
//

void
spindump_event_initialize(enum spindump_event_type eventType,
			  enum spindump_connection_type connectionType,
			  const spindump_network* initiatorAddress,
			  const spindump_network* responderAddress,
			  const char* session,
			  unsigned long long timestamp,
			  struct spindump_event* event) {

  //
  // Sanity checks
  //
  
  spindump_assert(initiatorAddress != 0);
  spindump_assert(responderAddress != 0);
  spindump_assert(session != 0);
  spindump_assert(strlen(session) < spindump_event_sessioidmaxlength);
  spindump_assert(event != 0);
  memset(event,0,sizeof(*event));
  event->eventType = eventType;
  event->connectionType = connectionType;
  event->initiatorAddress = *initiatorAddress;
  event->responderAddress = *responderAddress;
  strncpy(&event->session[0],session,sizeof(event->session));
  event->timestamp = timestamp;
}

const char*
spindump_event_type_tostring(enum spindump_event_type type) {
  switch (type) {
  case spindump_event_type_new_connection: return("new");
  case spindump_event_type_connection_delete: return("delete");
  case spindump_event_type_new_rtt_measurement: return("measurement");
  case spindump_event_type_spin_flip: return("spinflip");
  case spindump_event_type_spin_value: return("spinvalue");
  case spindump_event_type_ecn_congestion_event: return("ecnce");
  default:
    spindump_errorf("invalid event type");
    return("UNKNOWN");
  }
}

