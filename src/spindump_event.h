
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

#ifndef SPINDUMP_EVENT_H
#define SPINDUMP_EVENT_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <stdio.h>
#include "spindump_util.h"
#include "spindump_connections_structs.h"

//
// Data types ---------------------------------------------------------------------------------
//

enum spindump_event_type {
  spindump_event_type_new_connection = 1,
  spindump_event_type_connection_delete = 2,
  spindump_event_type_new_rtt_measurement = 3,
  spindump_event_type_spin_flip = 4,
  spindump_event_type_spin_value = 5,
  spindump_event_type_ecn_congestion_event = 6
};

enum spindump_direction {
  spindump_direction_frominitiator = 0,
  spindump_direction_fromresponder = 1
};

enum spindump_measurement_type {
  spindump_measurement_type_unidirectional = 0,
  spindump_measurement_type_bidirectional = 1
};

//
// Parameters ---------------------------------------------------------------------------------
//

//
// Data structures ----------------------------------------------------------------------------
//

struct spindump_event_new_connection {
  unsigned char padding;
};

struct spindump_event_connection_delete {
  unsigned char padding;
};

struct spindump_event_new_rtt_measurement {
  enum spindump_measurement_type measurement;
  enum spindump_direction direction;
  unsigned long rtt;
};

struct spindump_event_spin_flip {
  enum spindump_direction direction;
  int spin0to1;
};

struct spindump_event_spin_value {
  enum spindump_direction direction;
  unsigned char value;
};

struct spindump_event_ecn_congestion_event {
  enum spindump_direction direction;
};

#define spindump_event_sessioidmaxlength   (18*2*2+1)

struct spindump_event {
  enum spindump_event_type eventType;
  enum spindump_connection_type connectionType;
  spindump_network initiatorAddress;
  spindump_network responderAddress;
  char session[spindump_event_sessioidmaxlength];
  unsigned long long timestamp;
  unsigned int packets;
  unsigned int bytes;
  union {
    struct spindump_event_new_connection newConnection;
    struct spindump_event_connection_delete connectionDelete;
    struct spindump_event_new_rtt_measurement newRttMeasurement;
    struct spindump_event_spin_flip spinFlip;
    struct spindump_event_spin_value spinValue;
    struct spindump_event_ecn_congestion_event ecnCongestionEvent;
  } u;
};

//
// External API interface to this module ------------------------------------------------------
//

void
spindump_event_initialize(enum spindump_event_type eventType,
			  enum spindump_connection_type connectionType,
			  const spindump_network* initiatorAddress,
			  const spindump_network* responderAddress,
			  const char* session,
			  unsigned long long timestamp,
			  unsigned int packets,
			  unsigned int bytes,
			  struct spindump_event* event);
const char*
spindump_event_type_tostring(enum spindump_event_type type);

#endif // SPINDUMP_EVENT_H
