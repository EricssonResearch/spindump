
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
  spindump_event_type_change_connection = 2,
  spindump_event_type_connection_delete = 3,
  spindump_event_type_new_rtt_measurement = 4,
  spindump_event_type_spin_flip = 5,
  spindump_event_type_spin_value = 6,
  spindump_event_type_ecn_congestion_event = 7,
  spindump_event_type_rtloss_measurement = 8,
  spindump_event_type_qrloss_measurement = 9,
  spindump_event_type_qlloss_measurement = 10,
  spindump_event_type_packet = 11
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

struct spindump_event_change_connection {
  unsigned char padding;
};

struct spindump_event_connection_delete {
  unsigned char padding;
};

struct spindump_event_packet {
  enum spindump_direction direction;
  unsigned long length;
};

struct spindump_event_new_rtt_measurement {
  enum spindump_measurement_type measurement;
  enum spindump_direction direction;
  unsigned long rtt;
  unsigned long avgRtt;
  unsigned long devRtt;
  unsigned long filtAvgRtt;
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
  spindump_counter_64bit ecn0;
  spindump_counter_64bit ecn1;
  spindump_counter_64bit ce;
};

#define spindump_lossfield_charlength 10

struct spindump_event_rtloss_measurement {
  enum spindump_direction direction;
  char avgLoss[spindump_lossfield_charlength];
  char totLoss[spindump_lossfield_charlength];
};

struct spindump_event_qrloss_measurement {
  enum spindump_direction direction;
  char avgLoss[spindump_lossfield_charlength];
  char totLoss[spindump_lossfield_charlength];
  char avgRefLoss[spindump_lossfield_charlength];
  char totRefLoss[spindump_lossfield_charlength];
};

struct spindump_event_qlloss_measurement {
  enum spindump_direction direction;
  char qLoss[spindump_lossfield_charlength];
  char lLoss[spindump_lossfield_charlength];
};

#define spindump_event_sessioidmaxlength   (18*2*2+1)
#define spindump_event_notes_maxlength     30

struct spindump_event {
  enum spindump_event_type eventType;
  enum spindump_connection_type connectionType;
  enum spindump_connection_state state;
  spindump_network initiatorAddress;
  spindump_network responderAddress;
  char session[spindump_event_sessioidmaxlength];
  unsigned long long timestamp;
  spindump_counter_64bit packetsFromSide1;
  spindump_counter_64bit packetsFromSide2;
  spindump_counter_64bit bytesFromSide1;
  spindump_counter_64bit bytesFromSide2;
  spindump_counter_64bit bandwidthFromSide1;
  spindump_counter_64bit bandwidthFromSide2;
  char notes[spindump_event_notes_maxlength];
  union {
    struct spindump_event_new_connection newConnection;
    struct spindump_event_change_connection changeConnection;
    struct spindump_event_connection_delete connectionDelete;
    struct spindump_event_packet packet;
    struct spindump_event_new_rtt_measurement newRttMeasurement;
    struct spindump_event_spin_flip spinFlip;
    struct spindump_event_spin_value spinValue;
    struct spindump_event_ecn_congestion_event ecnCongestionEvent;
    struct spindump_event_rtloss_measurement rtlossMeasurement;
    struct spindump_event_qrloss_measurement qrlossMeasurement;
    struct spindump_event_qlloss_measurement qllossMeasurement;
  } u;
};

//
// External API interface to this module ------------------------------------------------------
//

void
spindump_event_initialize(enum spindump_event_type eventType,
                          enum spindump_connection_type connectionType,
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
                          const char* notes,
                          struct spindump_event* event);
int
spindump_event_equal(const struct spindump_event* event1,
                     const struct spindump_event* event2);
const char*
spindump_event_type_tostring(enum spindump_event_type type);

#endif // SPINDUMP_EVENT_H
