
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "spindump_util.h"
#include "spindump_bandwidth.h"

//
// Actual code --------------------------------------------------------------------------------
//

//
// Initialize a bandwidth-tracking object
//

void
spindump_bandwidth_initialize(struct spindump_bandwidth* bandwidth) {
  spindump_assert(bandwidth != 0);
  memset(bandwidth,0,sizeof(*bandwidth));
}

//
// Provide a new measurement point
//

void
spindump_bandwidth_newpacket(struct spindump_bandwidth* bandwidth,
                             unsigned int bytes,
                             const struct timeval* timestamp) {

  //
  // Sanity checks
  //
  
  spindump_assert(bandwidth != 0);
  spindump_assert(timestamp != 0);
  
  //
  // Update the whole counter
  // 
  
  bandwidth->bytes += bytes;
  
  //
  // Update the periodic counters
  // 

  if (spindump_iszerotime(&bandwidth->thisPeriodStart)) {
    bandwidth->thisPeriodStart = *timestamp;
  }
  unsigned long long diff = spindump_timediffinusecs(timestamp,&bandwidth->thisPeriodStart);
  if (diff < spindump_bandwidth_period) {
    bandwidth->bytesInThisPeriod += bytes;
  } else {
    bandwidth->bytesInLastPeriod = bandwidth->bytesInThisPeriod;
    bandwidth->bytesInThisPeriod = bytes;
    bandwidth->thisPeriodStart = *timestamp;
    bandwidth->periods++;
  }

  //
  // If there was no previous measurement of bandwidth, copy current
  // measurement to the previous one so that it can be displayed
  //

  if (bandwidth->periods == 0) {
    bandwidth->bytesInLastPeriod = bandwidth->bytesInThisPeriod;
  }

  //
  // Debugs
  //
  
  spindump_deepdeepdebugf("bandwidth update period %u current %u last %u",
                          bandwidth->periods,
                          bandwidth->bytesInThisPeriod,
                          bandwidth->bytesInLastPeriod);
}

//
// Update the counter from an external source (e.g., another Spindump
// instance).
//

void
spindump_bandwidth_setcounter(struct spindump_bandwidth* bandwidth,
                              spindump_counter_64bit bytes,
                              const struct timeval* timestamp) {
  //
  // Sanity checks
  //
  
  spindump_assert(bandwidth != 0);
  spindump_assert(timestamp != 0);
  
  //
  // Set the whole counter
  // 
  
  bandwidth->bytes = bytes;

  //
  // Reset the rest
  //
  
  bandwidth->bytesInLastPeriod = 0;
  memset(&bandwidth->thisPeriodStart,0,sizeof(bandwidth->thisPeriodStart));
  bandwidth->bytesInThisPeriod = 0;
  
}

//
// Uninitialize the BANDWIDTH tracker object
//

void
spindump_bandwidth_uninitialize(struct spindump_bandwidth* bandwidth) {
  spindump_assert(bandwidth != 0);
  // No-op// 
}

