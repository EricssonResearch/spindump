
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

#ifndef SPINDUMP_BANDWIDTH_H
#define SPINDUMP_BANDWIDTH_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <sys/time.h>
#include "spindump_util.h"

//
// Parameters ---------------------------------------------------------------------------------
//

#define spindump_bandwidth_period_default             (1 * 1000 * 1000) // 1M us or 1s

//
// Data structures ----------------------------------------------------------------------------
//

struct spindump_bandwidth {
  unsigned long long     period;             // measurement period in microseconds
  spindump_counter_64bit bytes;              // all bytes, ever
  spindump_counter_64bit bytesInLastPeriod;  // bytes during the last completed period
  struct timeval         thisPeriodStart;    // start of the current (uncompleted) period
  spindump_counter_64bit bytesInThisPeriod;  // bytes during the current (uncompleted) period
  unsigned int           periods;            // how many periods we've seen
};

//
// External API interface to this module ------------------------------------------------------
//

void
spindump_bandwidth_initialize(struct spindump_bandwidth* bandwidth,
                              unsigned long long period);
void
spindump_bandwidth_setcounter(struct spindump_bandwidth* bandwidth,
                              spindump_counter_64bit bytes,
                              const struct timeval* timestamp);
void
spindump_bandwidth_newpacket(struct spindump_bandwidth* bandwidth,
                             unsigned int bytes,
                             const struct timeval* timestamp);
void
spindump_bandwidth_uninitialize(struct spindump_bandwidth* bandwidth);
spindump_counter_64bit
spindump_bandwidth_periodbytes_to_bytespersec(const struct spindump_bandwidth* bandwidth);

#endif // SPINDUMP_BANDWIDTH_H
