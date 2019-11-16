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
//  SPINDUMP (C) 2019 BY ERICSSON RESEARCH
//  AUTHOR: MARCUS IHLAR AND FABIO BULGARELLA
//
//

#ifndef SPINDUMP_RTLOSS_STRUCTS_H
#define SPINDUMP_RTLOSS_STRUCTS_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <stdint.h>
#include <time.h>
#include "spindump_util.h"

//
// Parameters ---------------------------------------------------------------------------------
//

#define spindump_rtloss_n                   10
#define spindump_rtloss_maxrate             1.0
#define spindump_rtloss2_reorder_threshold  10000    // 10ms

//
// Data Structures ----------------------------------------------------------------------------
//

struct spindump_rtloss {
  float averageLossRate;
  float totalLossRate;
};

struct spindump_rtloss_stats {
  struct spindump_rtloss rates;
  float recentLossRates[spindump_rtloss_n];
  int currentIndex;
};

struct spindump_rtloss1tracker {
  int reflectionPhase;
  int isLastSpinPeriodEmpty;
  spindump_counter_32bit currentCounter;
  spindump_counter_32bit previousCounter;
  struct timeval lastLossTime;
  // Stats fields
  spindump_counter_32bit markedPktCounter;
  spindump_counter_32bit generatedPktCounter;
  spindump_counter_32bit reflectedPktCounter;
  spindump_counter_32bit lostPackets;
  struct spindump_rtloss_stats lossStats;
};

struct spindump_rtloss2tracker {
    int reflectionPhase;
    spindump_counter_32bit tmpGenCounter;
    spindump_counter_32bit genCounter;
    spindump_counter_32bit rflCounter;
    unsigned long long lockCounterTime;
    struct timeval lastRflTime;
    // Stats fields
    spindump_counter_32bit markedPktCounter;
    spindump_counter_32bit generatedPktCounter;
    spindump_counter_32bit reflectedPktCounter;
    spindump_counter_32bit lostPackets;
    struct spindump_rtloss_stats lossStats;
};

#endif
