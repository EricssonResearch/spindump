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

#ifndef SPINDUMP_RTLOSS1_STRUCTS_H
#define SPINDUMP_RTLOSS1_STRUCTS_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <stdint.h>
#include <time.h>
#include "spindump_util.h"

//
// Parameters ---------------------------------------------------------------------------------
//

#define spindump_rtloss1_n       10
#define spindump_rtloss1_maxrate 1.0

//
// Data Structures ----------------------------------------------------------------------------
//

struct spindump_rtloss1 {
  float averageLossRate;
  float totalLossRate;
};

struct spindump_rtloss1stats {
  struct spindump_rtloss1 rates;
  float recentLossRates[spindump_rtloss1_n];
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
  struct spindump_rtloss1stats lossStats;
};

#endif