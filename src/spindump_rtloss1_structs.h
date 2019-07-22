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
  uint32_t currentCounter;
  uint32_t previousCounter;
  struct timeval lastLossTime;
  // Stats fields
  uint32_t markedPktCounter;
  uint32_t generatedPktCounter;
  uint32_t reflectedPktCounter;
  uint32_t lostPackets;
  struct spindump_rtloss1stats lossStats;
};

#endif