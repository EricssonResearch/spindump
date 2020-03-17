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
//  AUTHOR: FABIO BULGARELLA
//
//

#ifndef SPINDUMP_TITALIA_QRLOSS_STRUCTS_H
#define SPINDUMP_TITALIA_QRLOSS_STRUCTS_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <stdint.h>
#include <time.h>
#include "spindump_util.h"

//
// Parameters ---------------------------------------------------------------------------------
//

#define spindump_qrloss_qperiod             64
#define spindump_qrloss_3x_qperiod          192
#define spindump_qrloss_n                   10
#define spindump_qrloss_maxrate             1.0f
#define spindump_qrloss_reorder_threshold   10

//
// Data Structures ----------------------------------------------------------------------------
//

struct spindump_qrloss {
  float averageLossRate;
  float totalLossRate;
  float averageRefLossRate;
  float totalRefLossRate;
};

struct spindump_qrloss_stats {
  float recentLossRates[spindump_qrloss_n];
  int currentIndex;
};

struct spindump_qrlosstracker {
  int currentSquareBit;
  spindump_counter_32bit squarePktCounter;
  spindump_counter_32bit holdingSquarePktCounter;
  //struct timeval lastSquareTime;

  int currentRefSquareBit;
  spindump_counter_32bit refSquarePktCounter;
  spindump_counter_32bit holdingRefSquarePktCounter;
  //struct timeval lastRefSquareTime;

  // Stats fields
  int refSquareStarting;
  spindump_counter_32bit totSquarePkts;
  spindump_counter_32bit totRefSquarePkts;
  spindump_counter_32bit lostPackets;
  spindump_counter_32bit refLostPackets;
  struct spindump_qrloss_stats lossStats;
  struct spindump_qrloss_stats refLossStats;
};

#endif
