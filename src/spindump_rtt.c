
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
#include "spindump_rtt.h"

//
// Actual code --------------------------------------------------------------------------------
//

//
// Initialize an RTT-tracking object
//

void
spindump_rtt_initialize(struct spindump_rtt* rtt) {
  spindump_assert(rtt != 0);
  rtt->lastRTT = spindump_rtt_infinite;
  rtt->recentTableIndex = 0;
  for (unsigned int i = 0; i < spindump_rtt_nrecent; i++) {
    rtt->recentRTTs[i] = spindump_rtt_infinite;
  }
}

//
// Provide a new measurement point
//

unsigned long
spindump_rtt_newmeasurement(struct spindump_rtt* rtt,
                            unsigned long long timediff) {
  
  //
  // Update the base measurement
  // 
  
  if (timediff > spindump_rtt_max) {
    rtt->lastRTT = spindump_rtt_max;
  } else {
    rtt->lastRTT = (unsigned long)timediff;
  }
  
  //
  // Update the table for moving average
  // 
  
  spindump_assert(rtt->recentTableIndex < spindump_rtt_nrecent);
  rtt->recentRTTs[rtt->recentTableIndex] = rtt->lastRTT;
  rtt->recentTableIndex++;
  rtt->recentTableIndex %= spindump_rtt_nrecent;
  spindump_assert(rtt->recentTableIndex < spindump_rtt_nrecent);

  return(rtt->lastRTT);
}

//
// Uninitialize the RTT tracker object
//

void
spindump_rtt_uninitialize(struct spindump_rtt* rtt) {
  spindump_assert(rtt != 0);
  // No-op// 
}

//
// Calculate the most recent moving average
// 
  
unsigned long
spindump_rtt_calculateLastMovingAvgRTT(struct spindump_rtt* rtt) {
  
  unsigned long long sum = 0;
  unsigned int n = 0;
  unsigned int i;
  
  spindump_assert(rtt != 0);
  
  for (i = 0; i < spindump_rtt_nrecent; i++) {
    unsigned long val = rtt->recentRTTs[i];
    if (val != spindump_rtt_infinite) {
      sum += (unsigned long long)val;
      n++;
    }
  }

  if (n == 0) return(spindump_rtt_infinite);
  
  unsigned long long avg = sum / (unsigned long long)n;
  unsigned long lastMovingAvgRTT;
  
  if (avg > spindump_rtt_max) {
    lastMovingAvgRTT = spindump_rtt_max;
  } else {
    lastMovingAvgRTT = (unsigned long)avg;
  }
  
  spindump_debugf("new calculated avg RTT = %lu us (n = %u)",
                  lastMovingAvgRTT, n);
  rtt->lastMovingAvgRTT = lastMovingAvgRTT;
  return(lastMovingAvgRTT);
}

//
// Create a printable string representation of an RTT value. E.g., "10
// ms". The returned buffer need not be deallocated, but it will not
// survive the next call to this same function.
//
// Note: not thread safe.
//

const char*
spindump_rtt_tostring(unsigned long rttval) {
  static char buf[50];

  if (rttval == spindump_rtt_infinite) {
    snprintf(buf,sizeof(buf)-1,"n/a");
  } else if (rttval > 60 * 1000 * 1000) {
    snprintf(buf,sizeof(buf)-1,"%.1f min", ((double)rttval) / (60.0 * 1000.0 * 1000.0));
  } else if (rttval > 1000 * 1000) {
    snprintf(buf,sizeof(buf)-1,"%.1f s", ((double)rttval) / (1000.0 * 1000.0));
  } else if (rttval > 1000) {
    snprintf(buf,sizeof(buf)-1,"%.1f ms", ((double)rttval) / 1000.0);
  } else {
    snprintf(buf,sizeof(buf)-1,"%lu us",rttval);
  }
  
  return(buf);
}
