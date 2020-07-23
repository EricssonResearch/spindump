
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

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "spindump_util.h"
#include "spindump_rtt.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static int
spindump_rtt_valuewithinlimits(unsigned long val,
                               unsigned int n,
                               struct spindump_rtt* rtt,
                               unsigned int filterLimitPercentage);

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
  rtt->lastMovingAvgRTT = spindump_rtt_infinite;
  rtt->lastStandardDeviation = spindump_rtt_infinite;
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
  // Sanity checks and normalization
  // 
  
  if (timediff > spindump_rtt_max) {
    timediff = spindump_rtt_max;
  } else {
    timediff = (unsigned long)timediff;
  }

  //
  // Update the base measurement
  // 
  
  rtt->lastRTT = (unsigned long)timediff;

  //
  // Update the RTT histogram
  //

  spindump_rtt_update_histogram(rtt);

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

static int
spindump_rtt_valuewithinlimits(unsigned long val,
                               unsigned int n,
                               struct spindump_rtt* rtt,
                               unsigned int filterLimitPercentage) {
  spindump_deepdeepdebugf("filter check val %lu percentage = %u avg %lu dev %lu n %u",
                          val,
                          filterLimitPercentage,
                          rtt->lastMovingAvgRTT,
                          rtt->lastStandardDeviation,
                          n);
  if (rtt->lastMovingAvgRTT == spindump_rtt_infinite) {
    spindump_deepdeepdebugf("filter exception 1");
    return(1);
  }
  if (rtt->lastStandardDeviation == spindump_rtt_infinite) {
    spindump_deepdeepdebugf("filter exception 2");
    return(1);
  }
  if (n < spindump_rtt_nminfilter) {
    spindump_deepdeepdebugf("filter exception 3: %u", n);
    return(1);
  }
  unsigned long limitdiff =
    (filterLimitPercentage * rtt->lastStandardDeviation) / 100;
  unsigned long lowerlimit =
    rtt->lastMovingAvgRTT > limitdiff ? rtt->lastMovingAvgRTT - limitdiff : 0;
  unsigned long upperlimit =
    (rtt->lastMovingAvgRTT + limitdiff >= rtt->lastMovingAvgRTT) ? rtt->lastMovingAvgRTT + limitdiff : spindump_rtt_max;
  spindump_deepdeepdebugf("filter value %lu limitdiff %lu to within %lu..%lu", val, limitdiff, lowerlimit, upperlimit);
  if (val < lowerlimit) {
    spindump_deepdeepdebugf("filter away, too low");
    return(0);
  }
  if (val > upperlimit) {
    spindump_deepdeepdebugf("filter away, too high");
    return(0);
  }
  return(1);
}

//
// Calculate the most recent moving average. Returns the average.
// Input parameters are the RTT structure and filter flag if filtering
// should be performed, and if so, what percentage of standard
// deviation is considered exceptional. Output parameters are the
// standard deviation and filtered average.
// 
  
unsigned long
spindump_rtt_calculateLastMovingAvgRTT(struct spindump_rtt* rtt,
                                       int filter,
                                       unsigned int filterLimitPercentage,
                                       unsigned long* standardDeviation,
                                       unsigned long* filteredAvg) {
  
  unsigned long long sum = 0;
  unsigned long long devSum = 0;
  unsigned int n = 0;
  unsigned int i;

  //
  // Sanity checks
  //
  
  spindump_assert(rtt != 0);
  spindump_assert(spindump_isbool(filter));
  spindump_assert(standardDeviation != 0);
  spindump_assert(filteredAvg != 0);
  
  //
  // Calculate basic moving average
  //
  
  for (i = 0; i < spindump_rtt_nrecent; i++) {
    unsigned long val = rtt->recentRTTs[i];
    if (val != spindump_rtt_infinite) {
      sum += (unsigned long long)val;
      n++;
    }
  }
  
  if (n == 0) {
    *standardDeviation = 0;
    if (!filter) {
      rtt->lastStandardDeviation = spindump_rtt_infinite;
      rtt->lastMovingAvgRTT = spindump_rtt_infinite;
    }
    return(spindump_rtt_infinite);
  }
  
  unsigned long long avg = sum / (unsigned long long)n;
  
  //
  // Calculate standard deviation
  //

  unsigned long dev = 0;
  if (n > 1) {
    for (i = 0; i < spindump_rtt_nrecent; i++) {
      unsigned long long val = (unsigned long long)(rtt->recentRTTs[i]);
      if (val != spindump_rtt_infinite) {
        unsigned long long diff = val > avg ? val - avg : avg - val;
        devSum += (diff * diff);
        spindump_deepdeepdebugf("standard deviation val %llu avg %llu diff %llu sqrt %llu",
                                val, avg, diff, diff * diff);
      }
    }
    double realResult = floor(sqrt((1.0/(n-1))*(double)devSum));
    dev = (unsigned long)realResult;
    spindump_deepdeepdebugf("standard deviation n = %u avg = %llu devSum = %llu ", n, avg, devSum);
  } else {
    dev = 0;
  }
  
  //
  // Calculate filtered moving average
  //

  unsigned int fn = 0;
  unsigned long long fsum = 0;
  
  if (filter) {

    for (i = 0; i < spindump_rtt_nrecent; i++) {
      unsigned long val = rtt->recentRTTs[i];
      if (val != spindump_rtt_infinite &&
          (filter == 0 ||
           spindump_rtt_valuewithinlimits(val,n,rtt,filterLimitPercentage))) {
        fsum += (unsigned long long)val;
        fn++;
      }
    }
    
  } else {
    fsum = sum;
    fn = n;
  }
  
  unsigned long long favg = fn > 0 ? fsum / (unsigned long long)fn : 0;
  
  //
  // Determine if the value is within limits
  //
  
  if (avg > spindump_rtt_max) {
    avg = spindump_rtt_max;
  }
  if (dev > spindump_rtt_max) {
    dev = spindump_rtt_max;
  }
  if (favg > spindump_rtt_max) {
    favg = spindump_rtt_max;
  }
  
  //
  // Set output parameters and permanently stored values if needed
  //
  
  *standardDeviation = dev;
  *filteredAvg = favg;
  rtt->lastMovingAvgRTT = avg;
  rtt->lastStandardDeviation = dev;
  
  //
  // Return
  //
  
  spindump_debugf("new calculated avg RTT = %lu us (n = %u, std. dev. = %lu)",
                  (unsigned long)avg, n, (unsigned long)dev);
  return((unsigned long)avg);
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


//
// This function update the RTT histogram
// based on the rtt->lastRTT value
//
// There are 6 levels of delay intervals in this histogram
// level 0: 0, 100, 200 ... 900us
// level 1: 1, 2, 3 ... 9ms
// level 2: 10, 20, 30 ... 90ms
// level 3: 100, 200, 300 .. 900ms
// level 4: 1, 2, 3 ... 9s
// level 5: 10, 20, 30 ... 60s
//
void
spindump_rtt_update_histogram(struct spindump_rtt* rtt) {
  unsigned long long rttval = rtt->lastRTT;
  unsigned int bin_idx = 6;
  unsigned int level = 5;

  if (rttval < 1000) { //1ms
    level = 0;
    bin_idx = (int)((double) rttval / 100.0);
  } else if (rttval < 10 * 1000) { //10ms
    level = 1;
    bin_idx = (int)((double) rttval / 1000.0);
  } else if (rttval < 100 * 1000) { //100ms
    level = 2;
    bin_idx = (int)((double) rttval / (10.0 * 1000.0));
  } else if (rttval < 1000 * 1000) { //1s
    level = 3;
    bin_idx = (int)((double) rttval / (100.0 * 1000.0));
  } else if (rttval < 10 * 1000 * 1000) { //10s
    level = 4;
    bin_idx = (int)((double) rttval / (1000.0 * 1000.0));
  } else {
    bin_idx = (int)((double) rttval / (10.0 * 1000.0 * 1000.0));
  }

  rtt->rttHisto[level][bin_idx]++;
}
