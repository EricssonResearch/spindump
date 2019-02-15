
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

#ifndef SPINDUMP_RTT_H
#define SPINDUMP_RTT_H

//
// Parameters ---------------------------------------------------------------------------------
//

#define spindump_rtt_nrecent 20

//
// Data structures ----------------------------------------------------------------------------
//

#define spindump_rtt_infinite 0xffffffff
#define spindump_rtt_max 0xfffffffe

struct spindump_rtt {
  unsigned long lastRTT;                     // in usecs, spindump_rtt_infinite if not set
  unsigned long lastMovingAvgRTT;            // in usecs, spindump_rtt_infinite if not set
  unsigned int recentTableIndex;             // where the next recent RTT measurement will
					     //	be placed in
  unsigned int padding;                      // unused padding to align the next field properly
  unsigned long
    recentRTTs[spindump_rtt_nrecent];        // recent RTT measurements, in usec. Value 
					     //	positions via above index.
};

//
// External API interface to this module ------------------------------------------------------
//

void
spindump_rtt_initialize(struct spindump_rtt* rtt);
unsigned long
spindump_rtt_newmeasurement(struct spindump_rtt* rtt,
			    unsigned long long timediff);
unsigned long
spindump_rtt_calculateLastMovingAvgRTT(struct spindump_rtt* rtt);
const char*
spindump_rtt_tostring(unsigned long rttval);
void
spindump_rtt_uninitialize(struct spindump_rtt* rtt);

#endif // SPINDUMP_RTT_H
