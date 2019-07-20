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

#include <stdlib.h>
#include "spindump_rtloss1.h"


void
spindump_rtloss1tracker_observeandcalculateloss(struct spindump_analyze* state,
                                                struct spindump_packet* packet,
                                                struct spindump_connection* connection,
                                                struct timeval* ts,
                                                int fromResponder,
                                                int lossbit,
                                                int isFlip) {
  struct spindump_rtloss1tracker* tracker;
  if (fromResponder)
    tracker = &connection->u.quic.rtloss1FromPeer2to1;
  else
    tracker = &connection->u.quic.rtloss1FromPeer1to2;
  if (isFlip) {
    if (tracker->isLastSpinPeriodEmpty) {

      if (tracker->currentCounter > 0) {

        if (tracker->reflectionPhase) {

          if (tracker->previousCounter < tracker->currentCounter) {
            tracker->lostPackets += tracker->previousCounter;
            /*
             * signal a new loss measurement
             * GEN:  tracker->previousCounter
             * RFL:  0
             * LOST: tracker->previousCounter
             */
            // realign phases
            if (tracker->previousCounter > 0)
              tracker->reflectionPhase = 0;
              
          } 
          else {
            uint32_t losses = tracker->previousCounter - tracker->currentCounter;
            tracker->lostPackets += losses;
            tracker->generatedPktCounter += tracker->previousCounter;
            tracker->reflectedPktCounter += tracker->currentCounter;
            /*
             * signal a new loss measurement
             * GEN:  tracker->previousCounter
             * RFL:  losses
             * LOST: tracker->currentCounter
             */
          }
        }
        tracker->previousCounter = tracker->currentCounter;
        tracker->currentCounter = 0;
        tracker->reflectionPhase = !tracker->reflectionPhase;
      }
    }
    else {
      tracker->isLastSpinPeriodEmpty = 1;
    }
  }
  
  if (lossbit) {
    tracker->markedPktCounter++;
    tracker->currentCounter++;
    tracker->lastLossTime = *ts;
    tracker->isLastSpinPeriodEmpty = 0;
  }
}


//
// Initialize the loss tracker object
//
void
spindump_rtloss1tracker_initialize(struct spindump_rtloss1tracker* tracker) {
  spindump_assert(tracker != 0);
  memset(tracker,0,sizeof(*tracker));
}

//
// Uninitialize the loss tracker object
//
void
spindump_rtloss1tracker_uninitialize(struct spindump_rtloss1tracker* tracker) {
  spindump_assert(tracker != 0);
  // no-op//
} 