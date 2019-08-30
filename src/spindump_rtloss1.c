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
#include "spindump_analyze.h"

//
// Function Prototypes
//

void 
spindump_rtloss1_setaveragelossrate(struct spindump_rtloss1stats* lossStats);

//
// Actual Code
//

void
spindump_rtloss1tracker_observeandcalculateloss(struct spindump_analyze* state,
                                                struct spindump_packet* packet,
                                                struct spindump_connection* connection,
                                                struct timeval* ts,
                                                int fromResponder,
                                                int lossbit,
                                                int isFlip) {
  struct spindump_rtloss1tracker* tracker;
  if (fromResponder) {
    tracker = &connection->u.quic.rtloss1FromPeer2to1;
  }
  else {
    tracker = &connection->u.quic.rtloss1FromPeer1to2;
  }
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
            tracker->lossStats.rates.totalLossRate = (float)(tracker->lostPackets) / tracker->markedPktCounter;
            

            // realign phases
            if (tracker->previousCounter > 0) {
              tracker->reflectionPhase = 0;
            }
              
          } else {
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
            
            //
            // Calculate loss rates and update connection statistics
            //

            tracker->lossStats.recentLossRates[tracker->lossStats.currentIndex++] = (float)losses / tracker->previousCounter;
            tracker->lossStats.currentIndex %= spindump_rtloss1_n;
            tracker->lossStats.rates.totalLossRate = (float)(tracker->lostPackets) / tracker->generatedPktCounter;
            spindump_rtloss1_setaveragelossrate(&tracker->lossStats);

            if (fromResponder) {
              connection->rtLossesFrom2to1 = tracker->lossStats.rates;
            } else {
              connection->rtLossesFrom1to2 = tracker->lossStats.rates; 
            }

            // Call handlers if any

            spindump_analyze_process_handlers(state,
                                              fromResponder ? spindump_analyze_event_responderrtloss1measurement
                                              : spindump_analyze_event_initiatorrtloss1measurement,
                                              packet,
                                              connection);  
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

void
spindump_rtloss1_setaveragelossrate(struct spindump_rtloss1stats* lossStats) {
  
  int n = 0;
  float sum = 0;

  for (int i = 0; i < spindump_rtloss1_n; ++i) {
    float rr = lossStats->recentLossRates[i];
    if (((double)rr) < (double)spindump_rtloss1_maxrate) {
      sum += rr;
      ++n;
    }    
  }
  lossStats->rates.averageLossRate = sum / n;
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
