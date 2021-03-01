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
#include "spindump_titalia_rtloss.h"
#include "spindump_analyze.h"

//
// Function Prototypes
//

void 
spindump_rtloss_setaveragelossrate(struct spindump_rtloss_stats* lossStats);

//
// Actual Code
//

//
// Compute the loss value (single bit version) and produce a new loss
// measurement if the reflection phase is considered ended
//

void
spindump_rtloss1tracker_observeandcalculateloss(struct spindump_analyze* state,
                                                struct spindump_packet* packet,
                                                struct spindump_connection* connection,
                                                struct timeval* ts,
                                                int fromResponder,
                                                unsigned int ipPacketLength,
                                                spindump_extrameas_int extrameasbits,
                                                int isFlip) {  
  //
  // Get lossbit
  //

  uint8_t lossbit = extrameasbits & spindump_extrameas_rtloss1;

  //
  // Get tracker
  //
  
  struct spindump_rtloss1tracker* tracker;
  if (fromResponder) tracker = &connection->u.quic.rtloss1FromPeer2to1;
  else tracker = &connection->u.quic.rtloss1FromPeer1to2;

  //
  // Compute round trip loss
  //

  if (isFlip) {
    if (tracker->isLastSpinPeriodEmpty) {

      if (tracker->currentCounter > 0) {

        if (tracker->reflectionPhase) {

          if (tracker->previousCounter < tracker->currentCounter) {

            //TODO: introduce check done in TelecomItalia observer to limit errors
            // when considering this packets as completely lost
            tracker->lostPackets += tracker->previousCounter;
            tracker->lossStats.rates.totalLossRate = (float)(tracker->lostPackets) / tracker->markedPktCounter;
            
            //
            // Realign Phases in case currentCounter is greater than previousCounter.
            // This means that more reflected than generated packets have been counted.
            //

            tracker->reflectionPhase = 0;
              
          } else {

            uint32_t losses = tracker->previousCounter - tracker->currentCounter;
            tracker->lostPackets += losses;
            tracker->generatedPktCounter += tracker->previousCounter;
            tracker->reflectedPktCounter += tracker->currentCounter;
            
            //
            // Calculate loss rates and update connection statistics
            //

            tracker->lossStats.recentLossRates[tracker->lossStats.currentIndex++] = (float)losses / tracker->previousCounter;
            tracker->lossStats.currentIndex %= spindump_rtloss_n;
            tracker->lossStats.rates.totalLossRate = (float)(tracker->lostPackets) / tracker->generatedPktCounter;
            spindump_rtloss_setaveragelossrate(&tracker->lossStats);

            if (fromResponder) {
              connection->rtLossesFrom2to1 = tracker->lossStats.rates;
            } else {
              connection->rtLossesFrom1to2 = tracker->lossStats.rates; 
            }

            // Call handlers if any

            spindump_analyze_process_handlers(state,
                                              (fromResponder ?
                                               spindump_analyze_event_responderrtlossmeasurement :
                                               spindump_analyze_event_initiatorrtlossmeasurement),
                                              ts,
                                              fromResponder,
                                              ipPacketLength,
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

//
// Compute the loss value (2 bits version) and produce a new loss
// measurement if the reflection phase is considered ended
//

void
spindump_rtloss2tracker_observeandcalculateloss(struct spindump_analyze *state,
                                                struct spindump_packet *packet,
                                                struct spindump_connection *connection,
                                                struct timeval *ts,
                                                int fromResponder,
                                                unsigned int ipPacketLength,
                                                spindump_extrameas_int extrameasbits) {
  //
  // Get lossbits
  //

  uint8_t lossbits = (extrameasbits & (spindump_extrameas_rtloss2_bit1 | spindump_extrameas_rtloss2_bit2)) >> 2;

  //
  // Get tracker
  //

  struct spindump_rtloss2tracker *tracker;
  if (fromResponder) tracker = &connection->u.quic.rtloss2FromPeer2to1;
  else tracker = &connection->u.quic.rtloss2FromPeer1to2;
  tracker->markedPktCounter++;

  //
  // Compute loss rate
  //
  
  unsigned long long timestamp;
  spindump_timeval_to_timestamp(ts, &timestamp);

  if (lossbits == 1) {
    if (tracker->reflectionPhase && timestamp > tracker->lockCounterTime) {
      tracker->reflectionPhase = 0;
      tracker->genCounter = tracker->tmpGenCounter;
      tracker->tmpGenCounter = 0;
      tracker->lockCounterTime = timestamp + spindump_rtloss2_reorder_threshold;
    }
    tracker->tmpGenCounter++;

  } else if (lossbits == 2) {
    if (!tracker->reflectionPhase && timestamp > tracker->lockCounterTime) {
      if (tracker->rflCounter > tracker->genCounter) {

        // Error during counters processing, skipping measurement

        spindump_warnf("rtloss2 rflCounter (%u) is greater than genCounter (%u), triggered at %lu (usec)",
                       tracker->rflCounter,
                       tracker->genCounter,
                       tracker->lastRflTime.tv_usec);

      } else if (tracker->genCounter > 0) {
        uint32_t losses = tracker->genCounter - tracker->rflCounter;
        tracker->lostPackets += losses;
        tracker->generatedPktCounter += tracker->genCounter;
        tracker->reflectedPktCounter += tracker->rflCounter;

        //
        // Calculate loss rates and update connection statistics
        //

        tracker->lossStats.recentLossRates[tracker->lossStats.currentIndex++] = (float) losses / tracker->genCounter;
        tracker->lossStats.currentIndex %= spindump_rtloss_n;
        tracker->lossStats.rates.totalLossRate = (float) (tracker->lostPackets) / tracker->generatedPktCounter;
        spindump_rtloss_setaveragelossrate(&tracker->lossStats);

        if (fromResponder) {
          connection->rtLossesFrom2to1 = tracker->lossStats.rates;
        } else {
          connection->rtLossesFrom1to2 = tracker->lossStats.rates;
        }

        // Call handlers if any

        spindump_analyze_process_handlers(state,
                                          (fromResponder ?
                                           spindump_analyze_event_responderrtlossmeasurement :
                                           spindump_analyze_event_initiatorrtlossmeasurement),
                                          ts,
                                          fromResponder,
                                          ipPacketLength,
                                          packet,
                                          connection);
      }

      tracker->reflectionPhase = 1;
      tracker->rflCounter = 0;
      tracker->lockCounterTime = timestamp + spindump_rtloss2_reorder_threshold;
    }

    tracker->rflCounter++;
    tracker->lastRflTime = *ts;
  }
}

void
spindump_rtloss_setaveragelossrate(struct spindump_rtloss_stats* lossStats) {

  int n = 0;
  float sum = 0;

  for (int i = 0; i < spindump_rtloss_n; ++i) {
    float rr = lossStats->recentLossRates[i];
    if (((double)rr) < (double)spindump_rtloss_maxrate) {
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
void
spindump_rtloss2tracker_initialize(struct spindump_rtloss2tracker* tracker) {
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
void
spindump_rtloss2tracker_uninitialize(struct spindump_rtloss2tracker* tracker) {
  spindump_assert(tracker != 0);
  // no-op//
}
