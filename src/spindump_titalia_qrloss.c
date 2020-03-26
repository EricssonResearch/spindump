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

#include <stdlib.h>
#include <stdint.h>
#include "spindump_util.h"
#include "spindump_analyze.h"
#include "spindump_extrameas.h"
#include "spindump_titalia_qrloss.h"

//
// Function Prototypes
//

float
spindump_qrloss_setaveragelossrate(struct spindump_qrloss_stats *lossStats);

//
// Actual Code
//

//
// Compute the loss value (single bit version) and produce a new loss
// measurement if the reflection phase is considered ended
//

void
spindump_qrlosstracker_observeandcalculateloss(struct spindump_analyze *state,
                                               struct spindump_packet *packet,
                                               struct spindump_connection *connection,
                                               struct timeval *ts,
                                               int fromResponder,
                                               int lossbits) {
  struct spindump_qrlosstracker *tracker;
  struct spindump_qrloss *lossRates;
  if (fromResponder) {
    tracker = &connection->u.quic.qrFromPeer2to1;
    lossRates = &connection->u.quic.qrLossesFrom2to1;
  } else {
    tracker = &connection->u.quic.qrFromPeer1to2;
    lossRates = &connection->u.quic.qrLossesFrom1to2;
  }

  //
  // Extract the sQuare and ref sQuare bits
  //

  int squareBit = ((lossbits & spindump_extrameas_qrloss_qbit) != 0);
  int refSquareBit = ((lossbits & spindump_extrameas_qrloss_rbit) != 0);

  //
  // SQUARE BIT SECTION
  //

  if (squareBit == tracker->currentSquareBit) {
    tracker->squarePktCounter++;
  } else {
    tracker->holdingSquarePktCounter++;

    if (tracker->holdingSquarePktCounter == spindump_qrloss_reorder_threshold) {
      tracker->totSquarePkts += tracker->squarePktCounter;

      // Compute Loss
      spindump_counter_32bit losses;
      if (tracker->squarePktCounter <= spindump_qrloss_qperiod) {
        losses = spindump_qrloss_qperiod - tracker->squarePktCounter;
        tracker->lossStats.recentLossRates[tracker->lossStats.currentIndex++] =
            (float) losses / spindump_qrloss_qperiod;
      } else {
        losses = spindump_qrloss_3x_qperiod - tracker->squarePktCounter;
        tracker->lossStats.recentLossRates[tracker->lossStats.currentIndex++] =
            (float) losses / spindump_qrloss_3x_qperiod;
      }
      tracker->lossStats.currentIndex %= spindump_rtloss_n;

      if (losses != 0) {
        tracker->lostPackets += losses;

        //
        // Calculate loss rates and update connection statistics
        //

        lossRates->totalLossRate =
            (float) (tracker->lostPackets) / (float) (tracker->totSquarePkts + tracker->lostPackets);
        lossRates->averageLossRate = spindump_qrloss_setaveragelossrate(&tracker->lossStats);

        // Call handlers if any
        spindump_analyze_process_handlers(state,
                                          fromResponder ? spindump_analyze_event_responderqrlossmeasurement
                                                        : spindump_analyze_event_initiatorqrlossmeasurement,
                                          packet,
                                          connection);
      }
      tracker->currentSquareBit = squareBit;

      // Cleaning holding counters
      tracker->squarePktCounter = spindump_qrloss_reorder_threshold;
      tracker->holdingSquarePktCounter = 0;
    }
  }

  /*
   * REF SQUARE BIT SECTION
   */
  if (tracker->refSquareStarting)
  {
    if (refSquareBit == 0) return;
    tracker->refSquareStarting = 0;
    tracker->currentRefSquareBit = 1;
  }

  if (refSquareBit == tracker->currentRefSquareBit) {
    tracker->refSquarePktCounter++;
  } else {
    tracker->holdingRefSquarePktCounter++;

    if (tracker->holdingRefSquarePktCounter == spindump_qrloss_reorder_threshold) {
      tracker->totRefSquarePkts += tracker->refSquarePktCounter;

      // Compute Loss
      spindump_counter_32bit losses;
      if (tracker->refSquarePktCounter <= spindump_qrloss_qperiod) {
        losses = spindump_qrloss_qperiod - tracker->refSquarePktCounter;
        tracker->refLossStats.recentLossRates[tracker->refLossStats.currentIndex++] =
            (float) losses / spindump_qrloss_qperiod;
      } else {
        losses = spindump_qrloss_3x_qperiod - tracker->refSquarePktCounter;
        tracker->refLossStats.recentLossRates[tracker->refLossStats.currentIndex++] =
            (float) losses / spindump_qrloss_3x_qperiod;
      }
      tracker->refLossStats.currentIndex %= spindump_rtloss_n;

      if (losses != 0) {
        tracker->refLostPackets += losses;

        //
        // Calculate loss rates and update connection statistics
        //

        lossRates->totalRefLossRate =
            (float) (tracker->refLostPackets) / (float) (tracker->totRefSquarePkts + tracker->refLostPackets);
        lossRates->averageRefLossRate = spindump_qrloss_setaveragelossrate(&tracker->refLossStats);

        // Call handlers if any
        spindump_analyze_process_handlers(state,
                                          fromResponder ? spindump_analyze_event_responderqrlossmeasurement
                                                        : spindump_analyze_event_initiatorqrlossmeasurement,
                                          packet,
                                          connection);
      }
      tracker->currentRefSquareBit = refSquareBit;

      // Cleaning holding counters
      tracker->refSquarePktCounter = spindump_qrloss_reorder_threshold;
      tracker->holdingRefSquarePktCounter = 0;
    }
  }
}

float
spindump_qrloss_setaveragelossrate(struct spindump_qrloss_stats *lossStats) {
  int n = 0;
  float sum = 0;

  for (int i = 0; i < spindump_qrloss_n; i++) {
    float lossRate = lossStats->recentLossRates[i];
    if (lossRate < spindump_qrloss_maxrate) {
      sum += lossRate;
      n++;
    } else break;
  }
  return sum / (float) n;
}

//
// Initialize the loss tracker object
//
void
spindump_qrlosstracker_initialize(struct spindump_qrlosstracker *tracker) {
  spindump_assert(tracker != 0);
  memset(tracker, 0, sizeof(*tracker));
  tracker->refSquareStarting = 1;
  for (int i = 0; i < spindump_qrloss_n; i++) {
    tracker->lossStats.recentLossRates[i] = spindump_qrloss_maxrate;
    tracker->refLossStats.recentLossRates[i] = spindump_qrloss_maxrate;
  }
}

//
// Uninitialize the loss tracker object
//
void
spindump_qrlosstracker_uninitialize(struct spindump_qrlosstracker *tracker) {
  spindump_assert(tracker != 0);
  // no-op//
}
