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
//  SPINDUMP (C) 2021 BY ERICSSON RESEARCH
//  AUTHOR: FABIO BULGARELLA
//
//

#include <stdlib.h>
#include "spindump_titalia_delaybit.h"
#include "spindump_analyze.h"
#include "spindump_connections.h"
#include "spindump_connections_structs.h"
#include "spindump_util.h"

//
// Actual Code
//

//
// Observe spin changes and calculate RTT if a delay sample is received
//

void
spindump_delaybittracker_observeandcalculatertt(struct spindump_analyze* state,
                                                struct spindump_packet* packet,
                                                struct spindump_connection* connection,
                                                struct timeval* ts,
                                                int fromResponder,
                                                unsigned int ipPacketLength,
                                                spindump_extrameas_int extrameasbits) {
  
  //
  // Simply return if packet is not a delay sample
  //

  if ((extrameasbits & spindump_extrameas_delaybit) == 0) return;

  //
  // Get trackers
  //

  struct spindump_delaybittracker* tracker;
  struct spindump_delaybittracker* otherTracker;
  if (fromResponder) {
    tracker = &connection->u.quic.delaybitFromPeer2to1;
    otherTracker = &connection->u.quic.delaybitFromPeer1to2;
  } else {
    tracker = &connection->u.quic.delaybitFromPeer1to2;
    otherTracker = &connection->u.quic.delaybitFromPeer2to1;
  }

  //
  // Try to compute the end-to-end RTT
  //

  unsigned long long diff = spindump_timediffinusecs(ts, &tracker->lastDelaySample);
  if (diff < spindump_delaybit_tmax) {
    spindump_connections_newrttmeasurement(state,
                                           packet,
                                           connection,
                                           ipPacketLength,
                                           fromResponder,
                                           1, // unidirectional
                                           &tracker->lastDelaySample,
                                           ts,
                                           "DELAYBIT_UNIDIR");
  }

  //
  // Try to compute LeftRTT or RightRTT
  //

  diff = spindump_timediffinusecs(ts, &otherTracker->lastDelaySample);
  if (diff < spindump_delaybit_tmax) {
    spindump_connections_newrttmeasurement(state,
                                           packet,
                                           connection,
                                           ipPacketLength,
                                           fromResponder, // 0 = left, 1 = right
                                           0, // bidirectional
                                           &otherTracker->lastDelaySample,
                                           ts,
                                           "DELAYBIT");
  }

  //
  // Save delay sample timestamp
  //

  tracker->lastDelaySample = *ts;
}

//
// Initialize the loss tracker object
//

void
spindump_delaybittracker_initialize(struct spindump_delaybittracker* tracker) {
  spindump_assert(tracker != 0);
  memset(tracker,0,sizeof(*tracker));
}

//
// Uninitialize the loss tracker object
//

void
spindump_delaybittracker_uninitialize(struct spindump_delaybittracker* tracker) {
  spindump_assert(tracker != 0);
  // no-op//
}
