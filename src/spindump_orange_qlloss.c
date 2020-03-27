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
//  AUTHOR: ALEXANDRE FERRIEUX AND MARCUS IHLAR
//
//

#include <stdlib.h>
#include "spindump_orange_qlloss.h"
#include "spindump_extrameas.h"
#include "spindump_analyze.h"
#include "spindump_util.h"

#define QPERIOD 64

void
spindump_qllosstracker_observeandcalculateloss(struct spindump_analyze* state,
                                               struct spindump_packet* packet,
                                               struct spindump_connection* connection,
                                               struct timeval* ts,
                                               int fromResponder,
                                               unsigned int ipPacketLength,
                                               int ql) {
  struct spindump_qllosstracker* tracker;
  if (fromResponder)
    tracker = &connection->u.quic.qlFromPeer2to1;
  else
    tracker = &connection->u.quic.qlFromPeer1to2;
  
  // 
  // Let's extract the sQuare and Retransmit bits
  //

  uint q=((ql & spindump_extrameas_qlloss_bit1) != 0);
  uint l=((ql & spindump_extrameas_qlloss_bit2) != 0);

  //
  // Is this the first packet?
  //

  if ((!tracker->qcnt)&&(!tracker->qrank)) { 
    tracker->qcur = q;
    tracker->qcnt++;

  } else if (q == tracker->qcur) {
    tracker->qcnt++;
  } else {
    
    // 
    // End of square half-period, let's calculate upstream loss and report loss.
    //

    tracker->qloss += (QPERIOD-tracker->qcnt);
    tracker->qcur = q;
    tracker->qcnt = 1;
    tracker->qrank++;

    if (fromResponder) {
      connection->qLossesFrom2to1 = (float)tracker->qloss / connection->packetsFromSide2;
    } else {
      connection->qLossesFrom1to2 = (float)tracker->qloss / connection->packetsFromSide1; 
    }

    spindump_analyze_process_handlers(state,
                                      (fromResponder ?
                                       spindump_analyze_event_responderqllossmeasurement :
                                       spindump_analyze_event_initiatorqllossmeasurement),
                                      ts,
                                      fromResponder,
                                      ipPacketLength,
                                      packet,
                                      connection);
  }
  tracker->lloss += (l != 0);

  if (fromResponder) {
    connection->rLossesFrom2to1 = (float)tracker->lloss / connection->packetsFromSide2;
  } else {
    connection->rLossesFrom1to2 = (float)tracker->lloss / connection->packetsFromSide1;
  }
}

//
// Initialize the loss tracker object
//
void
spindump_qllosstracker_initialize(struct spindump_qllosstracker* tracker) {
  spindump_assert(tracker != 0);
  memset(tracker,0,sizeof(*tracker));
}

//
// Uninitialize the loss tracker object
//
void
spindump_qllosstracker_uninitialize(struct spindump_qllosstracker* tracker) {
  spindump_assert(tracker != 0);
  // no-op//
}
