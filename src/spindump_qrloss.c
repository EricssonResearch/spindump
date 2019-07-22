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
//  AUTHOR: ALEXANDRE FERRIEUX
//
//

#include <stdlib.h>
#include "spindump_qrloss.h"
#include "spindump_extrameas.h"

#define QPERIOD 64

void
spindump_qrlosstracker_observeandcalculateloss(struct spindump_analyze* state,
                                                struct spindump_packet* packet,
                                                struct spindump_connection* connection,
                                                struct timeval* ts,
                                                int fromResponder,
                                                int extrameas) {
  struct spindump_qrlosstracker* tracker;
  if (fromResponder)
    tracker = &connection->u.quic.qrFromPeer2to1;
  else
    tracker = &connection->u.quic.qrFromPeer1to2;
  
  // 
  // Let's extract the sQuare and Retransmit bits
  //

  uint q=((extrameas & spindump_extrameas_qrloss_bit1)!=0);
  uint r=((extrameas & spindump_extrameas_qrloss_bit2)!=0);

  //
  // Is this the first packet?
  //

  if ((!tracker->qcnt)&&(!tracker->qrank)) { 
    tracker->qcur=q;
    tracker->qcnt++;

  } else if (q==tracker->qcur) {
    tracker->qcnt++;
  } else {
    
    // 
    // End of square half-period, let's calculate upstream loss and report loss.
    //

    tracker->qloss += (QPERIOD-tracker->qcnt);
    tracker->qcur=q;
    tracker->qcnt=1;
    tracker->qrank++;
  }

  tracker->rloss+=(r!=0);
}

//
// Initialize the loss tracker object
//
void
spindump_qrlosstracker_initialize(struct spindump_qrlosstracker* tracker) {
  spindump_assert(tracker != 0);
  memset(tracker,0,sizeof(*tracker));
}

//
// Uninitialize the loss tracker object
//
void
spindump_qrlosstracker_uninitialize(struct spindump_qrlosstracker* tracker) {
  spindump_assert(tracker != 0);
  // no-op//
}
