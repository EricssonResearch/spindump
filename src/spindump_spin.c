
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

#include <string.h>
#include <stdlib.h>
#include "spindump_util.h"
#include "spindump_spin.h"
#include "spindump_connections.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static int
spindump_spintracker_observespin(struct spindump_analyze* state,
				 struct spindump_packet* packet,
				 struct spindump_connection* connection,
				 struct spindump_spintracker* tracker,
				 struct timeval* ts,
				 int spin,
				 int fromResponder,
				 int* p_spin0to1);
static struct timeval*
spindump_spintracker_matchspin(struct spindump_spintracker* tracker,
			       int requireExactSpinValue,
			       int spin0to1);

//
// Actual code --------------------------------------------------------------------------------
//

void
spindump_spintracker_initialize(struct spindump_spintracker* tracker) {
  spindump_assert(tracker != 0);
  memset(tracker,0,sizeof(*tracker));
  tracker->lastSpinSet = 0;
  tracker->lastSpin = 0;
  tracker->spinindex = 0;
}

void
spindump_spintracker_observespinandcalculatertt(struct spindump_analyze* state,
						struct spindump_packet* packet,
						struct spindump_connection* connection,
						struct spindump_spintracker* tracker,
						struct spindump_spintracker* otherDirectionTracker,
						struct timeval* ts,
						int spin,
						int fromResponder) {
  int spin0to1;
  if (spindump_spintracker_observespin(state,
				       packet,
				       connection,
				       tracker,
				       ts,
				       spin,
				       fromResponder,
				       &spin0to1)) {
		//
		// Try to match the spin flip with the most recent matching flip in the other direction.
		// Responder spin flips match with equal flips, initiator flips match with inverse flips.
		//
    struct timeval* otherSpinTime = spindump_spintracker_matchspin(otherDirectionTracker,
								   1,
								   fromResponder ? spin0to1 : !spin0to1);
    if (otherSpinTime) {
      spindump_deepdebugf("found a matching %s spin for the spin %s",
			  spin0to1 ? "1to0" : "0to1",
			  spin0to1 ? "0to1" : "1to0");
      spindump_connections_newrttmeasurement(state,
					     packet,
					     connection,
					     fromResponder,
					     otherSpinTime,
					     ts,
					     "SPIN");
    } else {
      spindump_deepdebugf("did not find matching %s spin for the spin %s",
			  spin0to1 ? "1to0" : "0to1",
			  spin0to1 ? "0to1" : "1to0");
    }

  }
}

static int
spindump_spintracker_observespin(struct spindump_analyze* state,
				 struct spindump_packet* packet,
				 struct spindump_connection* connection,
				 struct spindump_spintracker* tracker,
				 struct timeval* ts,
				 int spin,
				 int fromResponder,
				 int* p_spin0to1) {
  spindump_assert(tracker != 0);
  spindump_assert(ts != 0);
  spindump_assert(spin == 0 || spin == 1);
  if (!tracker->lastSpinSet) {
    tracker->lastSpinSet = 1;
    tracker->lastSpin = spin;
    spindump_deepdebugf("initial SPIN set to %u from %s",
			spin,
			fromResponder ? "responder" : "initiator");
    spindump_analyze_process_handlers(state,
				      (fromResponder ? spindump_analyze_event_responderspinvalue :
				       spindump_analyze_event_initiatorspinvalue),
				      packet,
				      connection);
    return(0);
  } else if (spin != tracker->lastSpin) {
    int spin0to1 = (tracker->lastSpin == 0);
    spindump_deepdebugf("observed a SPIN flip from %u to %u from %s",
			tracker->lastSpin,
			spin,
			fromResponder ? "responder" : "initiator");
    tracker->lastSpin = spin;
    spindump_analyze_process_handlers(state,
				      (fromResponder ? spindump_analyze_event_responderspinvalue :
				       spindump_analyze_event_initiatorspinvalue),
				      packet,
				      connection);
    spindump_spintracker_add(tracker,ts,spin0to1);
    *p_spin0to1 = spin0to1;
    spindump_analyze_process_handlers(state,
				      (fromResponder ? spindump_analyze_event_responderspinflip :
				       spindump_analyze_event_initiatorspinflip),
				      packet,
				      connection);
    return(1);
  } else {
    return(0);
  }
}

void
spindump_spintracker_add(struct spindump_spintracker* tracker,
			 struct timeval* ts,
			 int spin0to1) {

  spindump_assert(tracker != 0);
  spindump_assert(ts != 0);
  spindump_assert(spin0to1 == 0 || spin0to1 == 1);
  spindump_assert(tracker->spinindex < spindump_spintracker_nstored);
  tracker->stored[tracker->spinindex].outstanding = 1;
  tracker->stored[tracker->spinindex].received = *ts;
  tracker->stored[tracker->spinindex].spin0to1 = spin0to1;
  tracker->spinindex++;
  tracker->spinindex %= spindump_spintracker_nstored;
  spindump_assert(tracker->spinindex < spindump_spintracker_nstored);
  tracker->totalSpins++;
}

struct timeval*
	spindump_spintracker_matchspin(struct spindump_spintracker* tracker,
			       int requireExactSpinValue,
			       int spin0to1) {

  spindump_assert(requireExactSpinValue == 0 || requireExactSpinValue == 1);
  spindump_assert(spin0to1 == 0 || spin0to1 == 1);

  //
  // Find the spin
  //

  struct spindump_spinstore* chosen = 0;
  for (unsigned int i = 0; i < spindump_spintracker_nstored; i++) {

    struct spindump_spinstore* candidate = &tracker->stored[i];

    //
    // Is this entry in use? If not, go to next
    //

    if (!candidate->outstanding) continue;

    //
    // Is this correct?
    //

    if (!requireExactSpinValue || candidate->spin0to1 == spin0to1) {

      //
      // It is. Now see if this is the earliest one.
      //

      if (chosen == 0)
	chosen = candidate;
      else if (spindump_isearliertime(&chosen->received,&candidate->received))
	chosen = candidate;
    }
  }

  if (chosen != 0) {

    //
    // Found. Return the time when that packet was sent.
    // But first, clear the spin stores from all entries
    // sent earlier than the one that we found. And clear this
    // entry too.
    //

    for (unsigned int j = 0; j < spindump_spintracker_nstored; j++) {
      struct spindump_spinstore* other = &tracker->stored[j];
      if (other->outstanding && spindump_isearliertime(&chosen->received,&other->received)) {
	other->outstanding = 0;
      }
    }

    chosen->outstanding = 0;
    return(&chosen->received);

  } else {

    //
    // Not found
    //

    return(0);

  }
}

void
spindump_spintracker_uninitialize(struct spindump_spintracker* tracker) {
  spindump_assert(tracker != 0);
  // no-op//
}
