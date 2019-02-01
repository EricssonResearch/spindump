
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
spindump_spintracker_match_unidirectional_spin(struct spindump_spintracker* tracker,
					       int spin0to1);

static struct timeval*
spindump_spintracker_match_bidirectional_spin(struct spindump_spintracker* tracker,
					      int requireExactSpinValue,
					      int spin0to1);

//
// Helper macros ------------------------------------------------------------------------------
//

#define spimdump_spin_spin0to1tostring(spin0to1) ((spin0to1) ? "1to0" : "0to1")

//
// Actual code --------------------------------------------------------------------------------
//

//
// Is the given recorded spin still outstanding for a unidirectional measurement?
//

static inline int
spindump_spinstore_is_outstanding_unidir(int outstanding) {
  return((outstanding & spindump_spinstore_outstanding_unidir) != 0);
}

//
// Is the given recorded spin still outstanding for a bidirectional measurement?
//

static inline int
spindump_spinstore_is_outstanding_bidir(int outstanding) {
  return((outstanding & spindump_spinstore_outstanding_bidir) != 0);
}

//
// Mark the given recorded spin still as no longer outstanding for a
// unidirectional measurement
//

static inline void
spindump_spinstore_observed_unidir(struct spindump_spinstore* store) {
  store->outstanding &= (~spindump_spinstore_outstanding_unidir);
}

//
// Mark the given recorded spin still as no longer outstanding for a
// biidirectional measurement
//

static inline void
spindump_spinstore_observed_bidir(struct spindump_spinstore* store) {
  store->outstanding &= (~spindump_spinstore_outstanding_bidir);
}

//
// Get the index of the current/last observed spin in the tracker
//

static inline int
spindump_spintracker_curr_index(struct spindump_spintracker* tracker) {
  return(tracker->spinindex > 0 ?
	 tracker->spinindex - 1 :
	 spindump_spintracker_nstored - 1);
}

//
// Get the index of the previous-to-last observed spin in the tracker
//

static inline int
spindump_spintracker_prev_index(struct spindump_spintracker* tracker) {
  switch (tracker->spinindex) {
  case 0:
    return(spindump_spintracker_nstored - 2);
  case 1:
    return(spindump_spintracker_nstored - 1);
  default:
    return(tracker->spinindex - 2);
  }
}

//
// Initialize a spin-tracking object
//

void
spindump_spintracker_initialize(struct spindump_spintracker* tracker) {
  spindump_assert(tracker != 0);
  memset(tracker,0,sizeof(*tracker));
  tracker->lastSpinSet = 0;
  tracker->lastSpin = 0;
  tracker->spinindex = 0;
}

//
// Mark a spin value as observed in the network, and calculate RTT
// based on it if the spin did flip
//

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
    
    struct timeval* otherSpinTime =
      spindump_spintracker_match_bidirectional_spin(otherDirectionTracker,
						    1,
						    fromResponder ? spin0to1 : !spin0to1);
    
    if (otherSpinTime) {
      spindump_deepdebugf("found a matching %s SPIN for the SPIN %s",
			  spimdump_spin_spin0to1tostring(!spin0to1),
			  spimdump_spin_spin0to1tostring(spin0to1));
      spindump_connections_newrttmeasurement(state,
					     packet,
					     connection,
					     fromResponder, // 0 = left, 1 = right
					     0, // bidirectional
					     otherSpinTime,
					     ts,
					     "SPIN");
    } else {
      spindump_deepdebugf("did not find matching %s SPIN for the SPIN %s",
			  spimdump_spin_spin0to1tostring(!spin0to1),
			  spimdump_spin_spin0to1tostring(spin0to1));
    }
    
    //
    // Match spin with previous in same direction to obtain end to end RTT.
    //
    
    otherSpinTime = spindump_spintracker_match_unidirectional_spin(tracker, spin0to1);
    
    if (otherSpinTime) {
      spindump_debugf("found a matching unidirectional %s to %s spin flip",
		      spimdump_spin_spin0to1tostring(!spin0to1),
		      spimdump_spin_spin0to1tostring(spin0to1));
      
      spindump_connections_newrttmeasurement(state,
					     packet,
					     connection,
					     fromResponder,
					     1, // unidirectional
					     otherSpinTime,
					     ts,
					     "SPIN_UNIDIR");
    }
  }
}

//
// Mark a spin value as observed in the network, i.e., store it in the
// spintracker ring buffer if it was a flip, remember the proper value
// if this is the first observed spin value, etc.
//

static int
spindump_spintracker_observespin(struct spindump_analyze* state,
				 struct spindump_packet* packet,
				 struct spindump_connection* connection,
				 struct spindump_spintracker* tracker,
				 struct timeval* ts,
				 int spin,
				 int fromResponder,
				 int* p_spin0to1) {

  //
  // Sanity checks on inputs
  //
  
  spindump_assert(tracker != 0);
  spindump_assert(ts != 0);
  spindump_assert(spindump_isbool(spin));
  spindump_assert(spindump_isbool(fromResponder));

  //
  // First check if there's never been any spin value. If so, we take
  // the spin in (at whatever value it is), but it is not a change.
  //
  
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
    
  }
  
  //
  // Otherwise, if we actuall see a change from the previous spin, it
  // is a flip
  //
  
  if (spin != tracker->lastSpin) {
    
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
    
  }

  //
  // And finally, we're just seeing a repeated spin value from previous packet
  //
  
  spindump_deepdebugf("regular SPIN still %u from %s",
		      spin,
		      fromResponder ? "responder" : "initiator");
  spindump_analyze_process_handlers(state,
				    (fromResponder ? spindump_analyze_event_responderspinvalue :
				     spindump_analyze_event_initiatorspinvalue),
				    packet,
				    connection);
  return(0);
}

//
// Mark a spin flip as observed in the network, i.e., store it in the
// spintracker ring buffer.
//

void
spindump_spintracker_add(struct spindump_spintracker* tracker,
			 struct timeval* ts,
			 int spin0to1) {

  spindump_assert(tracker != 0);
  spindump_assert(ts != 0);
  spindump_assert(spin0to1 == 0 || spin0to1 == 1);
  spindump_assert(tracker->spinindex < spindump_spintracker_nstored);
  tracker->stored[tracker->spinindex].outstanding = spindump_spinstore_outstanding_init;
  tracker->stored[tracker->spinindex].received = *ts;
  tracker->stored[tracker->spinindex].spin0to1 = spin0to1;
  tracker->spinindex++;
  tracker->spinindex %= spindump_spintracker_nstored;
  spindump_assert(tracker->spinindex < spindump_spintracker_nstored);
  tracker->totalSpins++;
}

//
// Match a spin flip within one side (e.g., initiator->responder
// packet flow).
//

struct timeval*
spindump_spintracker_match_unidirectional_spin(struct spindump_spintracker* tracker,
					       int spin0to1) {
  
  spindump_assert(spindump_isbool(spin0to1));
  
  //
  // Find earlier spin in this same tracker and same packet flow
  //
  
  unsigned int previndex = spindump_spintracker_prev_index(tracker);
  spindump_deepdebugf("looking for unidirectional SPIN, indexes upcoming %u last %u (spin %s) previous %u",
		      tracker->spinindex,
		      spindump_spintracker_curr_index(tracker),
		      spimdump_spin_spin0to1tostring(spin0to1),
		      previndex);
  struct spindump_spinstore* previous = &tracker->stored[previndex];
  spindump_deepdebugf("looking at previous SPIN flip, outstanding = %x", previous->outstanding);
  if (!spindump_spinstore_is_outstanding_unidir(previous->outstanding)) {
    return(0);
  }
  
  spindump_deepdebugf("this SPIN flip is %u (%s), previous is %u (%s)",
		      spin0to1,
		      spimdump_spin_spin0to1tostring(spin0to1),
		      previous->spin0to1,
		      spimdump_spin_spin0to1tostring(previous->spin0to1));
  spindump_assert(spin0to1 != previous->spin0to1);
  spindump_spinstore_observed_unidir(previous);
  return (&previous->received);
}

//
// Match a spin flip from one side to the other side
//

struct timeval*
spindump_spintracker_match_bidirectional_spin(struct spindump_spintracker* tracker,
					      int requireExactSpinValue,
					      int spin0to1) {
  
  spindump_assert(spindump_isbool(requireExactSpinValue));
  spindump_assert(spindump_isbool(spin0to1));
  
  //
  // Find the spin
  //

  struct spindump_spinstore* chosen = 0;
  for (unsigned int i = 0; i < spindump_spintracker_nstored; i++) {

    struct spindump_spinstore* candidate = &tracker->stored[i];

    //
    // Is this entry in use? If not, go to next
    //

    if (!spindump_spinstore_is_outstanding_bidir(candidate->outstanding)) continue;

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
      if (spindump_spinstore_is_outstanding_bidir(other->outstanding) &&
	  spindump_isearliertime(&chosen->received,&other->received)) {
	spindump_spinstore_observed_bidir(other);
      }
    }
    
    spindump_spinstore_observed_bidir(chosen);
    return(&chosen->received);
    
  } else {

    //
    // Not found
    //

    return(0);

  }
}

//
// Uninitialize the spin tracker object
//

void
spindump_spintracker_uninitialize(struct spindump_spintracker* tracker) {
  spindump_assert(tracker != 0);
  // no-op//
}
