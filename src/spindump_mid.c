
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
#include "spindump_mid.h"

//
// Actual code --------------------------------------------------------------------------------
//

void
spindump_messageidtracker_initialize(struct spindump_messageidtracker* tracker) {
  spindump_assert(tracker != 0);
  memset(tracker,0,sizeof(*tracker));
  tracker->messageidindex = 0;
}

void
spindump_messageidtracker_add(struct spindump_messageidtracker* tracker,
			      const struct timeval* ts,
			      const uint16_t messageid) {
  spindump_assert(tracker != 0);
  spindump_assert(tracker->messageidindex < spindump_messageidtracker_nstored);
  tracker->stored[tracker->messageidindex].outstanding = 1;
  tracker->stored[tracker->messageidindex].received = *ts;
  tracker->stored[tracker->messageidindex].messageid = messageid;
  tracker->messageidindex++;
  tracker->messageidindex %= spindump_messageidtracker_nstored;
  spindump_assert(tracker->messageidindex < spindump_messageidtracker_nstored);
}

const struct timeval*
spindump_messageidtracker_ackto(struct spindump_messageidtracker* tracker,
				const uint16_t messageid) {
  
  //
  // Find the earliest sent packet that this could be an
  // acknowledgment for.
  // 
  
  struct spindump_messageidstore* chosen = 0;
  for (unsigned int i = 0; i < spindump_messageidtracker_nstored; i++) {
    
    struct spindump_messageidstore* candidate = &tracker->stored[i];

    //
    // Is this entry in use? If not, go to next
    // 

    if (!candidate->outstanding) continue;
    
    //
    // Is this previously seen message ID the one acked by message id
    // "messageid"?
    // 
    
    if (candidate->messageid == messageid) {
      
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
    // But first, clear the message id stores from all entries
    // sent earlier than the one that we found. And clear this
    // entry too.
    // 

    for (unsigned int j = 0; j < spindump_messageidtracker_nstored; j++) {
      struct spindump_messageidstore* other = &tracker->stored[j];
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
spindump_messageidtracker_uninitialize(struct spindump_messageidtracker* tracker) {
  spindump_assert(tracker != 0);
  // no-op
}

