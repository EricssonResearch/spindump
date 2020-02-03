
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
//  SPINDUMP (C) 2019 BY ERICSSON AB
//  AUTHOR: DENIS SCHERBAKOV
//
// 

//
// Includes -----------------------------------------------------------------------------------
//

#include <string.h>
#include <stdlib.h>
#include "spindump_util.h"
#include "spindump_sctp_tsn.h"

//
// Actual code --------------------------------------------------------------------------------
//

//
// Initialize a sequence number tracker. A sequence number tracker
// records sent out sequence numbers that are 32 bits long, remembers
// the time they were sent, and then can match an acknowledgment of
// that sequence number These trackers are used in the TCP protocol
// analyzer. There's two trackers, one for each direction.
//

void
spindump_tsntracker_initialize(struct spindump_tsntracker* tracker) {
  spindump_assert(tracker != 0);
  memset(tracker,0,sizeof(*tracker));
  tracker->seqindex = 0;
}

//
// Add a new sequence number to the tracker
//
void
spindump_tsntracker_add(struct spindump_tsntracker* tracker,
                        struct timeval* ts,
                        sctp_tsn tsn) {
  spindump_assert(tracker != 0);
  spindump_assert(tracker->seqindex < spindump_tsntracker_nstored);
  tracker->stored[tracker->seqindex].outstanding = 1;
  tracker->stored[tracker->seqindex].received = *ts;
  tracker->stored[tracker->seqindex].tsn = tsn;

  tracker->seqindex++;
  tracker->seqindex %= spindump_tsntracker_nstored;
  spindump_assert(tracker->seqindex < spindump_tsntracker_nstored);
}

//
// Determine what time the request message was sent for a given
// sequence number. Return a pointer to that time, or 0 if no such
// sequence number has been seen.
//
struct timeval*
spindump_tsntracker_ackto(struct spindump_tsntracker* tracker,
                          sctp_tsn ackTsn,
                          sctp_tsn* sentTsn) {
  spindump_assert(sentTsn != 0);

  //
  // Find the earliest sent packet that this could be an
  // acknowledgment for.
  // 

  struct spindump_tsnstore* chosen = 0;
  for (unsigned int i = 0; i < spindump_tsntracker_nstored; i++) {
    struct spindump_tsnstore* candidate = &tracker->stored[i];

    //
    // Is this entry in use? If not, go to next
    // 

    if (!candidate->outstanding) continue;

    //
    // Is this previously seen SCTP DATA the one
    // acked by Cumulative TSN Ack "ackTsn"?
    // 

    spindump_deepdebugf("compare received cumulative SACK %u to candidate TSN %u",
                        ackTsn,
                        candidate->tsn);
    if (candidate->tsn <= ackTsn) {

      //
      // It is. Now see if this is the earliest one.
      // 

      if (chosen == 0)
        chosen = candidate;
      else if (candidate->tsn < chosen->tsn)
        chosen = candidate;

      //
      // Clear an every TSN that was acked by cumulative ACK
      //
      candidate->outstanding = 0;
    }
  }

  if (chosen != 0) {

    //
    // Found. Return the time when that packet was sent.
    //

    chosen->outstanding = 0;
    *sentTsn = chosen->tsn;
    return(&chosen->received);

  } else {

    //
    // Not found
    // 

    *sentTsn = 0;
    return(0);

  }
}

//
// Uninitialize the TSN number tracker object.
//

void
spindump_tsntracker_uninitialize(struct spindump_tsntracker* tracker) {
  spindump_assert(tracker != 0);
  // no-op
}
