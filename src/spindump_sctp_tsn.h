
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

#ifndef SPINDUMP_SCTP_TSN_H
#define SPINDUMP_SCTP_TSN_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <time.h>
#include <sys/time.h>
#include "spindump_util.h"
#include "spindump_protocols.h"

//
// Parameters ---------------------------------------------------------------------------------
//

#ifndef spindump_tsntracker_nstored
#define spindump_tsntracker_nstored             50
#endif

typedef uint32_t sctp_tsn;
//
// Data structures ----------------------------------------------------------------------------
//

struct spindump_tsnstore {
  struct timeval received;
  int outstanding;
  sctp_tsn tsn;
};

struct spindump_tsntracker {
  struct spindump_tsnstore stored[spindump_tsntracker_nstored];
  unsigned int seqindex;
};

//
// External API interface to this module ------------------------------------------------------
//

void
spindump_tsntracker_initialize(struct spindump_tsntracker* tracker);
void
spindump_tsntracker_add(struct spindump_tsntracker* tracker,
                        struct timeval* ts,
                        sctp_tsn tsn);
struct timeval*
spindump_tsntracker_ackto(struct spindump_tsntracker* tracker,
                          sctp_tsn ackTsn,
                          sctp_tsn* sentTsn);
void
spindump_tsntracker_uninitialize(struct spindump_tsntracker* tracker);

#endif // SPINDUMP_SCTP_TSN_H