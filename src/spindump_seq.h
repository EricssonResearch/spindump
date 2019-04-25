
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

#ifndef SPINDUMP_SEQ_H
#define SPINDUMP_SEQ_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <time.h>
#include <sys/time.h>
#include "spindump_protocols.h"

//
// Parameters ---------------------------------------------------------------------------------
//

#ifndef spindump_seqtracker_nstored
#define spindump_seqtracker_nstored             50
#endif

//
// Data structures ----------------------------------------------------------------------------
//

struct spindump_seqstore {
  struct timeval received;
  int outstanding;
  unsigned int len;
  int finset;
  tcp_seq seq;
  //char padding[2]; // unused
};

struct spindump_seqtracker {
  struct spindump_seqstore stored[spindump_seqtracker_nstored];
  unsigned int seqindex;
  char padding[4]; // unused
};

//
// External API interface to this module ------------------------------------------------------
//

void
spindump_seqtracker_initialize(struct spindump_seqtracker* tracker);
void
spindump_seqtracker_add(struct spindump_seqtracker* tracker,
                        struct timeval* ts,
                        tcp_seq seq,
                        unsigned int payloadlen,
                        int finset);
struct timeval*
spindump_seqtracker_ackto(struct spindump_seqtracker* tracker,
                          tcp_seq seq,
                          tcp_seq* sentSeq,
                          int* sentFin);
void
spindump_seqtracker_uninitialize(struct spindump_seqtracker* tracker);

#endif // SPINDUMP_SEQ_H
