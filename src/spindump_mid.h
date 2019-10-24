
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

#ifndef SPINDUMP_MID_H
#define SPINDUMP_MID_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <time.h>
#include <sys/time.h>
#include "spindump_protocols.h"

//
// Parameters ---------------------------------------------------------------------------------
//

#define spindump_messageidtracker_nstored               40

//
// Data structures ----------------------------------------------------------------------------
//

struct spindump_messageidstore {
  struct timeval received;
  int outstanding;
  uint16_t messageid;
  uint16_t padding; // unused
};

struct spindump_messageidtracker {
  unsigned int messageidindex;
  unsigned int padding; // unused padding to align the next field properly
  struct spindump_messageidstore stored[spindump_messageidtracker_nstored];
};

//
// External API interface to this module ------------------------------------------------------
//

void
spindump_messageidtracker_initialize(struct spindump_messageidtracker* tracker);
void
spindump_messageidtracker_add(struct spindump_messageidtracker* tracker,
                              const struct timeval* ts,
                              const uint16_t messageid);
const struct timeval*
spindump_messageidtracker_ackto(struct spindump_messageidtracker* tracker,
                                const uint16_t messageid);
void
spindump_messageidtracker_uninitialize(struct spindump_messageidtracker* tracker);

#endif // SPINDUMP_MID_H
