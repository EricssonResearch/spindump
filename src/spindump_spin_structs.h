
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

#ifndef SPINDUMP_SPIN_STRUCTS_H
#define SPINDUMP_SPIN_STRUCTS_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <time.h>
#include <sys/time.h>
#include "spindump_protocols.h"

//
// Parameters ---------------------------------------------------------------------------------
//

#define spindump_spintracker_nstored            10

//
// Spinstore flags ----------------------------------------------------------------------------
//

#define spindump_spinstore_outstanding_unidir    0x1
#define spindump_spinstore_outstanding_bidir     0x2

#define spindump_spinstore_outstanding_init      \
    spindump_spinstore_outstanding_unidir | spindump_spinstore_outstanding_bidir

//
// Data structures ----------------------------------------------------------------------------
//

struct spindump_spinstore {
  int outstanding;
  int spin0to1;
  struct timeval received;
};

struct spindump_spintracker {
  int lastSpinSet;
  int lastSpin;
  unsigned int spinindex;
  uint8_t padding[4]; // unused padding to align the next field properly
  struct spindump_spinstore stored[spindump_spintracker_nstored];
  unsigned long long totalSpins;
};

#endif // SPINDUMP_SPIN_STRUCTS_H
