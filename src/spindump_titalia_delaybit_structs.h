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
//  SPINDUMP (C) 2021 BY ERICSSON RESEARCH
//  AUTHOR: FABIO BULGARELLA
//
//

#ifndef SPINDUMP_TITALIA_DELAYBIT_STRUCTS_H
#define SPINDUMP_TITALIA_DELAYBIT_STRUCTS_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <stdint.h>
#include <time.h>
#include "spindump_rtt.h"
#include "spindump_util.h"

//
// Parameters ---------------------------------------------------------------------------------
//

#define spindump_delaybit_tmax  225000  // usec (90% of 250ms)

//
// Data Structures ----------------------------------------------------------------------------
//

struct spindump_delaybittracker {
  struct timeval lastDelaySample;
};

#endif //SPINDUMP_SPINDUMP_DELAYBIT_STRUCTS_H
