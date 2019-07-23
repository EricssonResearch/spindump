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
//  AUTHOR: ALEXANDRE FERRIEUX AND MARCUS IHLAR
//
//

#ifndef SPINDUMP_QR_STRUCTS_H
#define SPINDUMP_QR_STRUCTS_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <stdint.h>
#include <time.h>
#include "spindump_util.h"

struct spindump_qrlosstracker {
  spindump_counter_32bit qrank;
  spindump_counter_32bit qcur;
  spindump_counter_32bit qcnt;
  spindump_counter_32bit qloss;
  spindump_counter_32bit rloss;
};

#endif
