
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

#ifndef SPINDUMP_MAIN_H
#define SPINDUMP_MAIN_H

//
// Includes -----------------------------------------------------------------------------------
//

#include "spindump_util.h"

//
// Parameters ---------------------------------------------------------------------------------
//

#define spindump_main_maxnaggregates	10

//
// Data structures ----------------------------------------------------------------------------
//

struct spindump_main_aggregate {
  int ismulticastgroup;
  int side1ishost;
  int side2ishost;
  uint8_t padding[4]; // unused padding to align the next field properly
  spindump_address side1address;
  spindump_address side2address;
  spindump_network side1network;
  spindump_network side2network;
};
  
#endif // SPINDUMP_MAIN_H
