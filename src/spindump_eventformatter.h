
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

#ifndef SPINDUMP_EVENTFORMATTER_H
#define SPINDUMP_EVENTFORMATTER_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <stdio.h>
#include "spindump_util.h"

//
// Data types ---------------------------------------------------------------------------------
//

enum spindump_eventformatter_outputformat {
  spindump_eventformatter_outputformat_text,
  spindump_eventformatter_outputformat_json
};

//
// Parameters ---------------------------------------------------------------------------------
//

//
// Data structures ----------------------------------------------------------------------------
//

struct spindump_eventformatter {
  FILE* file;
  struct spindump_analyze* analyzer;
  struct spindump_reverse_dns* querier;
  int anonymizeLeft;
  int anonymizeRight;
  enum spindump_eventformatter_outputformat format;
  uint8_t padding[4]; // unused padding to align the size of the structure correctly
};

//
// External API interface to this module ------------------------------------------------------
//

struct spindump_eventformatter*
spindump_eventformatter_initialize(struct spindump_analyze* analyzer,
				   enum spindump_eventformatter_outputformat format,
				   FILE* file,
				   struct spindump_reverse_dns* querier,
				   int anonymizeLeft,
				   int anonymizeRight);
void
spindump_eventformatter_uninitialize(struct spindump_eventformatter* formatter);

#endif // SPINDUMP_EVENTFORMATTER_H
