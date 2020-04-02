
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

#ifndef SPINDUMP_MAIN_LIB_H
#define SPINDUMP_MAIN_LIB_H

//
// Includes -----------------------------------------------------------------------------------
//

#include "spindump_util.h"
#include "spindump_main.h"
#include "spindump_tags.h"

//
// Parameters ---------------------------------------------------------------------------------
//

#define spindump_main_maxnaggregates    10

//
// Data types ---------------------------------------------------------------------------------
//

enum spindump_toolmode {
  spindump_toolmode_silent,
  spindump_toolmode_textual,
  spindump_toolmode_visual
};

//
// Data structures ----------------------------------------------------------------------------
//

struct spindump_main_aggregate {
  int defaultMatch;
  int ismulticastgroup;
  int side1ishost;
  int side2ishost;
  spindump_tags tags;
  uint8_t padding[4]; // unused padding to align the next field properly
  spindump_address side1address;
  spindump_address side2address;
  spindump_network side1network;
  spindump_network side2network;
};

struct spindump_main_configuration {
  char* interface;
  const char* inputFile;
  const char* jsonInputFile;
  char* filter;
  unsigned int snaplen;
  enum spindump_toolmode toolmode;
  enum spindump_eventformatter_outputformat format;
  unsigned int maxReceive;
  int showStats;
  int reverseDns;
  int reportPackets;
  int reportSpins;
  int reportSpinFlips;
  int reportRtLoss;
  int reportQrLoss;
  int reportQlLoss;
  int reportNotes;
  int averageMode;
  int aggregateMode;
  int anonymizeLeft;
  int anonymizeRight;
  unsigned int filterExceptionalValuesPercentage;
  unsigned long long updatePeriod;
  unsigned long long bandwidthMeasurementPeriod;
  unsigned int periodicReportPeriod;
  unsigned int nAggregates;
  struct spindump_main_aggregate aggregates[spindump_main_maxnaggregates];
  unsigned long remoteBlockSize;
  unsigned int nRemotes;
  struct spindump_remote_client* remotes[SPINDUMP_REMOTE_CLIENT_MAX_CONNECTIONS];
  int collector;
  spindump_port collectorPort;
  spindump_tags defaultTags;
};

struct spindump_main_state {
  struct spindump_main_configuration config;
  int interrupt;
};

//
// External API interface to this module ------------------------------------------------------
//

struct spindump_main_state*
spindump_main_initialize(void);
void
spindump_main_uninitialize(struct spindump_main_state* state);
void
spindump_main_processargs(int argc,
                          char** argv,
                          struct spindump_main_configuration* config);
void
spindump_main_help(void);

#endif // SPINDUMP_MAIN_LIB_H
