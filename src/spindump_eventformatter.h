
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
//  SPINDUMP (C) 2018-2020 BY ERICSSON RESEARCH
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
  spindump_eventformatter_outputformat_json,
  spindump_eventformatter_outputformat_qlog
};

#define spindump_eventformatter_maxpreamble  5
#define spindump_eventformatter_maxmidamble  5
#define spindump_eventformatter_maxpostamble 5
#define spindump_eventformatter_maxamble     (spindump_max(spindump_eventformatter_maxpreamble,              \
                                                           spindump_max(spindump_eventformatter_maxmidamble, \
                                                                        spindump_eventformatter_maxpostamble)))

//
// Parameters ---------------------------------------------------------------------------------
//

//
// Data structures ----------------------------------------------------------------------------
//

struct spindump_analyze;
struct spindump_reverse_dns;
struct spindump_remote_client;

struct spindump_eventformatter {
  FILE* file;
  unsigned long blockSize;
  uint8_t padding1[4]; // unused padding to align the size of the structure correctly
  unsigned int nEntries;
  unsigned int nRemotes;
  struct spindump_remote_client** remotes;
  uint8_t* block;
  unsigned long bytesInBlock;
  struct spindump_analyze* analyzer;
  struct spindump_reverse_dns* querier;
  int reportSpins;
  int reportSpinFlips;
  int reportRtLoss;
  int reportQrLoss;
  int reportQlLoss;
  int reportPackets;
  int reportNotes;
  int anonymizeLeft;
  int anonymizeRight;
  int aggregatesOnly;
  int averageRtts;
  int minimumRtts;
  unsigned int filterExceptionalValuesPercentage;
  enum spindump_eventformatter_outputformat format;
  size_t preambleLength;
  size_t postambleLength;
};

//
// External API interface to this module ------------------------------------------------------
//

struct spindump_eventformatter*
spindump_eventformatter_initialize_file(struct spindump_analyze* analyzer,
                                        enum spindump_eventformatter_outputformat format,
                                        FILE* file,
                                        struct spindump_reverse_dns* querier,
                                        int reportSpins,
                                        int reportSpinFlips,
                                        int reportRtLoss,
                                        int reportQrLoss,
                                        int reportQlLoss,
                                        int reportPackets,
                                        int reportNotes,
                                        int anonymizeLeft,
                                        int anonymizeRight,
                                        int aggregatesOnly,
                                        int averageRtts,
                                        int minimumRtts,
                                        unsigned int filterExceptionalValuesPercentage);
struct spindump_eventformatter*
spindump_eventformatter_initialize_remote(struct spindump_analyze* analyzer,
                                          enum spindump_eventformatter_outputformat format,
                                          unsigned int nRemotes,
                                          struct spindump_remote_client** remotes,
                                          unsigned long blockSize,
                                          struct spindump_reverse_dns* querier,
                                          int reportSpins,
                                          int reportSpinFlips,
                                          int reportRtLoss,
                                          int reportQrLoss,
                                          int reportQlLoss,
                                          int reportPackets,
                                          int reportNotes,
                                          int anonymizeLeft,
                                          int anonymizeRight,
                                          int aggregatesOnly,
                                          int averageRtts,
                                          int minimumRtts,
                                          unsigned int filterExceptionalValuesPercentage);
void
spindump_eventformatter_sendpooled(struct spindump_eventformatter* formatter);
void
spindump_eventformatter_uninitialize(struct spindump_eventformatter* formatter);

//
// Internal API interface to this module ------------------------------------------------------
//

void
spindump_eventformatter_deliverdata(struct spindump_eventformatter* formatter,
                                    unsigned long length,
                                    const uint8_t* data);

#endif // SPINDUMP_EVENTFORMATTER_H
