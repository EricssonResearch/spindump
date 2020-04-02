
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

#ifndef SPINDUMP_TABLE_STRUCTS_H
#define SPINDUMP_TABLE_STRUCTS_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include "spindump_tags.h"
#include "spindump_connections_structs.h"

//
// Parameters ---------------------------------------------------------------------------------
//

#define spindump_connectionstable_defaultsize 1024

//
// Data structures ----------------------------------------------------------------------------
//

struct spindump_connectionstable {
  unsigned long long bandwidthMeasurementPeriod;
  unsigned int periodicReportPeriod;
  int performingPeriodicReport;
  struct timeval lastPeriodicCheck;
  struct timeval lastPeriodicReport;
  spindump_tags defaultTags;
  unsigned int nConnections;
  unsigned int maxNConnections;
  struct spindump_connection** connections;
};

#endif // SPINDUMP_TABLE_STRUCTS_H
