
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

#ifndef SPINDUMP_REMOTE_FILE_H
#define SPINDUMP_REMOTE_FILE_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <microhttpd.h>
#include "spindump_util.h"
#include "spindump_protocols.h"
#include "spindump_table.h"
#include "spindump_eventformatter.h"
#include "spindump_json.h"

//
// Parameters ---------------------------------------------------------------------------------
//

//
// Data structures ----------------------------------------------------------------------------
//

struct spindump_remote_file {
  FILE* file;
  unsigned int nEvents;
  unsigned int maxEvents;
  struct spindump_event* events;
};

//
// External API interface to the server module ------------------------------------------------
//

struct spindump_remote_file*
spindump_remote_file_init(const char* filename);
int
spindump_remote_file_getupdate(struct spindump_remote_file* file,
                               struct spindump_analyze* analyzer,
                               struct timeval* timestamp);
void
spindump_remote_file_close(struct spindump_remote_file* file);

#endif // SPINDUMP_REMOTE_FILE_H
