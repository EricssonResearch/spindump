
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

#ifndef SPINDUMP_REMOTE_SERVER_H
#define SPINDUMP_REMOTE_SERVER_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <microhttpd.h>
#include "spindump_util.h"
#include "spindump_protocols.h"
#include "spindump_table.h"
#include "spindump_eventformatter.h"

//
// Parameters ---------------------------------------------------------------------------------
//

#define SPINDUMP_PORT_NUMBER 5040
#define SPINDUMP_REMOTE_SERVER_MAX_CONNECTIONS 5
#define SPINDUMP_REMOTE_SERVER_MAX_CONNECTIONDATASIZE (50*1024)
#define SPINDUMP_REMOTE_MAXPATHCOMPONENTLENGTH 20
#define SPINDUMP_REMOTE_PATHSTART "/data/"

//
// Data structures ----------------------------------------------------------------------------
//

struct spindump_remote_connection {
  int active;
  int ongoingTransaction;
  int isPost;
  int isBufferOverrun;
  char identifier[SPINDUMP_REMOTE_MAXPATHCOMPONENTLENGTH+1];
  struct MHD_PostProcessor* postprocessor;
  size_t submissionLength;
  char submission[SPINDUMP_REMOTE_SERVER_MAX_CONNECTIONDATASIZE];
};

struct spindump_remote_server {
  spindump_port listenport;
  uint8_t padding[2]; // unused padding to align the next field properly
  struct MHD_Daemon* daemon;
  struct spindump_remote_connection clients[SPINDUMP_REMOTE_SERVER_MAX_CONNECTIONS];
};

//
// External API interface to the server module ------------------------------------------------
//

struct spindump_remote_server*
spindump_remote_server_init(spindump_port port);
int
spindump_remote_server_getupdate(struct spindump_remote_server* server);
void
spindump_remote_server_close(struct spindump_remote_server* server);

#endif // SPINDUMP_REMOTE_SERVER_H
