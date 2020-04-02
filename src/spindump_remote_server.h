
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
#include "spindump_json.h"

//
// Parameters ---------------------------------------------------------------------------------
//

#define SPINDUMP_PORT_NUMBER 5040
#define SPINDUMP_REMOTE_SERVER_MAX_CONNECTIONS 5
#define SPINDUMP_REMOTE_SERVER_MAX_CONNECTIONDATASIZE (50*1024)
#define SPINDUMP_REMOTE_MAXPATHCOMPONENTLENGTH 20
#define SPINDUMP_REMOTE_PATHSTART "/data/"
#define SPINDUMP_REMOTE_SERVER_MAXSUBMISSIONS  1000

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
  spindump_port listenport;                           // used by main thread only
  uint8_t padding[2];                                 // unused padding to align the next field properly
  struct MHD_Daemon* daemon;                          // used by main thread only
  struct spindump_remote_connection
   clients[SPINDUMP_REMOTE_SERVER_MAX_CONNECTIONS];   // used by main thread only
  struct spindump_json_schema schema;                 // written by main thread only, read by daemon thread
  atomic_bool exit;                                   // written by main thread, read by daemon thread
  atomic_uint nextAddItemIndex;                       // written by daemon thread, read by main thread
  atomic_uint nextConsumeItemIndex;                   // written by main thread, read by daemon thread
  struct spindump_json_value*
      items[SPINDUMP_REMOTE_SERVER_MAXSUBMISSIONS];   // written by daemon thread, read by the main thread
};

//
// External API interface to the server module ------------------------------------------------
//

struct spindump_remote_server*
spindump_remote_server_init(spindump_port port);
int
spindump_remote_server_getupdate(struct spindump_remote_server* server,
                                 struct spindump_analyze* analyzer);
void
spindump_remote_server_close(struct spindump_remote_server* server);

#endif // SPINDUMP_REMOTE_SERVER_H
