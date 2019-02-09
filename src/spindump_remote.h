
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

#ifndef SPINDUMP_REMOTE_H
#define SPINDUMP_REMOTE_H

//
// Includes -----------------------------------------------------------------------------------
//

#include "spindump_util.h"
#include "spindump_protocols.h"
#include "spindump_table.h"

//
// Parameters ---------------------------------------------------------------------------------
//

#define SPINDUMP_PORT_NUMBER 5040
#define SPINDUMP_REMOTE_SERVER_MAX_CONNECTIONS 10
#define SPINDUMP_REMOTE_CLIENT_MAX_CONNECTIONS 10

//
// Data structures ----------------------------------------------------------------------------
//

struct spindump_remote_connection {
  int active;
  int fd;
};

struct spindump_remote_server {
  int listenfd;
  spindump_port listenport;
  struct spindump_remote_connection clients[SPINDUMP_REMOTE_SERVER_MAX_CONNECTIONS];
};

struct spindump_remote_client {
  const char* server;
  spindump_port serverport;
  int fd;
};

//
// External API interface to the server module ------------------------------------------------
//

struct spindump_remote_server*
spindump_remote_server_init(void);

void
spindump_remote_server_update(struct spindump_remote_server* server,
			      struct spindump_connectionstable* table);

void
spindump_remote_server_close(struct spindump_remote_server* server);

//
// External API interface to the client module ------------------------------------------------
//

struct spindump_remote_client*
spindump_remote_client_init(const char* name);
void
spindump_remote_client_update(struct spindump_remote_client* client,
			      struct spindump_connectionstable* table);
void
spindump_remote_client_close(struct spindump_remote_client* client);

#endif // SPINDUMP_REMOTE_H
