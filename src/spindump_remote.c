
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

//
// Includes -----------------------------------------------------------------------------------
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include "spindump_util.h"
#include "spindump_remote.h"

//
// Actual code --------------------------------------------------------------------------------
//

//
// Server API
//

struct spindump_remote_server*
spindump_remote_server_init() {
  unsigned int size = sizeof(struct spindump_remote_server);
  struct spindump_remote_server* server = (struct spindump_remote_server*)malloc(size);
  if (server == 0) {
    spindump_errorf("cannot allocate server of %u bytes", size);
    return(0);
  }
  
  memset(server,0,sizeof(*server));
  server->listenfd = -1;
  server->listenport = SPINDUMP_PORT_NUMBER;
  
  // ...
  
  spindump_warnf("server not implemented yet");
  return(server);
}

void
spindump_remote_server_update(struct spindump_remote_server* server,
			      struct spindump_connectionstable* table) {
  spindump_assert(server != 0);
  for (unsigned int i = 0; i < SPINDUMP_REMOTE_SERVER_MAX_CONNECTIONS; i++) {
    struct spindump_remote_connection* client = &server->clients[i];
    if (client->active) {
      // ...
    }
  }
}

void
spindump_remote_server_close(struct spindump_remote_server* server) {
  spindump_assert(server != 0);
  for (unsigned int i = 0; i < SPINDUMP_REMOTE_SERVER_MAX_CONNECTIONS; i++) {
    struct spindump_remote_connection* client = &server->clients[i];
    if (client->active) {
      client->active = 0;
      close(client->fd);
    }
  }
  close(server->listenfd);
  free(server);
}

//
// Client API
// 

struct spindump_remote_client*
spindump_remote_client_init(const char* name) {
  unsigned int size = sizeof(struct spindump_remote_client);
  struct spindump_remote_client* client = (struct spindump_remote_client*)malloc(size);
  if (client == 0) {
    spindump_errorf("cannot allocate client of %u bytes", size);
    return(0);
  }
  memset(client,0,sizeof(*client));
  
  // ...
  spindump_errorf("client not implemented yet");
  return(0);
}

void
spindump_remote_client_update(struct spindump_remote_client* client,
			      struct spindump_connectionstable* table) {
  // ...
}

void
spindump_remote_client_close(struct spindump_remote_client* client) {
  spindump_assert(client != 0);
  close(client->fd);
  free(client);
}

