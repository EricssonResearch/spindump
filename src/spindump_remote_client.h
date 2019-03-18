
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

#ifndef SPINDUMP_REMOTE_CLIENT_H
#define SPINDUMP_REMOTE_CLIENT_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <curl/curl.h>
#include <microhttpd.h>
#include "spindump_util.h"
#include "spindump_protocols.h"
#include "spindump_table.h"
#include "spindump_eventformatter.h"

//
// Parameters ---------------------------------------------------------------------------------
//

#define SPINDUMP_REMOTE_CLIENT_MAX_CONNECTIONS 5

//
// Data structures ----------------------------------------------------------------------------
//

struct spindump_remote_client {
  const char* url;
  CURL* curl;
};

//
// External API interface to the client module ------------------------------------------------
//

struct spindump_remote_client*
spindump_remote_client_init(const char* url);
void
spindump_remote_client_update_periodic(struct spindump_remote_client* client,
				       struct spindump_connectionstable* table);
void
spindump_remote_client_update_event(struct spindump_remote_client* client,
				    const char* mediaType,
				    unsigned long length,
				    const uint8_t* data);
void
spindump_remote_client_close(struct spindump_remote_client* client);

#endif // SPINDUMP_REMOTE_CLIENT_H
