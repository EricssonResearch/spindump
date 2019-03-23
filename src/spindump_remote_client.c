
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
#include "spindump_remote_client.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static size_t
spindump_remote_client_answer(void *buffer, size_t size, size_t nmemb, void *userp);

//
// Actual code --------------------------------------------------------------------------------
//

//
// Client API
// 

//
// Create an object to present a client that wants to access Spindump
// data from a server somewhere in the network.
//

struct spindump_remote_client*
spindump_remote_client_init(const char* url) {

  //
  // Allocate
  //
  
  unsigned int size = sizeof(struct spindump_remote_client);
  struct spindump_remote_client* client = (struct spindump_remote_client*)malloc(size);
  if (client == 0) {
    spindump_errorf("cannot allocate client of %u bytes", size);
    return(0);
  }

  //
  // Set the contents of the object
  //
  
  memset(client,0,sizeof(*client));
  client->url = url;
  client->curl = curl_easy_init();

  //
  // Done
  //
  
  return(client);
}

//
// Send a periodic update to the server
//

void
spindump_remote_client_update_periodic(struct spindump_remote_client* client,
				       struct spindump_connectionstable* table) {
  // ..
  spindump_deepdebugf("spindump_remote_client_update_periodic, data: ");
  spindump_errorf("periodic updates not implemented");
}

//
// Send an update for a specific event to the server (or pool updates,
// if so requested).
//

void
spindump_remote_client_update_event(struct spindump_remote_client* client,
				    const char* mediaType,
				    unsigned long length,
				    const uint8_t* data) {

  //
  // Configure the request
  //

  curl_easy_setopt(client->curl, CURLOPT_URL, client->url);
  curl_easy_setopt(client->curl, CURLOPT_POSTFIELDS, data);
  curl_easy_setopt(client->curl, CURLOPT_POSTFIELDSIZE, length);
  curl_easy_setopt(client->curl, CURLOPT_WRITEFUNCTION, spindump_remote_client_answer);
  spindump_debugf("performing a post on %s...", client->url);
  if (length > 0 && (data[0] == '[' || data[0] == '{')) {
    spindump_deepdebugf("data: %s", data);
  }

  //
  // Perform the request, res will get the return code
  //
  
  CURLcode res = curl_easy_perform(client->curl);
  
  //
  // Check for errors
  //
  
  if (res != CURLE_OK) {
    spindump_debugf("failed");
    spindump_errorf("remote request to %s failed: %s",
		    client->url,
		    curl_easy_strerror(res));
  }
  spindump_debugf("Ok");
}

//
// Close the client, i.e., no longer send updates to the server.
//

void
spindump_remote_client_close(struct spindump_remote_client* client) {
  spindump_assert(client != 0);
  curl_easy_cleanup(client->curl);
  free(client);
}

//
// By default, CURL writes any answer from a HTTP POST to stdout. This
// function will not do this.
//

static size_t
spindump_remote_client_answer(void *buffer, size_t size, size_t nmemb, void *userp) {
  return(size * nmemb);
}
