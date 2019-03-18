
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
#include "spindump_remote_server.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static int
spindump_remote_server_answer(void *cls,
			      struct MHD_Connection *connection,
			      const char *url,
			      const char *method,
			      const char *version,
			      const char *upload_data,
			      size_t *upload_data_size,
			      void **con_cls);
static struct spindump_remote_connection* 
spindump_remote_server_getconnectionobject(struct spindump_remote_server* server,
					   const char* identifier);
static void
spindump_remote_server_releaseconnectionobject(struct spindump_remote_server* server,
					       struct spindump_remote_connection* connection);
static int
spindump_remote_server_answer_error(struct MHD_Connection *connection,
				    unsigned int code,
				    char* why);
static void
spindump_remote_server_printparameters(struct MHD_Connection *connection);
static int
spindump_remote_server_printparameter(void *cls,
				      enum MHD_ValueKind kind, 
				      const char *key,
				      const char *value);
static void
spindump_remote_server_requestcompleted(void *cls,
					struct MHD_Connection *connection, 
					void **con_cls,
					enum MHD_RequestTerminationCode toe);
static int
spindump_remote_server_answertopost(struct spindump_remote_server* server,
				    struct spindump_remote_connection* connectionObject,
				    struct MHD_Connection *connection);
static int
spindump_remote_server_postiterator(void *coninfo_cls,
				    enum MHD_ValueKind kind,
				    const char *key,
				    const char *filename,
				    const char *content_type,
				    const char *transfer_encoding,
				    const char *data, 
				    uint64_t off, size_t size);
static int
spindump_remote_server_adddata(struct spindump_remote_connection* connectionObject,
			       const char* data,
			       size_t length);

//
// Actual code --------------------------------------------------------------------------------
//

//
// Create an object to represent perform a server function to listen
// for requests for Spindump data. Use the "Microhttpd" library to do
// the actual HTTP/HTTPS server work here.
//

struct spindump_remote_server*
spindump_remote_server_init(spindump_port port) {
  unsigned int size = sizeof(struct spindump_remote_server);
  struct spindump_remote_server* server = (struct spindump_remote_server*)malloc(size);
  if (server == 0) {
    spindump_errorf("cannot allocate server of %u bytes", size);
    return(0);
  }
  
  memset(server,0,sizeof(*server));
  server->listenport = port;
  server->daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, server->listenport,
				    NULL, NULL,
				    spindump_remote_server_answer, server,
				    MHD_OPTION_NOTIFY_COMPLETED, &spindump_remote_server_requestcompleted, server,
				    MHD_OPTION_END);
  if (server->daemon == 0) {
    spindump_errorf("cannot open a server daemon on port %u", server->listenport);
    free(server);
    return(0);
  }
  
  return(server);
}

//
// Close the server object and all connections associated with it.
//

void
spindump_remote_server_close(struct spindump_remote_server* server) {
  spindump_assert(server != 0);
  for (unsigned int i = 0; i < SPINDUMP_REMOTE_SERVER_MAX_CONNECTIONS; i++) {
    struct spindump_remote_connection* client = &server->clients[i];
    if (client->active) {
      client->active = 0;
    }
  }
  if (server->daemon != 0) {
    MHD_stop_daemon(server->daemon);
  }
  free(server);
}

//
// The server object queues up events reported by others in an
// internal data structure, as the web events come in another thread.
// The spindump_remote_server_getupdate function pulls one such
// reported event from the server queue and lets the caller handle it.
//
// This function is incomplete as of today, waiting for the
// implementation of representing events using some kind of data
// structure.
//

int
spindump_remote_server_getupdate(struct spindump_remote_server* server) {
  // ... TODO ....
  return(0);
}

//
// Find or allocate a connection object that can be used to store
// information belonging to a particular client.
//
// A connection object is connection to one client, identified by the
// clients identity that it itself gives when connecting to this
// server, by POSTing to example.net/data/id where "id" is the
// identity of the client. Each client can have at most one
// transaction going on at any one time.
//

static struct spindump_remote_connection* 
spindump_remote_server_getconnectionobject(struct spindump_remote_server* server,
					   const char* identifier) {

  //
  // Sanity checks
  //

  spindump_assert(server != 0);
  spindump_assert(identifier != 0);
  spindump_assert(strlen(identifier) > 0);

  //
  // Look for an exiting connection object for that identifier
  //

  struct spindump_remote_connection* firstFreeConnection = 0;
  for (unsigned int i = 0; i < SPINDUMP_REMOTE_SERVER_MAX_CONNECTIONS; i++) {
    struct spindump_remote_connection* connection = &server->clients[i];
    if (connection->active) {
      if (strcmp(identifier,connection->identifier) == 0) {
	spindump_deepdebugf("spindump_remote_server_getconnectionobject finds an existing connection object in index %u", i);
	return(connection);
      }
    } else if (firstFreeConnection == 0) {
      firstFreeConnection = connection;
    }
  }
  
  //
  // Not found and no space
  //
  
  if (firstFreeConnection == 0) {
    spindump_deepdebugf("spindump_remote_server_getconnectionobject cannot find space for a new connection object");
    spindump_errorf("cannot find space for a new connection table object for %s -- too many clients?", identifier);
    return(0);
  }

  //
  // Not found but we can allocate a new one
  //
  
  memset(firstFreeConnection,0,sizeof(*firstFreeConnection));
  firstFreeConnection->active = 1;
  firstFreeConnection->ongoingTransaction = 0;
  strncpy(firstFreeConnection->identifier,identifier,sizeof(firstFreeConnection->identifier)-1);
  firstFreeConnection->submissionLength = 0;
  spindump_deepdebugf("spindump_remote_server_getconnectionobject found space for a new connection object");
  return(firstFreeConnection);
}

//
// Release a connection object that is no longer needed. It does not
// get deallocated; the memory is part of the server object. But it
// does get marked inactive and any other resources released
//

static void
spindump_remote_server_releaseconnectionobject(struct spindump_remote_server* server,
					       struct spindump_remote_connection* connection) {
  //
  // Sanity checks
  //

  spindump_deepdebugf("spindump_remote_server_releaseconnectionobject");
  spindump_assert(server != 0);
  spindump_assert(connection != 0);
  spindump_assert(connection->active);
  spindump_assert(connection >= &server->clients[0]);
  spindump_assert(connection < &server->clients[SPINDUMP_REMOTE_SERVER_MAX_CONNECTIONS]);
  
  //
  // Release resources
  //

  if (connection->postprocessor != 0) {
    MHD_destroy_post_processor(connection->postprocessor);
    connection->postprocessor = 0;
  }
  connection->active = 0;
}

//
// Provide a HTTP error as an answer
//

static int
spindump_remote_server_answer_error(struct MHD_Connection *connection,
				    unsigned int code,
				    char* why) {
  spindump_deepdebugf("spindump_remote_server_answer_error");
  spindump_debugf("HTTP response %u because %s", code, why);
  struct MHD_Response *response = MHD_create_response_from_buffer (strlen(why),
								   (void*)why,
								   MHD_RESPMEM_PERSISTENT);
  int ret = MHD_queue_response(connection, code, response);
  MHD_destroy_response(response);
  return(ret);
}

//
// Print a HTTP paremeter (for debugging purposes).
//

static int
spindump_remote_server_printparameter(void *cls,
				      enum MHD_ValueKind kind, 
				      const char *key,
				      const char *value) {
  spindump_deepdebugf("%s: %s", key, value);
  return(MHD_YES);
}

//
// Print all HTTP paremeters (for debugging purposes).
//

static void
spindump_remote_server_printparameters(struct MHD_Connection *connection) {
  MHD_get_connection_values(connection, MHD_HEADER_KIND, spindump_remote_server_printparameter, NULL);
}

//
// The Microhttpd library requires a "post iterator" to be run before
// a request processing is complete. Since all data in the post has
// already been collected earlier as it came in, there's nothing we
// need to do here though.
//

static int
spindump_remote_server_postiterator(void *coninfo_cls,
				    enum MHD_ValueKind kind,
				    const char *key,
				    const char *filename,
				    const char *content_type,
				    const char *transfer_encoding,
				    const char *data,
				    uint64_t off,
				    size_t size) {
  spindump_deepdebugf("post iterator (%s, %s, %u bytes) %s", content_type, transfer_encoding, size, data);
  struct spindump_remote_connection* connectionObject =
    (struct spindump_remote_connection*)coninfo_cls;
  spindump_assert(connectionObject != 0);
  return(MHD_YES);
}

//
// Once a POST is complete, we need to answer. Depending on whether we
// got data at all or got it too much or got right amount of it, we
// will give different answers.
//

static int
spindump_remote_server_answertopost(struct spindump_remote_server* server,
				    struct spindump_remote_connection* connectionObject,
				    struct MHD_Connection *connection) {
  
  //
  // Respond to the POST
  //
  
  spindump_deepdebugf("spindump_remote_server_answertopost, collected submission length %u (error %u)",
		      connectionObject->submissionLength,
		      connectionObject->isBufferOverrun);
  if (connectionObject->isBufferOverrun) {
    return(spindump_remote_server_answer_error(connection,
					       MHD_HTTP_BAD_REQUEST,
					       "<html><p>data does not fit in buffer</p></html>\n"));
  }
  if (connectionObject->submissionLength == 0) {
    return(spindump_remote_server_answer_error(connection,
					       MHD_HTTP_BAD_REQUEST,
					       "<html><p>no data provided in POST</p></html>\n"));
  }

  struct MHD_Response *response = MHD_create_response_from_buffer(0,
								  (void*)"",
								  MHD_RESPMEM_PERSISTENT);
  unsigned int code = MHD_HTTP_OK;
  spindump_debugf("HTTP successful response %u", code);
  int ret = MHD_queue_response(connection, code, response);
  MHD_destroy_response(response);
  connectionObject->ongoingTransaction = 0;
  return(ret);
}  

//
// We have a fragment of data associated with a POST to the
// server. Add that to the buffer. Watch for buffer overruns, and if
// one would occur, prevent that and mark that an error occurred.
//

static int
spindump_remote_server_adddata(struct spindump_remote_connection* connectionObject,
			       const char* data,
			       size_t length) {
  spindump_deepdebugf("spindump_remote_server_adddata");
  spindump_assert(data != 0);
  if (connectionObject->isBufferOverrun) {
    spindump_deepdebugf("already seen an error, ignoring data");
    return(MHD_NO);
  } else if (connectionObject->submissionLength + length <=
      sizeof(connectionObject->submission)) {
    memcpy(&connectionObject->submission[connectionObject->submissionLength],
	   data,
	   length);
    connectionObject->submissionLength += length;
    spindump_deepdebugf("submission from %s grew to %u bytes by %u bytes",
			connectionObject->identifier,
			connectionObject->submissionLength,
			length);
    return(MHD_YES);
  } else {
    spindump_errorf("cannot add extra %u bytes of bdata to a buffer from a request from %s",
		    length,
		    connectionObject->identifier);
    connectionObject->isBufferOverrun = 1;
    return(MHD_NO);
  }
}

//
// The Microhttpd library calls the spindump_remote_server_answer
// callback whenever a HTTP request is made. In our case this function
// will ensure that the correct type of q request was made (to the
// right path, right method, etc).
//

static int
spindump_remote_server_answer(void *cls,
			      struct MHD_Connection *connection,
			      const char *url,
			      const char *method,
			      const char *version,
			      const char *upload_data,
			      size_t *upload_data_size,
			      void **con_cls)
{
  spindump_deepdebugf("spindump_remote_server_answer");
  struct spindump_remote_server* server = (struct spindump_remote_server*)cls;
  
  //
  // Sanity checks
  //
  
  spindump_assert(server != 0);
  spindump_assert(server->daemon != 0);
  spindump_assert(connection != 0);
  spindump_assert(url != 0);
  spindump_assert(method != 0);
  spindump_assert(version != 0);
  
  //
  // Debugs
  //
  
  spindump_debugf("received a %s on URL %s", method, url);
  spindump_remote_server_printparameters(connection);
  
  //
  // Check that this is a properly formatted request
  //
  
  if (strcmp(method,"POST") != 0) {
    return(spindump_remote_server_answer_error(connection,
					       MHD_HTTP_METHOD_NOT_ALLOWED,
					       "<html><p>invalid method</p></html>\n"));
  }
  
  if (strncmp(url,SPINDUMP_REMOTE_PATHSTART,strlen(SPINDUMP_REMOTE_PATHSTART)) != 0) {
    return(spindump_remote_server_answer_error(connection,
					       MHD_HTTP_BAD_REQUEST,
					       "<html><p>expected URL to start with " SPINDUMP_REMOTE_PATHSTART "</p></html>\n"));
  }
  
  const char* remainingPathInput = url + strlen(SPINDUMP_REMOTE_PATHSTART);
  if (strlen(remainingPathInput) > SPINDUMP_REMOTE_MAXPATHCOMPONENTLENGTH) {
    return(spindump_remote_server_answer_error(connection,
					       MHD_HTTP_BAD_REQUEST,
					       "<html><p>path component too long</p></html>\n"));
  }
  
  char remainingPath[SPINDUMP_REMOTE_MAXPATHCOMPONENTLENGTH];
  memset(remainingPath,0,sizeof(remainingPath));
  strncpy(remainingPath,remainingPathInput,SPINDUMP_REMOTE_MAXPATHCOMPONENTLENGTH);
  if (strlen(remainingPath) > 0 && remainingPath[strlen(remainingPath)-1] == '/') {
    remainingPath[strlen(remainingPath)-1] = 0;
  }
  
  if (strlen(remainingPath) == 0 ||
      index(remainingPath,'/') != 0) {
    return(spindump_remote_server_answer_error(connection,
					       MHD_HTTP_BAD_REQUEST,
					       "<html><p>expected exactly two path components</p></html>\n"));
  }
  
  //
  // Determine the senders's identifier from the URL (whatever comes after "/data/")
  //
  
  const char* identifier = remainingPath;
  spindump_deepdebugf("remote data submission sender's identity = %s", identifier);
  
  //
  // Setup the necessary callbacks and status structures
  //
  
  if (*con_cls == 0) {

    //
    // Setup connection information object in microhttpd
    //
    
    struct spindump_remote_connection* connectionObject =
      spindump_remote_server_getconnectionobject(server,identifier);
    if (connectionObject == 0) return(MHD_NO);

    //
    // If the connection object is already processing something,
    // refuse to add another transaction
    //

    if (connectionObject->ongoingTransaction) {
      return(spindump_remote_server_answer_error(connection,
						 MHD_HTTP_BAD_REQUEST,
						 "<html><p>only one transaction per client allowed</p></html>\n"));
    }
    
    //
    // Otherwise, initialize the connection object properly.
    //
    
    *con_cls = connectionObject;
    connectionObject->isPost = 0;
    connectionObject->ongoingTransaction = 1;
    
    //
    // Setup a post processor for any submitted post data, also in
    // microhttpd
    //
    
    if (strcmp(method,"POST") == 0) {
      
      connectionObject->isPost = 1;
      spindump_assert(connectionObject->postprocessor == 0);
      connectionObject->postprocessor = MHD_create_post_processor(connection,
								  SPINDUMP_REMOTE_SERVER_MAX_CONNECTIONDATASIZE, 
								  spindump_remote_server_postiterator,
								  (void*)connectionObject);
      spindump_deepdebugf("post processor created for max %u bytes", SPINDUMP_REMOTE_SERVER_MAX_CONNECTIONDATASIZE);
      if (connectionObject->postprocessor == 0) {
	spindump_remote_server_releaseconnectionobject(server,connectionObject);
	return(MHD_NO);
      }
      
    }
    
    *con_cls = connectionObject;
    return(MHD_YES);
    
  }
  
  //
  // Otherwise this is a continuation of an existing request
  //
  
  struct spindump_remote_connection* existingConnectionObject =
    (struct spindump_remote_connection*)*con_cls;
  spindump_assert(existingConnectionObject != 0);
  spindump_deepdebugf("continuing an existing request");
  
  //
  // Determinew what type of a request it is
  //

  if (existingConnectionObject->isPost) {
    
    //
    // Process the data in the POST
    //
    
    spindump_deepdebugf("submitted data (length %lu) = %s", *upload_data_size, upload_data);

    if (*upload_data_size > 0) {

      spindump_deepdebugf("adding data to buffer");
      if (spindump_remote_server_adddata(existingConnectionObject,
					 upload_data,
					 *upload_data_size) != MHD_YES) {
	spindump_deepdebugf("saw an error, we've already flagged it but need to continue processing");
	spindump_assert(existingConnectionObject->isBufferOverrun);
      }
      spindump_deepdebugf("calling MHD_post_process");
      MHD_post_process(existingConnectionObject->postprocessor, upload_data,	
		       *upload_data_size);
      spindump_deepdebugf("MHD_post_process call returned");
      *upload_data_size = 0;
      return(MHD_YES);
      
    } else {

      spindump_deepdebugf("no submitted data so going to answer");
      return(spindump_remote_server_answertopost(server,existingConnectionObject,connection));
      
    }
    
  } else {
    
    //
    // An error. We do not support other types of requests.
    //
    
    return(spindump_remote_server_answer_error(connection,
					       MHD_HTTP_METHOD_NOT_ALLOWED,
					       "<html><p>invalid method</p></html>\n"));
    
  }
}

//
// The spindump_remote_server_requestcompleted function gets called
// when the POST request is complete; it will ensure that we both
// answer and release the associated connection object for subsequent
// use.
//

static void
spindump_remote_server_requestcompleted(void *cls,
					struct MHD_Connection *connection, 
					void **con_cls,
					enum MHD_RequestTerminationCode toe) {
  spindump_deepdebugf("spindump_remote_server_requestcompleted");
  
  struct spindump_remote_server* server = (struct spindump_remote_server*)cls;
  struct spindump_remote_connection* connectionObject = (struct spindump_remote_connection*)*con_cls;

  spindump_assert(cls != 0);
  spindump_assert(connection != 0);
  spindump_assert(server != 0);
  spindump_assert(con_cls != 0);
  
  if (connectionObject == 0) return;
  spindump_remote_server_answertopost(server,connectionObject,connection);
  spindump_remote_server_releaseconnectionobject(server,connectionObject);
  *con_cls = 0;   
}
