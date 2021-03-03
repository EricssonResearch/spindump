
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

//
// Includes -----------------------------------------------------------------------------------
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include "spindump_util.h"
#include "spindump_remote_file.h"
#include "spindump_json.h"
#include "spindump_json_value.h"
#include "spindump_event.h"
#include "spindump_event_parser_json.h"
#include "spindump_event_parser_qlog.h"
#include "spindump_analyze.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static void
spindump_remote_file_init_callback(const struct spindump_event* event,
                                   void* data);

//
// Actual code --------------------------------------------------------------------------------
//

//
// Create an object to represent perform a server function to listen
// for requests for Spindump data. Use the "Microhttpd" library to do
// the actual HTTP/HTTPS server work here.
//

struct spindump_remote_file*
spindump_remote_file_init(const char* filename) {

  //
  // Sanity checks
  //

  spindump_assert(filename != 0);
  spindump_deepdebugf("spindump_remote_file_init %s", filename);
  
  //
  // Allocate the object
  //
  
  size_t size = sizeof(struct spindump_remote_file);
  struct spindump_remote_file* object = (struct spindump_remote_file*)spindump_malloc(size);
  if (object == 0) {
    spindump_errorf("cannot allocate file object of %u bytes", size);
    return(0);
  }

  //
  // Initialize the object
  //
  
  memset(object,0,sizeof(*object));
  object->maxEvents = 1000;
  size = object->maxEvents * sizeof(struct spindump_event);
  object->events = (struct spindump_event*)spindump_malloc(size);
  if (object->events == 0) {
    spindump_errorf("cannot allocate file object of %u bytes", size);
    return(0);
  }
  
  //
  // Open the file
  //
  
  object->file = fopen(filename,"r");
  if (object->file == 0) {
    spindump_errorf("cannot open JSON file %s", filename);
    spindump_free(object->events);
    spindump_free(object);
    return(0);
  }

  fseek(object->file,0,SEEK_END);
  size_t fileSize =  (size_t)ftell(object->file);
  spindump_deepdebugf("spindump_remote_file_init file size = %u", fileSize);
  fseek(object->file,0,SEEK_SET);
  
  //
  // Read the file
  //

  size = fileSize+1;
  char* readBuffer  = spindump_malloc(size);
  if (object->events == 0) {
    spindump_errorf("cannot allocate file object of %u bytes", size);
    fclose(object->file);
    spindump_free(object->events);
    spindump_free(object);
    return(0);
  }
  memset(readBuffer,0,size);
  size_t res = fread(readBuffer,1,fileSize,object->file);
  spindump_deepdeepdebugf("read %u of %u bytes", res, fileSize);
  if (res != fileSize) {
    spindump_errorf("cannot read %u bytes of file %s contents", fileSize,filename);
    fclose(object->file);
    spindump_free(readBuffer);
    spindump_free(object->events);
    spindump_free(object);
    return(0);
  }
  spindump_deepdebugf("spindump_remote_file_init read, %u bytes", fileSize);
  
  //
  // Process the read text
  //
  
  const char* readPointer = readBuffer;
  size_t sizeLeft = fileSize;
  while (isspace(*readPointer) && sizeLeft > 0) { sizeLeft--; readPointer++; }
  while (sizeLeft > 0) {
    spindump_deepdebugf("spindump_remote_file_init reading input from index %u, %u left",
                        readPointer - readBuffer, sizeLeft);
    if (spindump_event_parser_json_textparse(&readPointer,
                                             spindump_remote_file_init_callback,
                                             object) == 0) {
      spindump_errorf("parsing error on JSON file %s position %u", filename, fileSize-sizeLeft);
      fclose(object->file);
      spindump_free(readBuffer);
      spindump_free(object->events);
      spindump_free(object);
      return(0);
    }
    sizeLeft = fileSize - ((size_t)(readPointer - readBuffer));
    spindump_deepdebugf("spindump_remote_file_init read input, now index %u, %u left, next char %c",
                        readPointer - readBuffer, sizeLeft, *readPointer);
    while (isspace(*readPointer) && sizeLeft > 0) { sizeLeft--; readPointer++; }
    spindump_deepdebugf("spindump_remote_file_init skipped whitespace, now index %u, %u left, next char %c",
                        readPointer - readBuffer, sizeLeft, *readPointer);
  }
  
  //
  // Done!
  //
  
  spindump_free(readBuffer);
  spindump_deepdebugf("spindump_remote_file_init done, events %u max %u",
                      object->nEvents, object->maxEvents);
  return(object);
}

//
// Helper function to receive one JSON / event object
//

static void
spindump_remote_file_init_callback(const struct spindump_event* event,
                                   void* data) {

  //
  // Sanity checks
  //
  
  spindump_deepdebugf("spindump_remote_file_init_callback");
  spindump_assert(event != 0);
  spindump_assert(data != 0);

  //
  // Acquire the necessary objects
  //

  struct spindump_remote_file* object = (struct spindump_remote_file*)data;

  //
  // More sanity checks
  //

  spindump_assert(object->events != 0);
  spindump_assert(object->maxEvents > 0);
  spindump_assert(object->nEvents <= object->maxEvents);

  //
  // Do we need more space in the events table?
  //

  if (object->nEvents == object->maxEvents) {
    unsigned int newMaxEvents = object->maxEvents * 2;
    size_t size = newMaxEvents * sizeof(struct spindump_event);
    struct spindump_event* newEvents = (struct spindump_event*)spindump_malloc(size);
    if (newEvents == 0) {
      spindump_errorf("cannot allocate %u bytes for events from a JSON file", size);
      return;
    }
    memcpy(newEvents,object->events,object->maxEvents  * sizeof(struct spindump_event));
    spindump_free(object->events);
    object->events = newEvents;
    object->maxEvents = newMaxEvents;
  }

  //
  // Add the event to the table
  //

  spindump_deepdeepdebugf("adding a new event (%uth) to the event table of JSON file events for timestamp %llu",
                          object->nEvents+1,
                          event->timestamp);
  spindump_assert(object->nEvents < object->maxEvents);
  object->events[object->nEvents++] = *event;
}

//
// Close the file object and all open file reads
//

void
spindump_remote_file_close(struct spindump_remote_file* object) {
  spindump_assert(object != 0);
  if (object->file != 0) fclose(object->file);
  if (object->events != 0) spindump_free(object->events);
  spindump_free(object);
}

//
// The file object queues up events reported by others in an
// internal data structure.
// The spindump_remote_file_getupdate function pulls one such
// reported event from the server queue and lets the caller handle it.
//

int
spindump_remote_file_getupdate(struct spindump_remote_file* object,
                               struct spindump_analyze* analyzer,
                               struct timeval* timestamp) {

  //
  // Sanity checks and debugs
  //

  spindump_deepdebugf("spindump_remote_file_getupdate");
  spindump_assert(object != 0);
  spindump_assert(analyzer != 0);
  
  //
  // Check if there is items for us to take
  //

  if (object->nEvents > 0) {
    for (unsigned int i = 0; i < object->nEvents; i++) {
      const struct spindump_event* event = &object->events[i];
      struct spindump_connection* connection = 0;
      spindump_timestamp_to_timeval(event->timestamp,timestamp);
      spindump_deepdeepdebugf("spindump_remote_file_getupdate reading timestamp %llu from callback", event->timestamp);
      spindump_analyze_processevent(analyzer,event,&connection);
    }
    object->nEvents = 0;
    return(1);
  } else {
    return(0);
  }
}
