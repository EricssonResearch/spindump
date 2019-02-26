
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
#include "spindump_util.h"
#include "spindump_analyze.h"
#include "spindump_connections.h"
#include "spindump_eventformatter.h"
#include "spindump_eventformatter_text.h"
#include "spindump_eventformatter_json.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static void
spindump_eventformatter_measurement_begin(struct spindump_eventformatter* formatter);
static void
spindump_eventformatter_measurement_end(struct spindump_eventformatter* formatter);
static void
spindump_eventformatter_measurement_one(struct spindump_analyze* state,
					void* handlerData,
					void** handlerConnectionData,
					spindump_analyze_event event,
					struct spindump_packet* packet,
					struct spindump_connection* connection);

//
// Actual code --------------------------------------------------------------------------------
//

struct spindump_eventformatter*
spindump_eventformatter_initialize(struct spindump_analyze* analyzer,
				   enum spindump_eventformatter_outputformat format,
				   FILE* file,
				   struct spindump_reverse_dns* querier,
				   int anonymizeLeft,
				   int anonymizeRight) {

  //
  // Allocate an object
  //
  
  unsigned int siz = sizeof(struct spindump_eventformatter);
  struct spindump_eventformatter* formatter = (struct spindump_eventformatter*)malloc(siz);
  if (formatter == 0) {
    spindump_errorf("cannot allocate memory for the event formatter (%u bytes)", siz);
    return(0);
  }

  //
  // Fill in the contents
  //
  
  formatter->analyzer = analyzer;
  formatter->format = format;
  formatter->file = file;
  formatter->querier = querier;
  formatter->anonymizeLeft = anonymizeLeft;
  formatter->anonymizeRight = anonymizeRight;
  
  //
  // Start the format by adding whatever prefix is needed in the output stream
  //
  
  spindump_eventformatter_measurement_begin(formatter);
  
  //
  // Register a handler for relevant events
  //
  
  spindump_analyze_registerhandler(analyzer,
				   spindump_analyze_event_alllegal,
				   spindump_eventformatter_measurement_one,
				   formatter);

  //
  // Done. Return the object.
  //

  return(formatter);
}

void
spindump_eventformatter_uninitialize(struct spindump_eventformatter* formatter) {

  //
  // Sanity checks
  //
  
  spindump_assert(formatter != 0);
  spindump_assert(formatter->file != 0);
  spindump_assert(formatter->analyzer != 0);

  //
  // Emit whatever post-amble is needed in the output
  //
  
  spindump_eventformatter_measurement_end(formatter);
  
  //
  // Unregister whatever we registered as handlers in the analyzer
  //

  spindump_analyze_unregisterhandler(formatter->analyzer,
				     spindump_analyze_event_alllegal,
				     spindump_eventformatter_measurement_one,
				     formatter);
  
  //
  // Free the memory
  //
  
  free(formatter);
}

static void
spindump_eventformatter_measurement_begin(struct spindump_eventformatter* formatter) {
  switch (formatter->format) {
  case spindump_eventformatter_outputformat_text:
    spindump_eventformatter_measurement_begin_text(formatter);
    break;
  case spindump_eventformatter_outputformat_json:
    spindump_eventformatter_measurement_begin_json(formatter);
    break;
  default:
    spindump_errorf("invalid output format in internal variable");
    exit(1);
  }
}

static void
spindump_eventformatter_measurement_end(struct spindump_eventformatter* formatter) {
  switch (formatter->format) {
  case spindump_eventformatter_outputformat_text:
    spindump_eventformatter_measurement_end_text(formatter);
    break;
  case spindump_eventformatter_outputformat_json:
    spindump_eventformatter_measurement_end_json(formatter);
    break;
  default:
    spindump_errorf("invalid output format in internal variable");
    exit(1);
  }
}

//
// Function that gets called whenever a new RTT data has come in for
// any connection.  This is activated when the --textual mode is on.
//

static void
spindump_eventformatter_measurement_one(struct spindump_analyze* state,
					void* handlerData,
					void** handlerConnectionData,
					spindump_analyze_event event,
					struct spindump_packet* packet,
					struct spindump_connection* connection) {

  //
  // Sanity checks
  //

  //
  // Dig up the relevant data from the handlerData pointer etc
  //
  
  struct spindump_eventformatter* formatter = (struct spindump_eventformatter*)handlerData;
  struct spindump_reverse_dns* querier = formatter->querier;
  const char* type = spindump_connection_type_to_string(connection->type);
  const char* addrs = spindump_connection_addresses(connection,
						    70,
						    formatter->anonymizeLeft,
						    formatter->anonymizeRight,
						    querier);
  const char* session = spindump_connection_sessionstring(connection,70);

  //
  // Based on the format type, provide different kinds of output
  //
  
  switch (formatter->format) {
  case spindump_eventformatter_outputformat_text:
    spindump_eventformatter_measurement_one_text(formatter,event,connection,type,addrs,session,&packet->timestamp);
    break;
  case spindump_eventformatter_outputformat_json:
    spindump_eventformatter_measurement_one_json(formatter,event,connection,type,addrs,session,&packet->timestamp);
    break;
  default:
    spindump_errorf("invalid output format in internal variable");
    exit(1);
  }
}


