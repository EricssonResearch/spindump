
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
#include <string.h>
#include "spindump_util.h"
#include "spindump_analyze.h"
#include "spindump_connections.h"
#include "spindump_remote_client.h"
#include "spindump_eventformatter.h"
#include "spindump_eventformatter_text.h"
#include "spindump_eventformatter_json.h"
#include "spindump_event.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static unsigned long
spindump_eventformatter_measurement_beginlength(struct spindump_eventformatter* formatter);
static void
spindump_eventformatter_measurement_begin(struct spindump_eventformatter* formatter);
static const uint8_t*
spindump_eventformatter_measurement_beginaux(struct spindump_eventformatter* formatter,
					     unsigned long* length);
static unsigned long
spindump_eventformatter_measurement_endlength(struct spindump_eventformatter* formatter);
static void
spindump_eventformatter_measurement_end(struct spindump_eventformatter* formatter);
static const uint8_t*
spindump_eventformatter_measurement_endaux(struct spindump_eventformatter* formatter,
					   unsigned long* length);
static void
spindump_eventformatter_measurement_one(struct spindump_analyze* state,
					void* handlerData,
					void** handlerConnectionData,
					spindump_analyze_event event,
					struct spindump_packet* packet,
					struct spindump_connection* connection);
static struct spindump_eventformatter*
spindump_eventformatter_initialize(struct spindump_analyze* analyzer,
				   enum spindump_eventformatter_outputformat format,
				   struct spindump_reverse_dns* querier,
				   int anonymizeLeft,
				   int anonymizeRight);
static const char*
spindump_eventformatter_mediatype(enum spindump_eventformatter_outputformat format);
static void
spindump_eventformatter_deliverdata_remoteblock(struct spindump_eventformatter* formatter,
						unsigned long length,
						const uint8_t* data);

//
// Actual code --------------------------------------------------------------------------------
//

static struct spindump_eventformatter*
spindump_eventformatter_initialize(struct spindump_analyze* analyzer,
				   enum spindump_eventformatter_outputformat format,
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

  memset(formatter,0,sizeof(*formatter));
  formatter->analyzer = analyzer;
  formatter->format = format;
  formatter->file = 0;
  formatter->nRemotes = 0;
  formatter->remotes = 0;
  formatter->blockSize = 0;
  formatter->querier = querier;
  formatter->anonymizeLeft = anonymizeLeft;
  formatter->anonymizeRight = anonymizeRight;

  //
  // Register a handler for relevant events
  //
  
  spindump_analyze_registerhandler(analyzer,
				   spindump_analyze_event_alllegal,
				   0,
				   spindump_eventformatter_measurement_one,
				   formatter);

  //
  // Done. Return the object.
  //

  return(formatter);
}

struct spindump_eventformatter*
spindump_eventformatter_initialize_file(struct spindump_analyze* analyzer,
					enum spindump_eventformatter_outputformat format,
					FILE* file,
					struct spindump_reverse_dns* querier,
					int anonymizeLeft,
					int anonymizeRight) {
  
  //
  // Call the basic eventformatter initialization
  //

  struct spindump_eventformatter* formatter = spindump_eventformatter_initialize(analyzer,
										 format,
										 querier,
										 anonymizeLeft,
										 anonymizeRight);
  if (formatter == 0) {
    return(0);
  }
  
  //
  // Do the file-specific setup
  //

  formatter->file = file;
  
  //
  // Start the format by adding whatever prefix is needed in the output stream
  //
  
  spindump_eventformatter_measurement_begin(formatter);
  
  //
  // Done. Return the object.
  //

  return(formatter);
}

struct spindump_eventformatter*
spindump_eventformatter_initialize_remote(struct spindump_analyze* analyzer,
					  enum spindump_eventformatter_outputformat format,
					  unsigned int nRemotes,
					  struct spindump_remote_client** remotes,
					  unsigned long blockSize,
					  struct spindump_reverse_dns* querier,
					  int anonymizeLeft,
					  int anonymizeRight) {
  
  //
  // Call the basic eventformatter initialization
  //

  struct spindump_eventformatter* formatter = spindump_eventformatter_initialize(analyzer,
										 format,
										 querier,
										 anonymizeLeft,
										 anonymizeRight);
  if (formatter == 0) {
    return(0);
  }
  
  //
  // Do the remote-specific setup
  //

  formatter->nRemotes = nRemotes;
  formatter->remotes = remotes;
  formatter->blockSize = blockSize;
  
  //
  // Allocate the block buffer (if we can)
  //

  if (formatter->blockSize > 0) {
    formatter->block = (uint8_t*)malloc(formatter->blockSize);
    if (formatter->block == 0) {
      spindump_errorf("cannot allocate memory for the event formatter (%u bytes)", formatter->blockSize);
      free(formatter);
      return(0);
    }
    formatter->bytesInBlock = 0;
  }

  //
  // Check the preamble and postamble lengths
  //

  if (formatter->blockSize > 0 &&
      (spindump_eventformatter_measurement_beginlength(formatter) +
       spindump_eventformatter_measurement_endlength(formatter) >= formatter->blockSize ||
       spindump_eventformatter_measurement_beginlength(formatter) > spindump_eventformatter_maxpreamble ||
       spindump_eventformatter_measurement_beginlength(formatter) > spindump_eventformatter_maxpostamble)) {
    spindump_errorf("preamble and postamble lengths (%lu,%lu) are too large or exceed the block size %lu",
		    spindump_eventformatter_measurement_beginlength(formatter),
		    spindump_eventformatter_measurement_endlength(formatter),
		    formatter->blockSize);
    free(formatter->block);
    free(formatter);
    return(0);
  }
  
  //
  // Start the format by adding whatever prefix is needed in the output stream
  //
  
  if (formatter->blockSize > 0) {
    spindump_eventformatter_measurement_begin(formatter);
  }
  
  //
  // Done. Return the object.
  //
  
  return(formatter);
}

//
// Close the formatter, and emit any final text that may be needed
//

void
spindump_eventformatter_uninitialize(struct spindump_eventformatter* formatter) {

  //
  // Sanity checks
  //
  
  spindump_assert(formatter != 0);
  spindump_assert(formatter->file != 0 || formatter->nRemotes > 0);
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
				     0,
				     spindump_eventformatter_measurement_one,
				     formatter);
  
  //
  // Free the memory
  //
  
  free(formatter);
}

//
// Return the length of the preamble
//

static unsigned long
spindump_eventformatter_measurement_beginlength(struct spindump_eventformatter* formatter) {
  switch (formatter->format) {
  case spindump_eventformatter_outputformat_text:
    return(spindump_eventformatter_measurement_beginlength_text(formatter));
  case spindump_eventformatter_outputformat_json:
    return(spindump_eventformatter_measurement_beginlength_json(formatter));
  default:
    spindump_errorf("invalid output format in internal variable");
    return(0);
  }
}

static void
spindump_eventformatter_measurement_begin(struct spindump_eventformatter* formatter) {
  unsigned long length;
  const uint8_t* data = spindump_eventformatter_measurement_beginaux(formatter,&length);
  spindump_eventformatter_deliverdata(formatter,length,data);
}
 
static const uint8_t*
spindump_eventformatter_measurement_beginaux(struct spindump_eventformatter* formatter,
					     unsigned long* length) {
  *length = spindump_eventformatter_measurement_beginlength(formatter);
  switch (formatter->format) {
  case spindump_eventformatter_outputformat_text:
    return(spindump_eventformatter_measurement_begin_text(formatter));
  case spindump_eventformatter_outputformat_json:
    return(spindump_eventformatter_measurement_begin_json(formatter));
  default:
    spindump_errorf("invalid output format in internal variable");
    return((uint8_t*)"");
  }
}

static unsigned long
spindump_eventformatter_measurement_endlength(struct spindump_eventformatter* formatter) {
  switch (formatter->format) {
  case spindump_eventformatter_outputformat_text:
    return(spindump_eventformatter_measurement_endlength_text(formatter));
  case spindump_eventformatter_outputformat_json:
    return(spindump_eventformatter_measurement_endlength_json(formatter));
  default:
    spindump_errorf("invalid output format in internal variable");
    return(0);
  }
}

//
// Return the length of the postamble
//

static void
spindump_eventformatter_measurement_end(struct spindump_eventformatter* formatter) {
  unsigned long length;
  const uint8_t* data = spindump_eventformatter_measurement_endaux(formatter,&length);
  spindump_eventformatter_deliverdata(formatter,length,data);
}
 
static const uint8_t*
spindump_eventformatter_measurement_endaux(struct spindump_eventformatter* formatter,
					   unsigned long* length) {
  *length = spindump_eventformatter_measurement_endlength(formatter);
  switch (formatter->format) {
  case spindump_eventformatter_outputformat_text:
    return(spindump_eventformatter_measurement_end_text(formatter));
  case spindump_eventformatter_outputformat_json:
    return(spindump_eventformatter_measurement_end_json(formatter));
  default:
    spindump_errorf("invalid output format in internal variable");
    return((uint8_t*)"");
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
  const char* session = spindump_connection_sessionstring(connection,70);

  //
  // Construct the time stamp
  //
  
  unsigned long long timestamplonglong = ((unsigned long long)packet->timestamp.tv_sec) * 1000 * 1000 + (unsigned long long)packet->timestamp.tv_usec;
  
  //
  // Determine event type
  //
  
  enum spindump_event_type eventType;
  switch (event) {

  case spindump_analyze_event_newconnection:
    eventType = spindump_event_type_new_connection;
    break;

  case spindump_analyze_event_connectiondelete:
    eventType = spindump_event_type_connection_delete;
    break;

  case spindump_analyze_event_newleftrttmeasurement:
  case spindump_analyze_event_newrightrttmeasurement:
    eventType = spindump_event_type_new_rtt_measurement;
    break;

  case spindump_analyze_event_newinitrespfullrttmeasurement:
    eventType = spindump_event_type_new_rtt_measurement;
    break;

  case spindump_analyze_event_newrespinitfullrttmeasurement:
    eventType = spindump_event_type_new_rtt_measurement;

    break;

  case spindump_analyze_event_initiatorspinflip:
    spindump_assert(connection->type == spindump_connection_transport_quic);
    eventType = spindump_event_type_spin_flip;
    break;

  case spindump_analyze_event_responderspinflip:
    spindump_assert(connection->type == spindump_connection_transport_quic);
    eventType = spindump_event_type_spin_flip;
    break;

  case spindump_analyze_event_initiatorspinvalue:
    spindump_assert(connection->type == spindump_connection_transport_quic);
    eventType = spindump_event_type_spin_value;
    break;

  case spindump_analyze_event_responderspinvalue:
    spindump_assert(connection->type == spindump_connection_transport_quic);
    eventType = spindump_event_type_spin_value;
    break;

  case spindump_analyze_event_initiatorecnce:
    eventType = spindump_event_type_ecn_congestion_event;
    break;

  case spindump_analyze_event_responderecnce:
    eventType = spindump_event_type_ecn_congestion_event;
    break;

  default:
    return;

  }
  
  //
  // Create an event object
  //

  struct spindump_event eventobj;
  spindump_network initiatorAddress;
  spindump_network responderAddress;
  spindump_connections_getnetworks(connection,&initiatorAddress,&responderAddress);
  spindump_event_initialize(eventType,
			    connection->type,
			    &initiatorAddress,
			    &responderAddress,
			    session,
			    timestamplonglong,
			    &eventobj);


  switch (event) {

  case spindump_analyze_event_newconnection:
    break;

  case spindump_analyze_event_connectiondelete:
    break;

  case spindump_analyze_event_newleftrttmeasurement:
    eventobj.u.newRttMeasurement.measurement = spindump_measurement_type_bidirectional;
    eventobj.u.newRttMeasurement.direction = spindump_direction_fromresponder;
    eventobj.u.newRttMeasurement.rtt = connection->leftRTT.lastRTT;
    break;
    
  case spindump_analyze_event_newrightrttmeasurement:
    eventobj.u.newRttMeasurement.measurement = spindump_measurement_type_bidirectional;
    eventobj.u.newRttMeasurement.direction = spindump_direction_frominitiator;
    eventobj.u.newRttMeasurement.rtt = connection->rightRTT.lastRTT;
    break;
    
  case spindump_analyze_event_newinitrespfullrttmeasurement:
    eventobj.u.newRttMeasurement.measurement = spindump_measurement_type_unidirectional;
    eventobj.u.newRttMeasurement.direction = spindump_direction_frominitiator;
    eventobj.u.newRttMeasurement.rtt = connection->initToRespFullRTT.lastRTT;
    break;

  case spindump_analyze_event_newrespinitfullrttmeasurement:
    eventobj.u.newRttMeasurement.measurement = spindump_measurement_type_unidirectional;
    eventobj.u.newRttMeasurement.direction = spindump_direction_fromresponder;
    eventobj.u.newRttMeasurement.rtt = connection->respToInitFullRTT.lastRTT;
    break;

  case spindump_analyze_event_initiatorspinflip:
    spindump_assert(connection->type == spindump_connection_transport_quic);
    eventobj.u.spinFlip.direction = spindump_direction_frominitiator;
    eventobj.u.spinFlip.spin0to1 = connection->u.quic.spinFromPeer1to2.lastSpin;
    break;

  case spindump_analyze_event_responderspinflip:
    spindump_assert(connection->type == spindump_connection_transport_quic);
    eventobj.u.spinFlip.direction = spindump_direction_fromresponder;
    eventobj.u.spinFlip.spin0to1 = connection->u.quic.spinFromPeer2to1.lastSpin;
    break;
    
  case spindump_analyze_event_initiatorspinvalue:
    spindump_assert(connection->type == spindump_connection_transport_quic);
    eventobj.u.spinValue.direction = spindump_direction_frominitiator;
    eventobj.u.spinValue.value = (uint8_t)connection->u.quic.spinFromPeer1to2.lastSpin;
    break;

  case spindump_analyze_event_responderspinvalue:
    spindump_assert(connection->type == spindump_connection_transport_quic);
    eventobj.u.spinValue.direction = spindump_direction_fromresponder;
    eventobj.u.spinValue.value = (uint8_t)connection->u.quic.spinFromPeer2to1.lastSpin;
    break;

  case spindump_analyze_event_initiatorecnce:
    eventobj.u.ecnCongestionEvent.direction = spindump_direction_frominitiator;
    break;

  case spindump_analyze_event_responderecnce:
    eventobj.u.ecnCongestionEvent.direction = spindump_direction_fromresponder;
    break;

  default:
    return;

  }

  //
  // Based on the format type, provide different kinds of output
  //
  
  switch (formatter->format) {
  case spindump_eventformatter_outputformat_text:
    spindump_eventformatter_measurement_one_text(formatter,event,&eventobj,connection);
    break;
  case spindump_eventformatter_outputformat_json:
    spindump_eventformatter_measurement_one_json(formatter,event,&eventobj,connection);
    break;
  default:
    spindump_errorf("invalid output format in internal variable");
    exit(1);
  }
}

//
// Determine Internet media type based on the format
//

static const char*
spindump_eventformatter_mediatype(enum spindump_eventformatter_outputformat format) {
  switch (format) {
  case spindump_eventformatter_outputformat_text:
    return("application/text");
  case spindump_eventformatter_outputformat_json:
    return("application/json");
  default:
    spindump_errorf("invalid format");
    return("application/text");
  }
}

//
// Internal function that is called by the different format
// formatters, to deliver a bunch of bytes (e.g., a JSON string)
// towards the output. Depending on where the output needs to go, it
// could either be printed or queued up for storage to be later
// delivered via HTTP to a collector point.
//

void
spindump_eventformatter_deliverdata(struct spindump_eventformatter* formatter,
				    unsigned long length,
				    const uint8_t* data) {
  if (formatter->file != 0) {

    //
    // We're just outputting data to stdout; print it out
    //
    
    fwrite(data,length,1,formatter->file);
    
  } else if (formatter->nRemotes > 0) {

    //
    // We need to send data to remote collector point(s). If blockSize
    // is zero, then we simply send right away.
    //

    if (formatter->blockSize == 0) {
      spindump_eventformatter_deliverdata_remoteblock(formatter,
						      length,
						      data);
    } else {
      
      //
      // Otherwise, keep pooling data in a buffer until block size is filled
      //
      
      if (formatter->bytesInBlock + length + spindump_eventformatter_maxpostamble < formatter->blockSize) {
	
	//
	// All fits in and still some space
	//
	
	memcpy(formatter->block + formatter->bytesInBlock,data,length);
	formatter->bytesInBlock += length;
	
      } else if (formatter->bytesInBlock + length + spindump_eventformatter_maxpostamble == formatter->blockSize) {

	//
	// All fits in but exactly
	//
	
	memcpy(formatter->block + formatter->bytesInBlock,data,length);
	formatter->bytesInBlock += length;
	unsigned long postambleLength;
	const uint8_t* postamble = spindump_eventformatter_measurement_endaux(formatter,&postambleLength);
	memcpy(formatter->block + formatter->bytesInBlock,postamble,postambleLength);
	formatter->bytesInBlock += postambleLength;
	spindump_eventformatter_deliverdata_remoteblock(formatter,
							formatter->bytesInBlock,
							formatter->block);
	formatter->bytesInBlock = 0;
	spindump_eventformatter_measurement_begin(formatter);
	
      } else {

	//
	// Latest entry does not fit in, send the current block and
	// then put this entry to the buffer
	//
	
	unsigned long postambleLength;
	const uint8_t* postamble = spindump_eventformatter_measurement_endaux(formatter,&postambleLength);
	memcpy(formatter->block + formatter->bytesInBlock,postamble,postambleLength);
	formatter->bytesInBlock += postambleLength;
	spindump_eventformatter_deliverdata_remoteblock(formatter,
							formatter->bytesInBlock,
							formatter->block);
	formatter->bytesInBlock = 0;
	spindump_eventformatter_measurement_begin(formatter);
	memcpy(formatter->block,data,length);
	formatter->bytesInBlock = length;
	
      }
    }
    
  } else {
    
    spindump_errorf("no event destination specified");
    
  }
}

//
// Deliver one block of data to the remote collector point(s)
//

static void
spindump_eventformatter_deliverdata_remoteblock(struct spindump_eventformatter* formatter,
						unsigned long length,
						const uint8_t* data) {
  for (unsigned int i = 0; i < formatter->nRemotes; i++) {
    struct spindump_remote_client* client = formatter->remotes[i];
    spindump_assert(client != 0);
    const char* mediaType = spindump_eventformatter_mediatype(formatter->format);
    spindump_remote_client_update_event(client,mediaType,length,data);
  }
}
