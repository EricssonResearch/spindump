
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

#ifndef SPINDUMP_ANALYZE_H
#define SPINDUMP_ANALYZE_H

//
// Includes -----------------------------------------------------------------------------------
//

#include "spindump_capture.h"
#include "spindump_connections_structs.h"
#include "spindump_table.h"

//
// Parameters ---------------------------------------------------------------------------------
//

#define spindump_analyze_max_handlers 10

//
// Data types ---------------------------------------------------------------------------------
//

typedef uint16_t spindump_analyze_event;
#define spindump_analyze_event_newconnection		             1
#define spindump_analyze_event_connectiondelete		             2
#define spindump_analyze_event_newleftrttmeasurement	             4
#define spindump_analyze_event_newrightrttmeasurement	             8
#define spindump_analyze_event_newinitrespfullrttmeasurement        16
#define spindump_analyze_event_newrespinitfullrttmeasurement        32
#define spindump_analyze_event_initiatorspinflip	            64
#define spindump_analyze_event_responderspinflip	           128
#define spindump_analyze_event_initiatorspinvalue	           256
#define spindump_analyze_event_responderspinvalue                  512
#define spindump_analyze_event_newpacket                          1024
#define spindump_analyze_event_firstresponsepacket                2048
#define spindump_analyze_event_statechange                        4096

#define spindump_analyze_event_alllegal                           8191

struct spindump_analyze;

typedef void (*spindump_analyze_handler)(struct spindump_analyze* state,
					 void* handlerData,
					 void** handlerConnectionData,
					 spindump_analyze_event event,
					 struct spindump_packet* packet,
					 struct spindump_connection* connection);

struct spindump_analyze_handler {
  spindump_analyze_event eventmask;
  spindump_analyze_handler function;
  void* handlerData;
};

struct spindump_analyze {
  struct spindump_connectionstable* table;
  struct spindump_stats* stats;
  unsigned int nHandlers;
  struct spindump_analyze_handler handlers[spindump_analyze_max_handlers];
};

//
// The public analyzer API, the external function prototypes ----------------------------------
//

struct spindump_analyze*
spindump_analyze_initialize();
void
spindump_analyze_uninitialize(struct spindump_analyze* state);
void
spindump_analyze_registerhandler(struct spindump_analyze* state,
				 spindump_analyze_event eventmask,
				 spindump_analyze_handler handler,
				 void* handlerData);
struct spindump_stats*
spindump_analyze_getstats(struct spindump_analyze* state);
void
spindump_analyze_process(struct spindump_analyze* state,
			 enum spindump_capture_linktype linktype,
			 struct spindump_packet* packet,
			 struct spindump_connection** p_connection);
void
spindump_analyze_getsource(struct spindump_packet* packet,
			   uint8_t ipVersion,
			   unsigned int ipHeaderPosition,
			   spindump_address *address);
void
spindump_analyze_getdestination(struct spindump_packet* packet,
				uint8_t ipVersion,
				unsigned int ipHeaderPosition,
				spindump_address *address);
const char*
spindump_analyze_eventtostring(spindump_analyze_event event);

//
// The private, internal function prototypes --------------------------------------------------
//

void
spindump_analyze_process_pakstats(struct spindump_analyze* state,
				  struct spindump_connection* connection,
				  int fromResponder,
				  struct spindump_packet* packet,
				  unsigned int ipPacketLength);
void
spindump_analyze_process_handlers(struct spindump_analyze* state,
				  spindump_analyze_event event,
				  struct spindump_packet* packet,
				  struct spindump_connection* connection);

#endif // SPINDUMP_ANALYZE_H
