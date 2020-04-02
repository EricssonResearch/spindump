
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
//  AUTHOR: JARI ARKKO AND MARCUS IHLAR
//
//

#ifndef SPINDUMP_ANALYZE_H
#define SPINDUMP_ANALYZE_H

//
// Includes -----------------------------------------------------------------------------------
//

#include "spindump_tags.h"
#include "spindump_capture.h"
#include "spindump_connections_structs.h"
#include "spindump_table.h"

//
// Parameters ---------------------------------------------------------------------------------
//

#define spindump_analyze_max_handlers 32

//
// Data types ---------------------------------------------------------------------------------
//

typedef uint32_t spindump_analyze_event;
#define spindump_analyze_event_newconnection                         1
#define spindump_analyze_event_changeconnection                      2
#define spindump_analyze_event_connectiondelete                      4
#define spindump_analyze_event_newleftrttmeasurement                 8
#define spindump_analyze_event_newrightrttmeasurement               16
#define spindump_analyze_event_newinitrespfullrttmeasurement        32
#define spindump_analyze_event_newrespinitfullrttmeasurement        64
#define spindump_analyze_event_initiatorspinflip                   128
#define spindump_analyze_event_responderspinflip                   256
#define spindump_analyze_event_initiatorspinvalue                  512
#define spindump_analyze_event_responderspinvalue                 1024
#define spindump_analyze_event_newpacket                          2048
#define spindump_analyze_event_firstresponsepacket                4096
#define spindump_analyze_event_statechange                        8192
#define spindump_analyze_event_initiatorecnce                    16384
#define spindump_analyze_event_responderecnce                    32768
#define spindump_analyze_event_initiatorrtlossmeasurement        65536
#define spindump_analyze_event_responderrtlossmeasurement       131072
#define spindump_analyze_event_initiatorqrlossmeasurement       262144
#define spindump_analyze_event_responderqrlossmeasurement       524288
#define spindump_analyze_event_initiatorqllossmeasurement      1048576
#define spindump_analyze_event_responderqllossmeasurement      2097152
#define spindump_analyze_event_periodic                        4194304

#define spindump_analyze_event_alllegal                        8388607

struct spindump_analyze;
struct spindump_event;

typedef void (*spindump_analyze_handler)(struct spindump_analyze* state,
                                         void* handlerData,
                                         void** handlerConnectionData,
                                         spindump_analyze_event event,
                                         const struct timeval* timestamp,
                                         const int fromResponder,
                                         const unsigned int ipPacketLength,
                                         struct spindump_packet* packet,
                                         struct spindump_connection* connection);

struct spindump_analyze_handler {
  spindump_analyze_handler function;               // function to call when the handler matches
  void* handlerData;                               // data to pass to the function
  spindump_analyze_event eventmask;                // what events does the handler match on?
  int connectionSpecific;                          // does the handler match for all connections or only some?
                                                   // (for connection-specific handlers, there's a bit mask in
                                                   // each connection object that shows which handlers should be run,
                                                   // where the bit mask is the index in the analyzer's table of handlers)
  char padding[2];                                 // unused
};

struct spindump_analyze {
  struct spindump_connectionstable* table;         // a table of all current connections 
  struct spindump_stats* stats;                    // pointer to statistics object
  unsigned int nHandlers;                          // the number of slots used in the handler table
  unsigned int padding;                            // unused
  struct spindump_analyze_handler
    handlers[spindump_analyze_max_handlers];       // the registered handlers
};

//
// The public analyzer API, the external function prototypes ----------------------------------
//

struct spindump_analyze*
spindump_analyze_initialize(unsigned int filterExceptionalValuePercentage,
                            unsigned long long bandwidthMeasurementPeriod,
                            unsigned int periodicReportPeriod,
                            const spindump_tags* defaultTags);
void

spindump_analyze_uninitialize(struct spindump_analyze* state);
void
spindump_analyze_registerhandler(struct spindump_analyze* state,
                                 spindump_analyze_event eventmask,
                                 struct spindump_connection* connection,
                                 spindump_analyze_handler handler,
                                 void* handlerData);
void
spindump_analyze_unregisterhandler(struct spindump_analyze* state,
                                   spindump_analyze_event eventmask,
                                   struct spindump_connection* connection,
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
spindump_analyze_processevent(struct spindump_analyze* state,
                              const struct spindump_event* event,
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
                                  const struct timeval* timestamp,
                                  const int fromResponder,
                                  struct spindump_packet* packet,
                                  unsigned int ipPacketLength,
                                  uint8_t ecnFlags);
void
spindump_analyze_process_handlers(struct spindump_analyze* state,
                                  spindump_analyze_event event,
                                  const struct timeval* timestamp,
                                  const int fromResponder,
                                  const unsigned int ipPacketLength,
                                  struct spindump_packet* packet,
                                  struct spindump_connection* connection);

#endif // SPINDUMP_ANALYZE_H
