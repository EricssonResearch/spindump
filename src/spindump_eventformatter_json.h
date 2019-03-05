
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

#ifndef SPINDUMP_EVENTFORMATTER_JSON_H
#define SPINDUMP_EVENTFORMATTER_JSON_H

//
// Includes -----------------------------------------------------------------------------------
//

#include "spindump_util.h"
#include "spindump_analyze.h"
#include "spindump_connections.h"
#include "spindump_eventformatter.h"

//
// Parameters ---------------------------------------------------------------------------------
//

//
// External API interface to this module ------------------------------------------------------
//

unsigned long
spindump_eventformatter_measurement_beginlength_json(struct spindump_eventformatter* formatter);
const uint8_t*
spindump_eventformatter_measurement_begin_json(struct spindump_eventformatter* formatter);
void
spindump_eventformatter_measurement_one_json(struct spindump_eventformatter* formatter,
					     spindump_analyze_event event,
					     struct spindump_connection* connection,
					     const char* type,
					     const char* addrs,
					     const char* session,
					     const struct timeval* timestamp);
const uint8_t*
spindump_eventformatter_measurement_end_json(struct spindump_eventformatter* formatter);
unsigned long
spindump_eventformatter_measurement_endlength_json(struct spindump_eventformatter* formatter);

#endif // SPINDUMP_EVENTFORMATTER_JSON_H
