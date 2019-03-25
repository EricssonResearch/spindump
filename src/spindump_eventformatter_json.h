
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
#include "spindump_event.h"

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
					     const struct spindump_event* eventobj,
					     struct spindump_connection* connection);
const uint8_t*
spindump_eventformatter_measurement_mid_json(struct spindump_eventformatter* formatter);
unsigned long
spindump_eventformatter_measurement_midlength_json(struct spindump_eventformatter* formatter);
const uint8_t*
spindump_eventformatter_measurement_end_json(struct spindump_eventformatter* formatter);
unsigned long
spindump_eventformatter_measurement_endlength_json(struct spindump_eventformatter* formatter);

#endif // SPINDUMP_EVENTFORMATTER_JSON_H
