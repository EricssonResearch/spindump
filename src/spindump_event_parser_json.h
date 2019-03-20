
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

#ifndef SPINDUMP_EVENT_PARSER_JSON_H
#define SPINDUMP_EVENT_PARSER_JSON_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <stdio.h>
#include "spindump_event.h"

//
// Data types ---------------------------------------------------------------------------------
//

//
// Parameters ---------------------------------------------------------------------------------
//

//
// Data structures ----------------------------------------------------------------------------
//

//
// External API interface to this module ------------------------------------------------------
//

int
spindump_event_parser_json_parse(const char* buffer,
				 const struct spindump_event* event);
int
spindump_event_parser_json_print(const struct spindump_event* event,
				 char* buffer,
				 size_t length);

#endif // SPINDUMP_EVENT_PARSER_JSON_H
