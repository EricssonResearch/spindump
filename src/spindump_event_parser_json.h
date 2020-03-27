
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
#include "spindump_json_value.h"

//
// Data types ---------------------------------------------------------------------------------
//

typedef void (*spindump_event_parser_json_callback)(const struct spindump_event* event,
                                                    void* data);

//
// Parameters ---------------------------------------------------------------------------------
//

//
// Data structures ----------------------------------------------------------------------------
//

//
// External API interface to this module ------------------------------------------------------
//

const struct spindump_json_schema*
spindump_event_parser_json_getschema(void);
int
spindump_event_parser_json_textparse(const char** jsonText,
                                     spindump_event_parser_json_callback callback,
                                     void* data);
int
spindump_event_parser_json_parse(const struct spindump_json_value* json,
                                 struct spindump_event* event);
int
spindump_event_parser_json_print(const struct spindump_event* event,
                                 char* buffer,
                                 size_t length,
                                 size_t* consumed);

#endif // SPINDUMP_EVENT_PARSER_JSON_H
