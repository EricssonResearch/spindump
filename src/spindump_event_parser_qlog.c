
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
//  SPINDUMP (C) 2018-2021 BY ERICSSON RESEARCH
//  AUTHOR: JARI ARKKO
//
// 

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "spindump_util.h"
#include "spindump_event.h"
#include "spindump_event_parser_qlog.h"
#include "spindump_connections.h"
#include "spindump_json.h"
#include "spindump_json_value.h"

//
// Function prototypes ------------------------------------------------------------------------
//


//
// Data types ---------------------------------------------------------------------------------
//

struct spindump_event_parser_qlog_parsingcontext {
  spindump_event_parser_qlog_callback callback;
  void* data;
  int success;
};

//
// Variables and constants --------------------------------------------------------------------
//


//
// Actual code --------------------------------------------------------------------------------
//

//
// Return the schema for the JSON that we should be using for Spindump logs.
//

const struct spindump_json_schema*
spindump_event_parser_qlog_getschema() {
  return(0); // ... TODO ...
}

//
// Parse text as Qlog JSON and call a callback for every Qlog event
// found from it.
//
// The input text point moves further as the input is read. Only a
// single JSON object is read at one time. That object may of course
// be a composite object, such as an array.
//
// If successful, return 1, otherwise 0.
//

int
spindump_event_parser_qlog_textparse(const char** jsonText,
                                     spindump_event_parser_qlog_callback callback,
                                     void* data) {
  return(0); // ...
}

//
// Take a Qlog JSON object and parse it as a JSON-formatted event
// description in Qlog format, placing the result in the output
// parameter "event".
//
// If successful, return 1, otherwise 0.
//

int
spindump_event_parser_qlog_parse(const struct spindump_json_value* json,
                                 struct spindump_event* event) {

  //
  // Sanity checks
  //

  spindump_assert(json != 0);
  spindump_assert(json->type == spindump_json_value_type_record);
  spindump_assert(event != 0);

  return(0); // ...
}
