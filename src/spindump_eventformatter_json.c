
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
#include <stdlib.h>
#include "spindump_util.h"
#include "spindump_eventformatter.h"
#include "spindump_eventformatter_json.h"
#include "spindump_event.h"
#include "spindump_event_parser_json.h"

//
// Actual code --------------------------------------------------------------------------------
//

//
// Return the length of the preamble
//

unsigned long
spindump_eventformatter_measurement_beginlength_json(struct spindump_eventformatter* formatter) {
  return(2);
}

//
// Print what is needed as a preface to the actual records
//

const uint8_t*
spindump_eventformatter_measurement_begin_json(struct spindump_eventformatter* formatter) {
  return((uint8_t*)"[\n");
}

//
// Return the length of the postamble
//

unsigned long
spindump_eventformatter_measurement_endlength_json(struct spindump_eventformatter* formatter) {
  return(2);
}

//
// Print what is needed as an end after the actual records
//

const uint8_t*
spindump_eventformatter_measurement_end_json(struct spindump_eventformatter* formatter) {
  return((uint8_t*)"]\n");
}

//
// Print out one --textual measurement event, when the format is set
// to --format json
//

void
spindump_eventformatter_measurement_one_json(struct spindump_eventformatter* formatter,
					     spindump_analyze_event event,
					     const struct spindump_event* eventobj,
					     struct spindump_connection* connection) {
  
  char buf[250];
  size_t consumed;
  spindump_event_parser_json_print(eventobj,buf,sizeof(buf)-1,&consumed);
  spindump_assert(consumed < sizeof(buf));
  buf[consumed] = 0;
    
  //
  // Print the buffer out
  //
  
  spindump_eventformatter_deliverdata(formatter,strlen(buf),(uint8_t*)buf);
  
}

