
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
#include "spindump_eventformatter_qlog.h"
#include "spindump_event.h"
#include "spindump_event_parser_qlog.h"
#include "spindump_event_printer_qlog.h"

//
// Qlog strings -------------------------------------------------------------------------------
//

static const char* qlog_begin =
  "{\"qlog_version\": \"draft-02\", \"qlog_format\": \"JSON\", \"description\": \"Spindump measurements\", \"traces\": [\n"
  " { \"vantage_point\": { \"type\": \"network\" }, \"events\": [\n";
static const char* qlog_mid =
  ",\n";
static const char* qlog_end =
  "  \n ]}]}\n";

//
// Actual code --------------------------------------------------------------------------------
//

//
// Return the length of the preamble
//

unsigned long
spindump_eventformatter_measurement_beginlength_qlog(struct spindump_eventformatter* formatter) {
  return(strlen(qlog_begin));
}

//
// Print what is needed as a preface to the actual records
//

const uint8_t*
spindump_eventformatter_measurement_begin_qlog(struct spindump_eventformatter* formatter) {
  spindump_deepdeepdebugf("eventformatter_qlog beg");
  return((const uint8_t*)qlog_begin);
}

//
// Return the length of the postamble
//

unsigned long
spindump_eventformatter_measurement_midlength_qlog(struct spindump_eventformatter* formatter) {
  return(strlen(qlog_mid));
}

//
// Print what is needed as an end after the actual records
//

const uint8_t*
spindump_eventformatter_measurement_mid_qlog(struct spindump_eventformatter* formatter) {
  spindump_deepdeepdebugf("eventformatter_qlog mid");
  return((const uint8_t*)qlog_mid);
}

//
// Return the length of the postamble
//

unsigned long
spindump_eventformatter_measurement_endlength_qlog(struct spindump_eventformatter* formatter) {
  return(strlen(qlog_end));
}

//
// Print what is needed as an end after the actual records
//

const uint8_t*
spindump_eventformatter_measurement_end_qlog(struct spindump_eventformatter* formatter) {
  spindump_deepdeepdebugf("eventformatter_qlog end");
  return((const uint8_t*)qlog_end);
}

//
// Print out one --textual measurement event, when the format is set
// to --format qlog
//

void
spindump_eventformatter_measurement_one_qlog(struct spindump_eventformatter* formatter,
                                             spindump_analyze_event event,
                                             const struct spindump_event* eventobj,
                                             struct spindump_connection* connection) {
  
  char buf[400];
  size_t consumed;
  spindump_event_printer_qlog_print(eventobj,buf,sizeof(buf)-1,&consumed);
  spindump_assert(consumed < sizeof(buf));
  buf[consumed] = 0;
  
  //
  // Print the buffer out
  //
  
  spindump_eventformatter_deliverdata(formatter,0,strlen(buf),(uint8_t*)buf);
  
}
