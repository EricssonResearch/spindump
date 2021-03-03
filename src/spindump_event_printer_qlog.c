
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
#include "spindump_event_printer_qlog.h"
#include "spindump_connections.h"
#include "spindump_json.h"
#include "spindump_json_value.h"

//
// Take an event description in the input parameter "event", and print
// it out as a JSON-formatted Qlog event. The printed version will
// be placed in the buffer "buffer" whose length is at most "length".
//
// If successful, in other words, if there was enough space in the
// buffer, return 1, otherwise 0. Set the output parameter "consumed" to
// the number of consumed bytes.
//

int
spindump_event_printer_qlog_print(const struct spindump_event* event,
                                  char* buffer,
                                  size_t length,
                                  size_t* consumed) {

  //
  // Check length
  //
  
  if (length < 2) return(0);
  memset(buffer,0,length);

  //
  // Some utilities to put strings onto the buffer
  //
  
#define addtobuffer1(x)     snprintf(buffer + strlen(buffer),length - 1 - strlen(buffer),x)
#define addtobuffer2(x,y)   snprintf(buffer + strlen(buffer),length - 1 - strlen(buffer),x,y)
#define addtobuffer3(x,y,z) snprintf(buffer + strlen(buffer),length - 1 - strlen(buffer),x,y,z)

  addtobuffer1("x");
  addtobuffer2("y%u",0);
  addtobuffer3("z%u%u",1,2);
  
  //
  // Done.
  //
  
  *consumed = strlen(buffer);
  return(strlen(buffer) < length - 1);
}
