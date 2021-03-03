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
//  SPINDUMP (C) 2018-2020 BY ERICSSON RESEARCH
//  AUTHOR: JARI ARKKO
//
// 

#ifndef SPINDUMP_EVENT_PRINTER_JSON_H
#define SPINDUMP_EVENT_PRINTER_JSON_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <stdio.h>
#include "spindump_event.h"
#include "spindump_json_value.h"

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
spindump_event_printer_json_print(const struct spindump_event* event,
                                  char* buffer,
                                  size_t length,
                                  size_t* consumed);

#endif // SPINDUMP_EVENT_PRINTER_JSON_H
