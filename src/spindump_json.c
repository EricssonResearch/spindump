
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

#include <string.h>
#include <ctype.h>
#include "spindump_util.h"
#include "spindump_json.h"

//
// Function prototypes ------------------------------------------------------------------------
//

//
// Actual code --------------------------------------------------------------------------------
//

//
// Parse a given input as JSON of a given type. Callbacks in the type
// definition will be called when the input is read correctly, and the
// "data" parqmeter is one of the parameters passed to the callbacks.
//
// This function returns 1 upon successful parsing, and 0 upon
// failure.
//

int
spindump_json_parse(struct spindump_json_typedef* type,
                    const char* input,
                    void* data) {
  return(0);
}
