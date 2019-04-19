
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

#include <time.h>
#include <ctype.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include "spindump_util.h"

//
// Variables ----------------------------------------------------------------------------------
//

int spindump_debug = 0;
int spindump_deepdebug = 0;
int spindump_deepdeepdebug = 0;
static FILE* debugdestination = 0;

//
// Actual code --------------------------------------------------------------------------------
//

//
// Debug helper function
//

void
spindump_setdebugdestination(FILE* file) {
  debugdestination = file;
}

#ifdef SPINDUMP_DEBUG

//
// Print out debug in a manner similar to printf. This function will
// only have an effect if the variable debug is 1.
//

__attribute__((__format__ (__printf__, 1, 0)))
void
spindump_debugf(const char* format, ...) {

  spindump_assert(format != 0);

  if (spindump_debug) {

    va_list args;

    if (debugdestination == 0) debugdestination = stderr;
  
    fprintf(debugdestination, "spindump: debug: ");
    va_start (args, format);
    vfprintf(debugdestination, format, args);
    va_end (args);
    fprintf(debugdestination, "\n");
    fflush(debugdestination);
    
  }
  
}

//
// Debug helper function, for more extensive debugging
//

__attribute__((__format__ (__printf__, 1, 0)))
void
spindump_deepdebugf(const char* format, ...) {

  spindump_assert(format != 0);
  
  if (spindump_debug && spindump_deepdebug) {

    va_list args;

    if (debugdestination == 0) debugdestination = stderr;
    
    fprintf(debugdestination, "spindump: debug:   ");
    va_start (args, format);
    vfprintf(debugdestination,format, args);
    va_end (args);
    fprintf(debugdestination, "\n");
    fflush(debugdestination);
    
  }
  
}

//
// Debug helper function, for very extensive debugging
//

__attribute__((__format__ (__printf__, 1, 0)))
void
spindump_deepdeepdebugf(const char* format, ...) {

  spindump_assert(format != 0);
  
  if (spindump_debug && spindump_deepdebug && spindump_deepdeepdebug) {

    va_list args;

    if (debugdestination == 0) debugdestination = stderr;
    
    fprintf(debugdestination, "spindump: debug:     ");
    va_start (args, format);
    vfprintf(debugdestination,format, args);
    va_end (args);
    fprintf(debugdestination, "\n");
    fflush(debugdestination);
    
  }
  
}

#endif // SPINDUMP_DEBUG
