
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

static FILE* errordestination = 0;

//
// Actual code --------------------------------------------------------------------------------
//

//
// Set the destination stream for all error messages (fatal, error,
// warn)
//

void
spindump_seterrordestination(FILE* file) {
  errordestination = file;
}

//
// Display a fatal error
//

__attribute__((__format__ (__printf__, 1, 0)))
noreturn void
spindump_fatalf(const char* format, ...) {
  
  va_list args;
  
  spindump_assert(format != 0);

  if (errordestination == 0) errordestination = stderr;
  
  spindump_debugf("spindump: fatal error: %s", format);
  fprintf(errordestination,"spindump: fatal error: ");
  va_start (args, format);
  vfprintf(errordestination, format, args);
  va_end (args);
  fprintf(errordestination," -- exit\n");
  
  exit(1);
}

//
// Display a fatal error a la perror
//

noreturn void
spindump_fatalp(const char* message) {
  
  const char* string = strerror(errno);
  spindump_assert(message != 0);
  spindump_fatalf("system: %s - %s", message, string);
  
}

//
// Display an error
//

__attribute__((__format__ (__printf__, 1, 0)))
void
spindump_errorf(const char* format, ...) {
  
  va_list args;
  
  spindump_assert(format != 0);
  
  if (errordestination == 0) errordestination = stderr;
  
  spindump_debugf("spindump: error: %s", format);
  fprintf(errordestination,"spindump: error: ");
  va_start (args, format);
  vfprintf(errordestination, format, args);
  fprintf(errordestination,"\n");
  va_end (args);
  
}

//
// Display an error a la perror
//

void
spindump_errorp(const char* message) {
  
  const char* string = strerror(errno);
  spindump_assert(message != 0);
  spindump_errorf("system: %s - %s", message, string);
  
}

//
// Display a warning
//

__attribute__((__format__ (__printf__, 1, 0)))
void
spindump_warnf(const char* format, ...) {
  
  va_list args;
  
  spindump_assert(format != 0);

  if (errordestination == 0) errordestination = stderr;
  
  spindump_debugf("spindump: warning %s", format);
  fprintf(errordestination,"spindump: warning: ");
  va_start (args, format);
  vfprintf(errordestination, format, args);
  va_end (args);
  fprintf(errordestination,"\n");
}

