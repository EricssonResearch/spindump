
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

#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <unistd.h>
#include "spindump_util.h"
#include "spindump_capture.h"
#include "spindump_analyze.h"
#include "spindump_report.h"
#include "spindump_remote_client.h"
#include "spindump_remote_server.h"
#include "spindump_eventformatter.h"
#include "spindump_main.h"
#include "spindump_main_lib.h"
#include "spindump_main_loop.h"

//
// Other Variables ----------------------------------------------------------------------------
//

static int* interruptFlagLocation = 0;

//
// Function prototypes ------------------------------------------------------------------------
//

static void
spindump_main_interrupt(int dummy);

//
// Actual code --------------------------------------------------------------------------------
//

//
// Interrupts (Ctrl-C) during program execution
// should cause the current probing process to end
// and results printed out.
//

static void
spindump_main_interrupt(int dummy) {
  if (interruptFlagLocation != 0) {
    *interruptFlagLocation = 1;
  }
}

//
// The main program
//

int main(int argc,char** argv) {

  //
  // Initialize
  //

  signal(SIGINT, spindump_main_interrupt);
  srand((unsigned int)time(0));
  FILE* debugfile = stderr;
  struct spindump_main_state* state = spindump_main_initialize();
  interruptFlagLocation = &state->interrupt;
  
  if (state == 0) exit(1);
  
  //
  // Process arguments
  //
  
  spindump_main_processargs(argc, argv, &state->config);
  
  //
  // Check where error and debug printouts should go
  //

  if (state->config.toolmode != spindump_toolmode_silent && spindump_debug) {
    debugfile = fopen("spindump.debug","w");
    if (debugfile == 0) {
      spindump_errorf("cannot open debug file");
      exit(1);
    }
    spindump_setdebugdestination(debugfile);
  }
  spindump_seterrordestination(debugfile);
  
  //
  // Main operation
  //
  
  spindump_main_loop_operation(state);
  
  //
  // Done successfully, exit
  //
  
  interruptFlagLocation = 0;
  spindump_main_uninitialize(state);
  exit(0);
}
