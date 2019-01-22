
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

#ifndef SPINDUMP_REPORT_H
#define SPINDUMP_REPORT_H

//
// Includes -----------------------------------------------------------------------------------
//

#include "spindump_connections.h"
#include "spindump_table.h"
#include "spindump_stats.h"

//
// Data structures ----------------------------------------------------------------------------
//

enum spindump_report_command {
  spindump_report_command_none,
  spindump_report_command_help,
  spindump_report_command_toggle_average,
  spindump_report_command_toggle_aggregate,
  spindump_report_command_toggle_closed,
  spindump_report_command_toggle_udp,
  spindump_report_command_update_interval,
  spindump_report_command_quit
};

enum spindump_report_destination {
  spindump_report_destination_quiet,
  spindump_report_destination_terminal
};

struct spindump_report_state {
  enum spindump_report_destination destination;
  unsigned int inputlineposition;
  struct spindump_reverse_dns* querier;
};

//
// External API interface to this module ------------------------------------------------------
//

struct spindump_report_state*
spindump_report_initialize_quiet();
struct spindump_report_state*
spindump_report_initialize_terminal(struct spindump_reverse_dns* querier);
void
spindump_report_update(struct spindump_report_state* reporter,
		       int average,
		       int aggregate,
		       int closed,
		       int udp,
		       struct spindump_connectionstable* table,
		       struct spindump_stats* stats);
enum spindump_report_command
spindump_report_checkinput(struct spindump_report_state* reporter,
			   double* p_argument);
void
spindump_report_showhelp(struct spindump_report_state* reporter);
void
spindump_report_uninitialize(struct spindump_report_state* reporter);

#endif // SPINDUMP_REPORT_H
