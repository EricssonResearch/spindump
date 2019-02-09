
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

#ifndef SPINDUMP_TABLE_H
#define SPINDUMP_TABLE_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include "spindump_table_structs.h"
#include "spindump_connections_structs.h"
#include "spindump_stats.h"
#include "spindump_reversedns.h"

//
// Forward declaration of structures ----------------------------------------------------------
//

struct spindump_analyze;

//
// External API interface to this module ------------------------------------------------------
//

struct spindump_connectionstable*
spindump_connectionstable_initialize(void);
void
spindump_connectionstable_uninitialize(struct spindump_connectionstable* table);
int
spindump_connectionstable_periodiccheck(struct spindump_connectionstable* table,
					const struct timeval* now,
					struct spindump_analyze* analyzer);
void
spindump_connectionstable_deleteconnection(struct spindump_connection* connection,
					   struct spindump_connectionstable* table,
					   struct spindump_analyze* analyzer,
					   const char* reason);
void
spindump_connectionstable_report(struct spindump_connectionstable* table,
				 FILE* file,
				 struct spindump_reverse_dns* querier);

#endif // SPINDUMP_TABLE_H
