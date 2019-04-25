
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

#ifndef SPINDUMP_CONNECTIONS_SET_H
#define SPINDUMP_CONNECTIONS_SET_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/in.h>
#include "spindump_util.h"
#include "spindump_rtt.h"
#include "spindump_seq.h"
#include "spindump_stats.h"
#include "spindump_connections_structs.h"
#include "spindump_table_structs.h"

//
// External API interface to this module ------------------------------------------------------
//

void
spindump_connections_set_initialize(struct spindump_connection_set* set);
void
spindump_connections_set_uninitialize(struct spindump_connection_set* set,
                                      struct spindump_connection* owner);
int
spindump_connections_set_inset(struct spindump_connection_set* set,
                               struct spindump_connection* connection);
void
spindump_connections_set_add(struct spindump_connection_set* set,
                             struct spindump_connection* connection);
void
spindump_connections_set_remove(struct spindump_connection_set* set,
                                struct spindump_connection* connection);
const char*
spindump_connections_set_listids(struct spindump_connection_set* set);

#endif // SPINDUMP_CONNECTIONS_SET_H
