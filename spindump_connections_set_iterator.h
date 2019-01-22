
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

#ifndef SPINDUMP_CONNECTIONS_SET_ITERATOR_H
#define SPINDUMP_CONNECTIONS_SET_ITERATOR_H

//
// Includes -----------------------------------------------------------------------------------
//

#include "spindump_connections_structs.h"

//
// Data structures ----------------------------------------------------------------------------
//

struct spindump_connection_set_iterator {
  struct spindump_connection_set* set;
  unsigned int iteration;
};

//
// External API interface to this module ------------------------------------------------------
//

void
spindump_connection_set_iterator_initialize(struct spindump_connection_set* set,
					    struct spindump_connection_set_iterator* iter);
int
spindump_connection_set_iterator_end(struct spindump_connection_set_iterator* iter);
struct spindump_connection*
spindump_connection_set_iterator_next(struct spindump_connection_set_iterator* iter);
void
spindump_connection_set_iterator_uninitialize(struct spindump_connection_set_iterator* set);

#endif // SPINDUMP_CONNECTIONS_SET_ITERATOR_H
