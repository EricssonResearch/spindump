
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

#include "spindump_util.h"
#include "spindump_connections_structs.h"
#include "spindump_connections_set_iterator.h"

//
// Actual code --------------------------------------------------------------------------------
//

void
spindump_connection_set_iterator_initialize(struct spindump_connection_set* set,
					    struct spindump_connection_set_iterator* iter) {
  spindump_assert(set != 0);
  spindump_assert(iter != 0);
  iter->set = set;
  iter->iteration = 0;
}

int
spindump_connection_set_iterator_end(struct spindump_connection_set_iterator* iter) {
  spindump_assert(iter != 0);
  return(iter->iteration >= iter->set->nConnections);
}

struct spindump_connection*
spindump_connection_set_iterator_next(struct spindump_connection_set_iterator* iter) {
  spindump_assert(iter != 0);
  spindump_assert(!spindump_connection_set_iterator_end(iter));
  return(iter->set->set[iter->iteration++]);
}

void
spindump_connection_set_iterator_uninitialize(struct spindump_connection_set_iterator* iter) {
  spindump_assert(iter != 0);
  // no-op
}
