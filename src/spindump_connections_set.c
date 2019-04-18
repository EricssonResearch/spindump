
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

#include <stdlib.h>
#include <string.h>
#include "spindump_util.h"
#include "spindump_connections_set.h"
#include "spindump_connections.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static void
spindump_connections_set_unlinkfromset(struct spindump_connection* connection,
				       struct spindump_connection* otherConnection);

//
// Actual code --------------------------------------------------------------------------------
//

//
// Notify a given connection object that it is being removed from a
// given set by another connection, and that consequently, the first
// connection should remove any links it might have with the second
// connection as well.
// 

static void
spindump_connections_set_unlinkfromset(struct spindump_connection* connection,
				       struct spindump_connection* otherConnection) {
  spindump_assert(connection != 0);
  spindump_assert(otherConnection != 0);
  if (spindump_connections_set_inset(&connection->aggregates,otherConnection)) {
    spindump_connections_set_remove(&connection->aggregates,otherConnection);
  }
  
  switch (connection->type) {
    
  case spindump_connection_transport_udp:
  case spindump_connection_transport_tcp:
  case spindump_connection_transport_quic:
  case spindump_connection_transport_dns:
  case spindump_connection_transport_coap:
  case spindump_connection_transport_icmp:
    break;
    
  case spindump_connection_aggregate_hostpair:
    if (spindump_connections_set_inset(&connection->u.aggregatehostpair.connections,otherConnection)) {
      spindump_connections_set_remove(&connection->u.aggregatehostpair.connections,otherConnection);
    }
    break;
    
  case spindump_connection_aggregate_hostnetwork:
    if (spindump_connections_set_inset(&connection->u.aggregatehostnetwork.connections,otherConnection)) {
      spindump_connections_set_remove(&connection->u.aggregatehostnetwork.connections,otherConnection);
    }
    break;
    
  case spindump_connection_aggregate_networknetwork:
    if (spindump_connections_set_inset(&connection->u.aggregatenetworknetwork.connections,otherConnection)) {
      spindump_connections_set_remove(&connection->u.aggregatenetworknetwork.connections,otherConnection);
    }
    break;
    
  case spindump_connection_aggregate_multicastgroup:
    if (spindump_connections_set_inset(&connection->u.aggregatemulticastgroup.connections,otherConnection)) {
      spindump_connections_set_remove(&connection->u.aggregatemulticastgroup.connections,otherConnection);
    }
    break;

  default:
    spindump_errorf("invalid connection type");
    break;
  }
}

//
// Initialize a connection set. Only an initialized connection set can
// be operated on to add or remove elements.
//
// An initialized connection set must be de-initialized before
// deallocation with the spindump_connections_set_uninitialize
// function.
// 

void
spindump_connections_set_initialize(struct spindump_connection_set* set) {
  spindump_assert(set != 0);
  memset(set,0,sizeof(*set));
}

//
// De-initialize a connection set; only an initialized connection set can be
// de-initialized. All resources dedicated to the set are freed. The set is in
// the connection "owner".
// 

void
spindump_connections_set_uninitialize(struct spindump_connection_set* set,
				      struct spindump_connection* owner) {
  spindump_assert(set != 0);
  if (set->maxNConnections > 0) {
    unsigned int i;
    for (i = 0; i < set->nConnections; i++) {
      struct spindump_connection* connection = set->set[i];
      spindump_assert(connection != 0);
      spindump_connections_set_unlinkfromset(connection,owner);
    }
    spindump_deepdebugf("freeting the set table in spindump_connections_set_uninitialize");
    spindump_free(set->set);
  }
  memset(set,0,sizeof(*set));
}

//
// Determine if a given connection is in the set.
// 

int
spindump_connections_set_inset(struct spindump_connection_set* set,
			       struct spindump_connection* connection) {
  spindump_assert(set != 0);
  spindump_assert(connection != 0);
  for (unsigned int i = 0; i < set->nConnections; i++) {
    if (set->set[i] == connection) return(1);
  }
  return(0);
}

//
// Add a new connection to the set.
// 

void
spindump_connections_set_add(struct spindump_connection_set* set,
			     struct spindump_connection* connection) {
  spindump_assert(set != 0);
  spindump_assert(connection != 0);
  spindump_assert(!spindump_connections_set_inset(set,connection));
  
  if (set->set == 0) {

    //
    // Make the first allocation of the table
    // 
    
    spindump_assert(set->nConnections == 0);
    spindump_assert(set->maxNConnections == 0);
    unsigned int defaultN = 10;
    unsigned int size = defaultN * sizeof(struct spindump_connection*);
    set->set = (struct spindump_connection**)spindump_malloc(size);
    if (set->set == 0) {
      spindump_fatalf("cannot allocate connection set of %u bytes", size);
    }
    memset(set->set,0,size);
    set->maxNConnections = defaultN;
    set->nConnections = 1;
    set->set[0] = connection;

  } else if (set->nConnections < set->maxNConnections) {

    //
    // Still space at the table, just add to it
    // 
    
    set->set[set->nConnections++] = connection;
    
  } else {
    
    //
    // Expand the already existing table
    // 
    
    spindump_assert(set->maxNConnections > 0);
    unsigned int newN = 2 * set->maxNConnections;
    unsigned int size = newN * sizeof(struct spindump_connection*);
    struct spindump_connection** newSet = (struct spindump_connection**)spindump_malloc(size);
    if (newSet == 0) {
      spindump_fatalf("cannot expand connection set to %u bytes", size);
    }
    memset(newSet,0,size);
    memcpy(newSet,set->set,set->maxNConnections * sizeof(struct spindump_connection*));
    set->maxNConnections = newN;
    set->set = newSet;
    set->set[set->nConnections++] = connection;
    
  }
}

//
// Remove an item from a connection set
// 

void
spindump_connections_set_remove(struct spindump_connection_set* set,
				struct spindump_connection* connection) {
  spindump_assert(set != 0);
  spindump_assert(connection != 0);
  spindump_assert(set->nConnections > 0);
  spindump_assert(set->maxNConnections > 0);
  spindump_assert(set->set != 0);
  
  for (unsigned int i = 0; i < set->nConnections; i++) {
    if (set->set[i] == connection) {
      for (unsigned int j = i+1; j < set->nConnections; j++) {
	set->set[j-1] = set->set[j];
      }
      set->set[set->nConnections -1] = 0;
      set->nConnections--;
      return;
    }
  }
  
  spindump_errorf("attempted to remove connection %u from a set that does not include that connection",
		  connection->id);
}

//
// Return a string listing (some maximum number of) connection IDs of
// the connections in the set.
// 
// Note: This function is not thread safe.
//

const char*
spindump_connections_set_listids(struct spindump_connection_set* set) {
  static char buf[200];
  int seenone = 0;
  memset(buf,0,sizeof(buf));
  for (unsigned int i = 0; i < set->nConnections; i++) {
    struct spindump_connection* connection = set->set[i];
    if (connection != 0) {
      snprintf(buf+strlen(buf),
	       sizeof(buf)-1-strlen(buf),
	       "%s%u",
	       seenone ? "," : "",
	       connection->id);
      seenone = 1;
    }
  }
  return(buf);
}
