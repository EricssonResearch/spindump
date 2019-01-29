
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
#include "spindump_table_structs.h"
#include "spindump_connections_structs.h"
#include "spindump_table.h"
#include "spindump_connections.h"
#include "spindump_stats.h"
#include "spindump_analyze.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static void
spindump_connectionstable_periodiccheck_aux(struct spindump_connection* connection,
					    const struct timeval* now,
					    struct spindump_connectionstable* table,
					    struct spindump_analyze* analyzer);
static void
spindump_connectionstable_compresstable(struct spindump_connectionstable* table);

//
// Actual code --------------------------------------------------------------------------------
//

struct spindump_connectionstable*
spindump_connectionstable_initialize() {

  //
  // Figure out sizes
  // 
  
  unsigned int maintabsize = sizeof(struct spindump_connectionstable);
  unsigned int variabletabelements = spindump_connectionstable_defaultsize;
  unsigned int variabletabsize = variabletabelements * sizeof(struct spindump_connection*);
  
  //
  // Allocate the main table
  // 
  
  struct spindump_connectionstable* table = (struct spindump_connectionstable*)malloc(maintabsize);
  if (table == 0) {
    spindump_errorf("cannot allocate connection table for %u bytes", maintabsize);
    return(0);
  }
  
  //
  // Initialize the main table
  // 
  
  memset(table,0,sizeof(*table));
  table->nConnections = 0;
  table->maxNConnections = variabletabelements;
  
  //
  // Allocate the actual table of connections
  // 
  
  table->connections = (struct spindump_connection**)malloc(variabletabsize);
  if (table->connections == 0) {
    spindump_errorf("cannot allocate the variable-size connection table for %u bytes", variabletabsize);
    spindump_deepdebugf("free table after an error");
    free(table);
    return(0);
  }
  
  //
  // Initialize the actual table of connections
  // 
  
  unsigned int i;
  for (i = 0; i < table->maxNConnections; i++) {
    table->connections[i] = 0;
  }
  
  //
  // Done. Return the table.
  // 
  
  return(table);
}

void
spindump_connectionstable_uninitialize(struct spindump_connectionstable* table) {
  spindump_assert(table != 0);
  spindump_assert(table->connections != 0);
  memset(table->connections,0xFF,table->maxNConnections * sizeof(struct spindump_connection*));
  spindump_deepdebugf("free table->connections %lx in spindump_connections_freetable", table->connections);
  free(table->connections);
  memset(table,0xFF,sizeof(*table));
  spindump_deepdebugf("free table in spindump_connections_freetable");
  free(table);
}

static void
spindump_connectionstable_periodiccheck_aux(struct spindump_connection* connection,
					    const struct timeval* now,
					    struct spindump_connectionstable* table,
					    struct spindump_analyze* analyzer) {


  //
  // Sanity checks
  //

  spindump_assert(connection != 0);
  spindump_assert(now != 0);
  spindump_assert(now->tv_sec > 0);
  spindump_assert(now->tv_usec < 1000 * 1000);
  spindump_assert(table != 0);
  spindump_assert(analyzer != 0);
  
  //
  // Check if we have an automatically created, dynamic
  // connection. For manually created ones, there's no need for
  // periodic cleanup.
  //

  if (connection->manuallyCreated) return;
  
  //
  // See when the last event related to this connection was
  //
  
  unsigned long long lastAction = spindump_connections_lastaction(connection,now);

  //
  // If the connection has been explictly deleted (e.g., TCP FIN/RST),
  // we can delete it sooner
  //

  struct spindump_stats* stats = spindump_analyze_getstats(analyzer);
  
  if (connection->deleted &&
      lastAction >= (unsigned long long)(spindump_connection_deleted_timeout)) {
    
    spindump_connectionstable_deleteconnection(connection,table,analyzer,"closed");
    stats->connectionsDeletedClosed++;
    
  } else if (spindump_connections_isestablishing(connection) &&
	     lastAction >= (unsigned long long)(spindump_connection_establishing_timeout)) {
    
    spindump_deepdebugf("timeouts last action %llu timeout %lu comparison %llu",
			lastAction,
			spindump_connection_establishing_timeout,
			(unsigned long long)(spindump_connection_establishing_timeout));
    spindump_connectionstable_deleteconnection(connection,table,analyzer,"failed");
    stats->connectionsDeletedInactive++;
    
  } else if (lastAction >= (unsigned long long)(spindump_connection_inactive_timeout)) {
    
    spindump_connectionstable_deleteconnection(connection,table,analyzer,"inactive");
    stats->connectionsDeletedInactive++;
    
  }
}

static void
spindump_connectionstable_compresstable(struct spindump_connectionstable* table) {
  unsigned int shiftdown = 0;
  for (unsigned int i = 0; i < table->nConnections; i++) {
    if (table->connections[i] == 0) {
      shiftdown++;
    } else if (shiftdown > 0) {
      table->connections[i-shiftdown] = table->connections[i];
      table->connections[i] = 0;
    }
  }
  table->nConnections -= shiftdown;
  if (shiftdown > 0) spindump_debugf("spindump_connectionstable_compresstable freed %u positions", shiftdown);
}

int
spindump_connectionstable_periodiccheck(struct spindump_connectionstable* table,
					const struct timeval* now,
					struct spindump_analyze* analyzer) {
  spindump_assert(now->tv_sec > 0);
  spindump_assert(now->tv_usec < 1000 * 1000);
  if (table->lastPeriodicCheck.tv_sec != now->tv_sec) {
    for (unsigned int i = 0; i < table->nConnections; i++) {
      struct spindump_connection* connection = table->connections[i];
      if (connection != 0) spindump_connectionstable_periodiccheck_aux(connection,now,table,analyzer);
    }
    spindump_connectionstable_compresstable(table);
    return(1);
  } else {
    return(0);
  }
}

void
spindump_connectionstable_deleteconnection(struct spindump_connection* connection,
					   struct spindump_connectionstable* table,
					   struct spindump_analyze* analyzer,
					   const char* reason) {

  //
  // Do some checks & print debugs
  // 
  
  spindump_assert(connection != 0);
  spindump_assert(table != 0);
  spindump_assert(reason != 0);
  
  spindump_debugf("deleting %s connection %u due to %s",
		  spindump_connection_type_to_string(connection->type),
		  connection->id,
		  reason);

  //
  // Call some handlers
  //
  
  struct spindump_packet dummy;
  memset(&dummy,0,sizeof(dummy));
  spindump_getcurrenttime(&dummy.timestamp);
  spindump_analyze_process_handlers(analyzer,
				    spindump_analyze_event_connectiondelete,
				    &dummy,
				    connection);
  
  //
  // Delete the connection from the table
  // 

  int found = 0;
  for (unsigned int i = 0; i < table->nConnections; i++) {
    if (table->connections[i] == connection) {
      found = 1;
      table->connections[i] = 0;
    }
  }
  
  spindump_assert(found);
  
  //
  // Delete the object
  // 

  spindump_connections_delete(connection);
}

void
spindump_connectionstable_report(struct spindump_connectionstable* table,
				 FILE* file,
				 struct spindump_reverse_dns* querier) {
  unsigned int i;
  spindump_assert(table != 0);
  for (i = 0; i < table->nConnections; i++) {
    struct spindump_connection* connection = table->connections[i];
    if (connection != 0) spindump_connection_report(connection,file,querier);
  }
}
