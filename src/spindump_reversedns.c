
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
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pthread.h>
#include <unistd.h>
#include "spindump_util.h"
#include "spindump_reversedns.h"

//
// Actual code --------------------------------------------------------------------------------
//

//
// Create a dummy query service which never knows the names associated
// with addresses.
//

struct spindump_reverse_dns*
spindump_reverse_dns_initialize_noop(void) {

  //
  // Allocate an object
  //

  unsigned int size = sizeof(struct spindump_reverse_dns);
  struct spindump_reverse_dns* service = (struct spindump_reverse_dns*)spindump_malloc(size);
  if (service == 0) {
    spindump_errorf("cannot allocate reverse DNS service object of size %u bytes", size);
    return(0);
  }

  //
  // Initialize object
  //

  memset(service,0,sizeof(*service));
  service->noop = 1;
  service->cleanupfn = 0;
  
  //
  // Done. Return the object.
  //
  
  return(service);
}

//
// Make a query. This function returns either the DNS name associated
// with the given address, in dotted notation, or the null pointer (0)
// if we were unable to determine the name.
//

const char*
spindump_reverse_dns_query(spindump_address* address,
			   struct spindump_reverse_dns* service) {

  //
  // Checks
  //

  spindump_assert(address != 0);
  spindump_assert(service != 0);
  spindump_assert(spindump_isbool(service->noop));

  //
  // If this is supposed to be a no-op service, just return that
  // we didn't find an answer.
  //

  if (service->noop) return(0);

  //
  // Else, we need to look it up. First look up from a local cache of names
  //

  for (unsigned int i = 0; i < spindump_reverse_dns_maxnentries; i++) {
    struct spindump_reverse_dns_entry* entry = &service->entries[i];
    if (entry->requestMade &&
	entry->responseGotten &&
	spindump_address_equal(address,&entry->address)) {

      //
      // Found an entry in the cache. Use it. Just need to check if there's an answer or not.
      //

      if (entry->responseName[0] != 0) {
	return(&entry->responseName[0]);
      } else {
	return(0);
      }

    }
  }

  //
  // If not found, contract the query out to our separate query thread, for it to figure out the answer for the next round of screen updates.
  //

  struct spindump_reverse_dns_entry* newEntry =
    &service->entries[service->nextEntryIndex % spindump_reverse_dns_maxnentries];
  newEntry->requestMade = 0;
  newEntry->address = *address;
  newEntry->responseGotten = 0;
  newEntry->responseName[0] = 0;
  newEntry->requestMade = 1;
  service->nextEntryIndex++;

  //
  // But while the other thread is doing work, for now, we need to say
  // we don't know the answer.
  //

  return(0);
}

//
// Convert an address to a string, either a literal one, or, if a name
// can be found, just the name
//

const char*
spindump_reverse_dns_address_tostring(spindump_address* address,
				      struct spindump_reverse_dns* service) {
  const char* name = spindump_reverse_dns_query(address,service);
  if (name != 0) {
    return(name);
  } else {
    return(spindump_address_tostring(address));
  }
}

//
// Delete the object
//

void
spindump_reverse_dns_uninitialize(struct spindump_reverse_dns* service) {

  //
  // Checks
  //

  spindump_assert(service != 0);
  spindump_assert(spindump_isbool(service->noop));

  //
  // Check if we need to terminate the separate thread and deallocate
  // the local cache
  //

  if (service->cleanupfn != 0) {
    
    (*(service->cleanupfn))(service);
    service->cleanupfn = 0;
    
  }

  //
  // Done. Free the object.
  //

  spindump_free(service);
}

