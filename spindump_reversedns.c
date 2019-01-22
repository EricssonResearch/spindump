
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
#include "spindump_reversedns.h"

//
// Actual code --------------------------------------------------------------------------------
//

//
// Create a dummy query service which never knows the names associated
// with addresses.
//

struct spindump_reverse_dns*
spindump_reverse_dns_initialize_noop() {

  //
  // Allocate an object
  //
  
  unsigned int size = sizeof(struct spindump_reverse_dns);
  struct spindump_reverse_dns* service = (struct spindump_reverse_dns*)malloc(size);
  if (service == 0) {
    spindump_fatalf("cannot allocate reverse DNS service object of size %u bytes", size);
    return(0);
  }

  //
  // Initialize object
  //
  
  memset(service,0,sizeof(*service));
  service->noop = 0;
  
  //
  // Done. Return the object.
  //
  
  return(service);
}

//
// Create a real query service which attempts to derive names associated
// with addresses via DNS queries.
//

struct spindump_reverse_dns*
spindump_reverse_dns_initialize_full() {
  
  //
  // Allocate an object
  //
  
  unsigned int size = sizeof(struct spindump_reverse_dns);
  struct spindump_reverse_dns* service = (struct spindump_reverse_dns*)malloc(size);
  if (service == 0) {
    spindump_fatalf("cannot allocate reverse DNS service object of size %u bytes", size);
    return(0);
  }

  //
  // Initialize object
  //
  
  memset(service,0,sizeof(*service));
  service->noop = 0;

  //
  // Setup a local cache of address-to-name mappings
  //
  
  // ... */

  //
  // Setup a separate thread to make queries in the background
  //
  
  // ... */
  
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

  // ...

  //
  // If not found, contract the query out to our separate query thread, for it to figure out the answer for the next round of screen updates.
  //

  // ...

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
  if (name != 0) return(name);
  else return(spindump_address_tostring(address));
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

  if (!service->noop) {
    
    // ...
    
  }
  
  //
  // Done. Free the object.
  //
  
  free(service);
}
