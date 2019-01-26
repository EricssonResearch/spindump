
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
// Function prototypese -----------------------------------------------------------------------
//

static const char*
spindump_reverse_dns_resolveinternal(spindump_address* address);
static void*
spindump_reverse_dns_backgroundfunction(void* data);
static void
spindump_reverse_dns_backgroundfunction_resolveone(struct spindump_reverse_dns_entry* entry);

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
  service->noop = 1;
  
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
  // Set parameters that control the background thread
  //
  
  service->exit = 0;
  
  //
  // Setup a local cache of address-to-name mappings & the request table
  // for the background thread
  //
  
  service->nextEntryIndex = 0;
  
  //
  // Setup a separate thread to make queries in the background
  //
  
  if (pthread_create(&service->thread,0,spindump_reverse_dns_backgroundfunction,(void*)service) != 0) {
    spindump_fatalf("cannot create a thread for reverse DNS process");
    free(service);
    return(0);
  }
  
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
    
    service->exit = 1;
    pthread_join(service->thread,0);
    
  }
  
  //
  // Done. Free the object.
  //
  
  free(service);
}

static const char*
spindump_reverse_dns_resolveinternal(spindump_address* address) {

  //
  // Checks
  //

  spindump_assert(address != 0);

  //
  // Convert the given address to a sockaddr (that includes a port; we
  // set the port to 0).
  //
  
  struct sockaddr_in sa4;
  struct sockaddr_in6 sa6;
  struct sockaddr* sa = 0;
  if (address->ss_family == AF_INET) {
    memset(&sa4,0,sizeof(sa4));
    sa4 = *(struct sockaddr_in*)address;
    sa4.sin_port = 0;
    sa = (struct sockaddr*)&sa4;
  } else if (address->ss_family == AF_INET6) {
    memset(&sa6,0,sizeof(sa6));
    sa6 = *(struct sockaddr_in6*)address;
    sa6.sin6_port = 0;
    sa = (struct sockaddr*)&sa6;
  } else {
    spindump_fatalf("invalid address family");
    return(0);
  }
  spindump_assert(sa != 0);
  
  //
  // Convert the sockaddr to a name, if one exists
  //
  
  static char hbuf[NI_MAXHOST+1];
  memset(hbuf,0,sizeof(hbuf));
  if (getnameinfo(sa, sa->sa_len, hbuf, sizeof(hbuf)-1, NULL, 0,
		  NI_NAMEREQD)) {
    return(0);
  } else {
    return(hbuf);
  }
}

//
// This is the function to actually resolve an address to a DNS
// name. This is being called in the background thread.
//

static void
spindump_reverse_dns_backgroundfunction_resolveone(struct spindump_reverse_dns_entry* entry) {

  //
  // Sanity checks
  //
  
  spindump_assert(entry != 0);

  //
  // Prepare the entry while we ask
  //
  
  entry->responseGotten = 0;
  
  //
  // Ask
  //
  
  const char* result = spindump_reverse_dns_resolveinternal(&entry->address);
  
  //
  // Fill in the answer
  //
  
  if (result == 0) {
    entry->responseName[0] = 0;
  } else {
    spindump_assert(strlen(result) < sizeof(entry->responseName)-1);
    strcpy(&entry->responseName[0],result);
  }
  
  //
  // Mark the entry as answered
  //

  spindump_deepdebugf("spindump_reversedns background thread resolved an address to %s", entry->responseName);
  entry->responseGotten = 1;
}

//
// The function that works in the background and takes DNS reverse
// query jobs, filling in the results in the service table as they
// come in. This is run in a thread started by
// spindump_reverse_dns_initialize_full.
//

static void*
spindump_reverse_dns_backgroundfunction(void* data) {

  //
  // Checks
  //
  
  spindump_assert(data != 0);

  //
  // Cast the input parameter passed to us by pthread_create
  //
  
  struct spindump_reverse_dns* service = (struct spindump_reverse_dns*)data;
  spindump_assert(spindump_isbool(service->exit));
  
  //
  // Main loop. Sleep a bit and come back to see if there's work for
  // us, or if we're told to exit.
  //
  
  unsigned int previousNextEntryIndex = 0;
  
  while (!service->exit) {
    
    //
    // Sanity checks again
    //
    
    spindump_assert(spindump_isbool(service->exit));

    //
    // See if our index has wrapped around. We only allow this to
    // happen when we run out of atomic_uint size. Then we will start
    // from the beginning again.
    //
    
    if (service->nextEntryIndex < previousNextEntryIndex) {
      previousNextEntryIndex = 0;
    }
    
    //
    // See if there's a request for us. Or requests.
    //

    while (service->nextEntryIndex > previousNextEntryIndex) {
      struct spindump_reverse_dns_entry* entry =
	&service->entries[previousNextEntryIndex++ % spindump_reverse_dns_maxnentries];
      spindump_reverse_dns_backgroundfunction_resolveone(entry);
    }
    
    //
    // Sleep a bit, wake up to check if we see some request
    //
    
    usleep(10 * 1000);
  }
  
  //
  // Done.
  //
  
  return(0);
}
