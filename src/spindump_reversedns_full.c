
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

static int
spindump_reverse_dns_resolveinternal(spindump_address* address,
                                     char* hbuf,
                                     size_t hbufsiz);
static void*
spindump_reverse_dns_backgroundfunction(void* data);
static void
spindump_reverse_dns_backgroundfunction_resolveone(struct spindump_reverse_dns_entry* entry);
static void
spindump_reverse_dns_cleanup(struct spindump_reverse_dns* service);
static int reverseDnsEnabled = 0;
static pthread_mutex_t reverseDns_mt = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t reverseDns_cv = PTHREAD_COND_INITIALIZER;

//
// Actual code --------------------------------------------------------------------------------
//

//
// Create a real query service which attempts to derive names associated
// with addresses via DNS queries.
//

struct spindump_reverse_dns*
spindump_reverse_dns_initialize_full(int reverseDns) {

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
  service->noop = 0;
  service->cleanupfn = spindump_reverse_dns_cleanup;
  
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
  reverseDnsEnabled = reverseDns;

  if (pthread_create(&service->thread,0,spindump_reverse_dns_backgroundfunction,(void*)service) != 0) {
    spindump_errorf("cannot create a thread for reverse DNS process");
    spindump_free(service);
    return(0);
  }

  //
  // Done. Return the object.
  //

  return(service);
}

//
// The actual function that performs the resolving on address to a
// name.
//

static int
spindump_reverse_dns_resolveinternal(spindump_address* address,
                                     char* hbuf,
                                     size_t hbufsiz) {

  //
  // Checks
  //

  spindump_assert(address != 0);
  spindump_assert(hbuf != 0);
  spindump_assert(hbufsiz > 10);
  
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
    spindump_errorf("invalid address family");
    return(0);
  }
  spindump_assert(sa != 0);

  //
  // Convert the sockaddr to a name, if one exists
  // The sockaddr definition is different between Linux and BSD
  //

  memset(hbuf,0,hbufsiz);
  int err;
#if defined(__linux__)
  if ((err = getnameinfo(sa, sizeof(*sa), hbuf, (socklen_t)(hbufsiz-1), NULL, 0,
                  NI_NAMEREQD))) {
#else
  if ((err = getnameinfo(sa, sa->sa_len, hbuf, (socklen_t)(hbufsiz-1), NULL, 0,
                  NI_NAMEREQD))) {
#endif
    spindump_deepdebugf("spindump_reversedns getnameinfo returned error code %s ", gai_strerror(err));
    return(0);
  } else {
    return(1);
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
  
  char hbuf[NI_MAXHOST+1];
  int result = spindump_reverse_dns_resolveinternal(&entry->address,hbuf,sizeof(hbuf));
  
  //
  // Fill in the answer
  //

  if (result == 0) {
    entry->responseName[0] = 0;
  } else {
    spindump_assert(strlen(hbuf) < sizeof(entry->responseName)-1);
    spindump_strlcpy(&entry->responseName[0],hbuf,sizeof(entry->responseName));
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

  pthread_mutex_lock(&reverseDns_mt);

  while (!service->exit) {

    //
    // Sanity checks again
    //

    spindump_assert(spindump_isbool(service->exit));

    //
    // See if we should proceed with the names resolution
    //

    if (!reverseDnsEnabled) {
      pthread_cond_wait(&reverseDns_cv, &reverseDns_mt);
      continue;
    }

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
    // Sleep a bit (10 ms), wake up to check if we see some request
    //

    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);

    long nsecToWait = timeout.tv_nsec + (10 * 1000 * 1000);

    timeout.tv_sec  = nsecToWait / (1000 * 1000 * 1000);
    timeout.tv_nsec = nsecToWait % (1000 * 1000 * 1000);

    pthread_cond_timedwait(&reverseDns_cv, &reverseDns_mt, &timeout);
  }

  pthread_mutex_unlock(&reverseDns_mt);

  //
  // Done.
  //

  return(0);
}

static void
spindump_reverse_dns_cleanup(struct spindump_reverse_dns* service) {
  spindump_assert(service != 0);
  spindump_assert(spindump_isbool(service->noop));

  pthread_mutex_lock(&reverseDns_mt);
  service->exit = 1;
  pthread_cond_signal(&reverseDns_cv);
  pthread_mutex_unlock(&reverseDns_mt);

  pthread_join(service->thread,0);
}

void
spindump_reverse_dns_toggle(int state) {
  pthread_mutex_lock(&reverseDns_mt);
  reverseDnsEnabled = state;
  pthread_cond_signal(&reverseDns_cv);
  pthread_mutex_unlock(&reverseDns_mt);
}
