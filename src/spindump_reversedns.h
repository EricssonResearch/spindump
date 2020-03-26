
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

#ifndef SPINDUMP_REVERSEDNS_H
#define SPINDUMP_REVERSEDNS_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <pthread.h>
#include <stdatomic.h>
#include <netdb.h>
#include <pthread.h>
#include "spindump_util.h"

//
// Data structures ----------------------------------------------------------------------------
//

#define spindump_reverse_dns_maxnentries   128

struct spindump_reverse_dns_entry {
  spindump_address address;                    // written by main thread, read by background thread
  atomic_bool requestMade;                     // written by main thread, read by background thread
  atomic_bool responseGotten;                  // written by background thread, read by main thread
  char responseName[NI_MAXHOST+1];             // written by background thread, read by main thread
  char padding[4];                             // unused
};

struct spindump_reverse_dns;
typedef void (*spindump_reverse_dns_cleanupfn)(struct spindump_reverse_dns* service);

struct spindump_reverse_dns {
  int noop;                                    // written and read by main thread only
  uint8_t padding1[4];                         // unused padding to align the next field properly
  pthread_t thread;                            // written and read by main thread only
  atomic_bool exit;                            // written by main thread, read by background thread
  uint8_t padding2[3];                         // unused padding to align the next field properly
  atomic_uint nextEntryIndex;                  // written by main thread, read by background thread
  struct spindump_reverse_dns_entry entries[spindump_reverse_dns_maxnentries];
  spindump_reverse_dns_cleanupfn cleanupfn;    // written and read by main thread only
  int reverseDnsEnabled;
  pthread_mutex_t reverseDns_mt;
  pthread_cond_t reverseDns_cv;
};

//
// External API interface to this module ------------------------------------------------------
//

struct spindump_reverse_dns*
spindump_reverse_dns_initialize_noop(void);
struct spindump_reverse_dns*
spindump_reverse_dns_initialize_full(int reverseDns);
const char*
spindump_reverse_dns_query(spindump_address* address,
                           struct spindump_reverse_dns* service);
const char*
spindump_reverse_dns_address_tostring(spindump_address* address,
                                      struct spindump_reverse_dns* service);
void
spindump_reverse_dns_uninitialize(struct spindump_reverse_dns* service);

void
spindump_reverse_dns_toggle(struct spindump_reverse_dns* service,
                            int state);

#endif // SPINDUMP_REVERSEDNS_H
