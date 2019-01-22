
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

#include "spindump_util.h"

//
// Data structures ----------------------------------------------------------------------------
//

struct spindump_reverse_dns {
  int noop;
  // ...
};

//
// External API interface to this module ------------------------------------------------------
//

struct spindump_reverse_dns*
spindump_reverse_dns_initialize_noop();
struct spindump_reverse_dns*
spindump_reverse_dns_initialize_full();
const char*
spindump_reverse_dns_query(spindump_address* address,
			   struct spindump_reverse_dns* service);
const char*
spindump_reverse_dns_address_tostring(spindump_address* address,
				      struct spindump_reverse_dns* service);
void
spindump_reverse_dns_uninitialize(struct spindump_reverse_dns* service);

#endif // SPINDUMP_REVERSEDNS_H
