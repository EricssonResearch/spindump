
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

#ifndef SPIDUMP_UTIL_H
#define SPIDUMP_UTIL_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/in.h>

//
// Some helper macros -------------------------------------------------------------------------
//

#ifdef SPINDUMP_DEBUG
#define spindump_assert(cond)	if (!(cond)) {                                      \
                                  spindump_fatalf("Assertion failed on %s line %u", \
                                                  __FILE__, __LINE__);		    \
                                }
#else
#define spindump_assert(cond)
#endif
#define spindump_max(a,b)       ((a) > (b) ? (a) : (b))
#define spindump_min(a,b)       ((a) < (b) ? (a) : (b))
#define spindump_isbool(x)      ((x) == 0 || (x) == 1)
#define spindump_iszerotime(x)  ((x)->tv_sec == 0)

//
// Types --------------------------------------------------------------------------------------
//

typedef struct sockaddr_storage spindump_address;
typedef struct {
  spindump_address address;
  unsigned int length;
} spindump_network;

//
// Configuration variables --------------------------------------------------------------------
//

extern int debug;
extern int deepdebug;

//
// External API interface to this module ------------------------------------------------------
//

void
spindump_getcurrenttime(struct timeval* result);
unsigned long long
spindump_timediffinusecs(const struct timeval* later,
			 const struct timeval* earlier);
int
spindump_isearliertime(const struct timeval* later,
		       const struct timeval* earlier);
void
spindump_zerotime(struct timeval* result);
const char*
spindump_timetostring(const struct timeval* result);
int
spindump_address_fromstring(spindump_address* address,
			    const char* string);
void
spindump_address_frombytes(spindump_address* address,
			   int af,
			   const unsigned char* string);
const char*
spindump_address_tostring(spindump_address* address);
const char*
spindump_address_tostring_anon(int anonymize,
			       spindump_address* address);
int
spindump_network_fromstring(spindump_network* network,
			    const char* string);
const char*
spindump_network_tostring(spindump_network* network);
int
spindump_address_equal(spindump_address* address1,
		       spindump_address* address2);
int
spindump_address_innetwork(spindump_address* address,
			   spindump_network* network);
int
spindump_address_ismulticast(spindump_address* address);
int
spindump_network_equal(spindump_network* network1,
		       spindump_network* network2);
int
spindump_network_ismulticast(spindump_network* network);
const char*
spindump_meganumber_tostring(unsigned long x);
const char*
spindump_meganumberll_tostring(unsigned long long x);
void
spindump_seterrordestination(FILE* file);
void
spindump_fatalf(const char* format, ...);
void
spindump_fatalp(const char* message);
void
spindump_errorf(const char* format, ...);
void
spindump_errorp(const char* message);
void
spindump_warnf(const char* format, ...);
void
spindump_setdebugdestination(FILE* file);
void
spindump_debugf(const char* format, ...);
void
spindump_deepdebugf(const char* format, ...);
#if defined(__linux__)
size_t
strlcpy(char * restrict dst, const char * restrict src, size_t size);
#endif

#endif // SPIDUMP_UTIL_H
