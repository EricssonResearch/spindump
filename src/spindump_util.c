
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

#include <time.h>
#include <ctype.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include "spindump_util.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static int
spindump_address_islocalbroadcast(uint32_t address);
static void
spindump_anon_aux(unsigned long seed,
		  unsigned char* bytes,
		  unsigned int length);

//
// Variables ----------------------------------------------------------------------------------
//

static FILE* errordestination = 0;
int debug = 0;
int deepdebug = 0;
static FILE* debugdestination = 0;

//
// Actual code --------------------------------------------------------------------------------
//

//
// Get current time
//

void
spindump_getcurrenttime(struct timeval* result) {

  //
  // Sanity checks
  //
  
  spindump_assert(result != 0);

  //
  // Get the time, see if we can get it
  //
  
  if (gettimeofday(result, 0) < 0) {
    spindump_errorp("cannot determine current time via gettimeofday");
    result->tv_sec = result->tv_usec = 0;
    return;
  }

  //
  // Sanity check the value gotten
  //
  
  if (result->tv_usec >= 1000 * 1000) {
    spindump_errorf("cannot have usec value greater than 1 000 000, got %lu", result->tv_usec);
    result->tv_sec = result->tv_usec = 0;
    return;
  }
  
}

//
// Time subtraction
//

unsigned long long
spindump_timediffinusecs(const struct timeval* later,
			 const struct timeval* earlier) {
  
  spindump_assert(earlier != 0);
  spindump_assert(later != 0);
  spindump_assert(later->tv_usec < 1000 * 1000);
  spindump_assert(earlier->tv_usec < 1000 * 1000);
  
  if (later->tv_sec < earlier->tv_sec) {
    spindump_errorf("expected later time to be greater, seconds go back %lus", earlier->tv_sec - later->tv_sec);
    return(0);
  }
  if (later->tv_sec == earlier->tv_sec) {
    if (later->tv_usec < earlier->tv_usec) {
      spindump_errorf("spindump_timediffinusec: expected later time to be greater, secs both %uls, microsecond go back %ulus (%ul to %ul)",
		      earlier->tv_sec,
		      earlier->tv_usec - later->tv_usec,
		      earlier->tv_usec, later->tv_usec);
      return(0);
    } else {
      return(later->tv_usec - earlier->tv_usec);
    }
  } else {
    unsigned long long result = 1000 * 1000 * (later->tv_sec - earlier->tv_sec - 1);
    result += (1000*1000) - earlier->tv_usec;
    result += later->tv_usec;
    return(result);
  }
}

//
// Check if one time "earlier" is indeed earlier than
// another time "later".
// 

int
spindump_isearliertime(const struct timeval* later,
		       const struct timeval* earlier) {
  spindump_assert(later != 0);
  spindump_assert(earlier != 0);
  spindump_assert(later->tv_usec < 1000 * 1000);
  spindump_assert(earlier->tv_usec < 1000 * 1000);
  if (earlier->tv_sec < later->tv_sec) return(1);
  else if (earlier->tv_sec == later->tv_sec &&
	   earlier->tv_usec < later->tv_usec) return(1);
  else return(0);
}

//
// Reset time
//

void
spindump_zerotime(struct timeval* result) {
  spindump_assert(result != 0);
  memset(result,0,sizeof(*result));
}

//
// Get time as string. The result need not be deallocated, but is only
// valid for one call at a time
//

const char*
spindump_timetostring(const struct timeval* result) {
  spindump_assert(result != 0);
  static char buf[100];
  struct tm* t = localtime(&result->tv_sec);
  snprintf(buf,sizeof(buf)-1,"%02u:%02u:%02u.%06u",
	   t->tm_hour,
	   t->tm_min,
	   t->tm_sec,
	   result->tv_usec);
  return(buf);
}

//
// Address comparison
//

int
spindump_address_equal(spindump_address* address1,
		       spindump_address* address2) {
  
  if (address1->ss_family != address2->ss_family) return(0);
  
  switch (address1->ss_family) {
    
  case AF_INET:
    {
      struct sockaddr_in* address1v4 = (struct sockaddr_in*)address1;
      struct sockaddr_in* address2v4 = (struct sockaddr_in*)address2;
      return(address1v4->sin_addr.s_addr == address2v4->sin_addr.s_addr);
    }
    
  case AF_INET6:
    {
      struct sockaddr_in6* address1v6 = (struct sockaddr_in6*)address1;
      struct sockaddr_in6* address2v6 = (struct sockaddr_in6*)address2;
      return(memcmp(address1v6->sin6_addr.s6_addr,address2v6->sin6_addr.s6_addr,16) == 0);
    }
    
  default:
    return(0);
  }
}

//
// Multicast address check
//

static int
spindump_address_islocalbroadcast(uint32_t address) {

  //
  // To find out if an IPv4 address is a local broadcast address, we
  // need to determine what the local interfaces and their addresses
  // and netmasks are.  Do this by calling getifaddrs, and then
  // storing the information in a static variable. Next calls will
  // reuse the same information.  NOTE: This implies that if
  // interfaces are brought up and down, the data does not get
  // updated.
  // 

  static struct ifaddrs* interfaces = 0;

  if (interfaces == 0) {
    getifaddrs(&interfaces);
  }
  
  if (interfaces == 0) {
    
    spindump_warnf("cannot get information about local interfaces");
    return(0);
    
  }

  //
  // Now we have interface information. Lets go through that and see
  // if our address is a broadcast address within those.
  // 
  
  for (struct ifaddrs* thisInterface = interfaces;
       thisInterface != 0;
       thisInterface = thisInterface->ifa_next) {

    if (thisInterface->ifa_addr != 0 &&
	thisInterface->ifa_netmask != 0 &&
	thisInterface->ifa_addr->sa_family == AF_INET) {
      
      spindump_deepdebugf("local broadcast: looking at interface %s",
			  thisInterface->ifa_name != 0 ? thisInterface->ifa_name : "none");
      struct sockaddr_in* addressv4 = (struct sockaddr_in*)thisInterface->ifa_addr;
      struct sockaddr_in* maskv4 = (struct sockaddr_in*)thisInterface->ifa_netmask;
      uint32_t thisBroadcast =
	(addressv4->sin_addr.s_addr & maskv4->sin_addr.s_addr) |
	(~(maskv4->sin_addr.s_addr));
      spindump_deepdebugf("address %08x netmask %08x broadcast %08x compare to %08x\n",
			  addressv4->sin_addr.s_addr,
			  maskv4->sin_addr.s_addr,
			  thisBroadcast,
			  address);
      if (address == thisBroadcast) return(1);
    }
  }
  
  //
  // We did not find an interface that would match this address as its
  // broadcast address.
  // 
  
  return(0);
    
}

int
spindump_address_ismulticast(spindump_address* address) {

  switch (address->ss_family) {

  case AF_INET:

    //
    // IPv4 per https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml
    //
    
    {
      struct sockaddr_in* addressv4 = (struct sockaddr_in*)address;
      uint32_t highByte = (ntohl(addressv4->sin_addr.s_addr) >> 24) & 0xFF;
      spindump_deepdebugf("spindump_address_ismulticast v4 high byte = %02x", highByte);
      return(spindump_address_islocalbroadcast(addressv4->sin_addr.s_addr) ||
	     (highByte >= 224 && highByte <= 239) ||
	     (highByte == 255));
    }
    
  case AF_INET6:

    //
    // IPv6 per https://www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xml
    //

    {
      struct sockaddr_in6* addressv6 = (struct sockaddr_in6*)address;
      uint8_t* addressValue = addressv6->sin6_addr.s6_addr;
      spindump_deepdebugf("spindump_address_ismulticast v6 high byte = %02x", addressValue[0]);
      return(addressValue[0] == 0xFF);
    }
    
  default:

    //
    // Other. Not a known multicast address, certainly!
    //
    
    return(0);
    
  }
}

//
// Network prefix comparison
//

int
spindump_network_equal(spindump_network* network1,
		       spindump_network* network2) {
  return(network1->length == network2->length &&
	 spindump_address_equal(&network1->address,
				&network2->address));
}

//
// Checking if a network is multicast network
//

int
spindump_network_ismulticast(spindump_network* network) {
  return(network->length >= 8 &&
	 spindump_address_ismulticast(&network->address));
}

//
// Address comparison to a network prefix
//

int
spindump_address_innetwork(spindump_address* address,
			   spindump_network* network) {

  static const uint32_t v4prefixmasks[33] = {
    
    0x00000000,
    
    0x80000000,
    0xC0000000,
    0xE0000000,
    0xF0000000,
    
    0xF8000000,
    0xFC000000,
    0xFE000000,
    0xFF000000,

    0xFF800000,
    0xFFC00000,
    0xFFE00000,
    0xFFF00000,

    0xFFF80000,
    0xFFFC0000,
    0xFFFE0000,
    0xFFFF0000,
    
    0xFFFF8000,
    0xFFFFC000,
    0xFFFFE000,
    0xFFFFF000,
    
    0xFFFFF800,
    0xFFFFFC00,
    0xFFFFFE00,
    0xFFFFFF00,

    0xFFFFFF80,
    0xFFFFFFC0,
    0xFFFFFFE0,
    0xFFFFFFF0,

    0xFFFFFFF8,
    0xFFFFFFFC,
    0xFFFFFFFE,
    0xFFFFFFFF
  };
  
  static const uint8_t v6prefixmasks[9] = {
    
    0x00,
    
    0x80,
    0xC0,
    0xE0,
    0xF0,
    
    0xF8,
    0xFC,
    0xFE,
    0xFF
    
  };
  
  spindump_assert(address != 0);
  spindump_assert(address->ss_family != 0);
  spindump_assert(network != 0);
  spindump_assert(network->address.ss_family != 0);
  
  if (address->ss_family != network->address.ss_family) return(0);
  
  switch (address->ss_family) {
    
  case AF_INET:
    {
      struct sockaddr_in* addressv4 = (struct sockaddr_in*)address;
      struct sockaddr_in* networkv4 = (struct sockaddr_in*)&network->address;
      uint32_t addressValue = htonl(addressv4->sin_addr.s_addr);
      uint32_t networkValue = htonl(networkv4->sin_addr.s_addr);
      spindump_assert(network->length <= 32);
      uint32_t addressMask = v4prefixmasks[network->length];
      return((addressValue & addressMask) ==
	     (networkValue & addressMask));
    }
    
  case AF_INET6:
    {
      struct sockaddr_in6* addressv6 = (struct sockaddr_in6*)address;
      struct sockaddr_in6* networkv6 = (struct sockaddr_in6*)&network->address;
      uint8_t* addressValue = addressv6->sin6_addr.s6_addr;
      uint8_t* networkValue = networkv6->sin6_addr.s6_addr;
      spindump_assert(network->length <= 128);
      unsigned int bytes = network->length / 8;
      unsigned int remainingbits = network->length % 8;
      spindump_assert(remainingbits < 8);
      if (remainingbits > 0) bytes++;
      spindump_assert(bytes <= 16);
      unsigned int i;
      for (i = 0; i < bytes; i++) {
	uint8_t bytemask;
	if (i == bytes - 1) {
	  bytemask = (remainingbits == 0) ? 0xFF : v6prefixmasks[remainingbits];
	} else {
	  bytemask = 0xFF;
	}
	uint8_t addressbyte = addressValue[i] & bytemask;
	uint8_t networkbyte = networkValue[i] & bytemask;
	if (addressbyte != networkbyte) return(0);
      }
      return(1);
    }
    
  default:
    return(0);
  }
}

//
// Read an address from a string
// 

int
spindump_address_fromstring(spindump_address* address,
			    const char* string) {
  if (index(string,':')) {
    
    address->ss_family = AF_INET6;
    struct sockaddr_in6* actual = (struct sockaddr_in6*)address;
    if (inet_pton(address->ss_family, string, &actual->sin6_addr) == 1) {
      return(1);
    } else {
      spindump_warnf("invalid IPv6 address string: %s", string);
      return(0);
    }
    
  } else if (index(string,'.')) {
    
    address->ss_family = AF_INET;
    struct sockaddr_in* actual = (struct sockaddr_in*)address;
    if (inet_pton(address->ss_family, string, &actual->sin_addr) == 1) {
      return(1);
    } else {
      spindump_warnf("invalid IPv4 address string: %s", string);
      return(0);
    }
    
  } else {
    spindump_warnf("invalid address string: %s", string);
    return(0);
  }
}

//
// Read address from packet
// 

void
spindump_address_frombytes(spindump_address* address,
			   int af,
			   const unsigned char* string) {
  spindump_assert(address != 0);
  spindump_assert(af == AF_INET || af == AF_INET6);
  memset(address,0,sizeof(*address));
  address->ss_family = af;
  if (af == AF_INET) {
    struct sockaddr_in* actual = (struct sockaddr_in*)address;
    memcpy((unsigned char*)&actual->sin_addr.s_addr,
	   string,
	   4);
  } else {
    struct sockaddr_in6* actual = (struct sockaddr_in6*)address;
    memcpy((unsigned char*)&actual->sin6_addr.s6_addr,
	   string,
	   16);
  }
}

const char*
spindump_address_tostring(spindump_address* address) {
  spindump_assert(address != 0);
  spindump_assert(address->ss_family != 0);
  static char buf[100];
  memset(buf,0,sizeof(buf));
  switch (address->ss_family) {
  case AF_INET:
    {
      struct sockaddr_in* actual = (struct sockaddr_in*)address;
      inet_ntop(AF_INET,&actual->sin_addr,buf,sizeof(buf)-1);
    }
    break;
  case AF_INET6:
    {
      struct sockaddr_in6* actual = (struct sockaddr_in6*)address;
      inet_ntop(AF_INET6,&actual->sin6_addr,buf,sizeof(buf)-1);
    }
    break;
  default:
    spindump_errorf("invalid address family");
    strcpy(buf,"invalid");
  }
  return(buf);
}

//
// Map a set of bytes to an anonymized set of bytes
//

static void
spindump_anon_aux(unsigned long seed,
		  unsigned char* bytes,
		  unsigned int length) {
  while (length > 0) {

    *bytes = (*bytes ^ (unsigned char)seed);
    seed <<= 1;
    seed ^= (unsigned long)*bytes;
    bytes++;
    length--;
    
  }
}

//
// Anonymize an address and return it as a string
//

const char*
spindump_address_tostring_anon(int anonymize,
			       spindump_address* address) {

  //
  // Some checks
  //
  
  spindump_assert(spindump_isbool(anonymize));
  spindump_assert(address != 0);
  spindump_assert(address->ss_family != 0);

  //
  // Do we need to anynymize? If not, just skip to regular processing.
  //

  if (!anonymize) return(spindump_address_tostring(address));
  
  //
  // Hold an internal (undisclosed) variable that is initialized to a
  // random number.  Then use that random number to calculate a
  // mapping from real addresses to sha1 of the real address.
  //

  static unsigned long seed = 0;
  if (seed == 0) seed = rand();
  
  //
  // Map the input address to another address
  //
  
  spindump_address mapped = *address;
  switch (address->ss_family) {
  case AF_INET:
    {
      struct sockaddr_in* actual = (struct sockaddr_in*)&mapped;
      spindump_anon_aux(seed,(unsigned char*)&actual->sin_addr,4);
    }
    break;
  case AF_INET6:
    {
      struct sockaddr_in6* actual = (struct sockaddr_in6*)&mapped;
      spindump_anon_aux(seed,(unsigned char*)&actual->sin6_addr,16);
    }
    break;
  default:
    spindump_errorf("invalid address family");
    return("invalid");
  }

  //
  // Convert the mapped address to a string
  //
  
  return(spindump_address_tostring(&mapped));
}

//
// Read a network address and prefix length from a string
// 

int
spindump_network_fromstring(spindump_network* network,
			    const char* string) {
  const char* prefix = index(string,'/');
  if (prefix == 0) {
    spindump_warnf("invalid prefix slash format: %s", string);
    return(0);
  }
  if (!isdigit(prefix[1])) {
    spindump_warnf("invalid prefix number format: %s", string);
    return(0);
  }
  network->length = atoi(prefix+1);
  char* addressString = strdup(string);
  if (addressString == 0) {
    spindump_errorf("cannot allocate memory for string of %u bytes", strlen(string));
    return(0);
  }
  char* slashPlace = index(addressString,'/');
  spindump_assert(slashPlace != 0);
  *slashPlace = 0;
  int result = spindump_address_fromstring(&network->address,addressString);
  spindump_deepdebugf("freeing addressString");
  free(addressString);
  return(result);
}

const char*
spindump_network_tostring(spindump_network* network) {
  static char buf[100];
  memset(buf,0,sizeof(buf));
  snprintf(buf, sizeof(buf)-1, "%s/%u",
	   spindump_address_tostring(&network->address),
	   network->length);
  return(buf);
}

const char*
spindump_meganumber_tostring(unsigned long x) {
  static char buf[50];
  const char* u;
  const unsigned long thou = 1000;
  unsigned long f;
  memset(buf,0,sizeof(buf));
  if (x > thou * thou * thou) {
    u = "G";
    f = thou * thou * thou;
  } else if (x > thou * thou) {
    u = "M";
    f = thou * thou;
  } else if (x > thou) {
    u = "K";
    f = thou;
  } else {
    u = "";
    f = 1;
  }

  if (f == 1) {
    snprintf(buf,sizeof(buf)-1,"%lu",x);
  } else {
    snprintf(buf,sizeof(buf)-1,"%lu.%lu%s",(x / f), ((x % f) / (f / (unsigned long)10)), u);
  }
  return(buf);
}

const char*
spindump_meganumberll_tostring(unsigned long long x) {
  static char buf[100];
  const char* u;
  const unsigned long long thou = 1000;
  unsigned long long f;
  memset(buf,0,sizeof(buf));
  if (x > thou * thou * thou * thou) {
    u = "P";
    f = thou * thou * thou * thou;
  } else if (x > thou * thou * thou) {
    u = "G";
    f = thou * thou * thou;
  } else if (x > thou * thou) {
    u = "M";
    f = thou * thou;
  } else if (x > thou) {
    u = "K";
    f = thou;
  } else {
    u = "";
    f = 1;
  }
  if (f == 1) {
    snprintf(buf,sizeof(buf)-1,"%llu",x);
  } else {
    snprintf(buf,sizeof(buf)-1,"%llu.%llu%s",(x / f), ((x % f) / (f / (unsigned long long)10)), u);
  }
  return(buf);
}

//
// Set the destination stream for all error messages (fatal, error,
// warn)
//

void
spindump_seterrordestination(FILE* file) {
  errordestination = file;
}

//
// Display a fatal error
//

void
spindump_fatalf(const char* format, ...) {
  
  va_list args;
  
  spindump_assert(format != 0);

  if (errordestination == 0) errordestination = stderr;
  
  spindump_debugf("spindump: fatal error: %s", format);
  fprintf(errordestination,"spindump: fatal error: ");
  va_start (args, format);
  vfprintf(errordestination, format, args);
  va_end (args);
  fprintf(errordestination," -- exit\n");
  
  exit(1);
}

//
// Display a fatal error a la perror
//

void
spindump_fatalp(const char* message) {
  
  const char* string = strerror(errno);
  spindump_assert(message != 0);
  spindump_fatalf("system: %s - %s", message, string);
  
}

//
// Display an error
//

void
spindump_errorf(const char* format, ...) {
  
  va_list args;
  
  spindump_assert(format != 0);
  
  if (errordestination == 0) errordestination = stderr;
  
  spindump_debugf("spindump: error: %s", format);
  fprintf(errordestination,"spindump: error: ");
  va_start (args, format);
  vfprintf(errordestination, format, args);
  va_end (args);
  fprintf(errordestination," -- exit\n");
  
  exit(1);
}

//
// Display an error a la perror
//

void
spindump_errorp(const char* message) {
  
  const char* string = strerror(errno);
  spindump_assert(message != 0);
  spindump_errorf("system: %s - %s", message, string);
  
}

//
// Display a warning
//

void
spindump_warnf(const char* format, ...) {
  
  va_list args;
  
  spindump_assert(format != 0);

  if (errordestination == 0) errordestination = stderr;
  
  spindump_debugf("spindump: warning %s", format);
  fprintf(errordestination,"spindump: warning: ");
  va_start (args, format);
  vfprintf(errordestination, format, args);
  va_end (args);
  fprintf(errordestination,"\n");
}

//
// Debug helper function
//

void
spindump_setdebugdestination(FILE* file) {
  debugdestination = file;
}

void
spindump_debugf(const char* format, ...) {

  spindump_assert(format != 0);

  if (debug) {

    va_list args;

    if (debugdestination == 0) debugdestination = stderr;
  
    fprintf(debugdestination, "spindump: debug: ");
    va_start (args, format);
    vfprintf(debugdestination, format, args);
    va_end (args);
    fprintf(debugdestination, "\n");
    fflush(debugdestination);
    
  }
  
}

//
// Debug helper function
//

void
spindump_deepdebugf(const char* format, ...) {

  spindump_assert(format != 0);
  
  if (debug && deepdebug) {

    va_list args;

    if (debugdestination == 0) debugdestination = stderr;
    
    fprintf(debugdestination, "spindump: debug:   ");
    va_start (args, format);
    vfprintf(debugdestination,format, args);
    va_end (args);
    fprintf(debugdestination, "\n");
    fflush(debugdestination);
    
  }
  
}

