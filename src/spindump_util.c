
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
      spindump_errorf("spindump_timediffinusec: expected later time to be greater, secs both %lus, microsecond go back %luus (%lu to %lu)",
                      earlier->tv_sec,
                      earlier->tv_usec - later->tv_usec,
                      earlier->tv_usec, later->tv_usec);
      return(0);
    } else {
      return(((unsigned long long)later->tv_usec) - ((unsigned long long)earlier->tv_usec));
    }
  } else {
    unsigned long long result = 1000 * 1000 * (((unsigned long long)later->tv_sec) -
                                               ((unsigned long long)earlier->tv_sec) -
                                               1);
    result += ((unsigned long long)(1000*1000)) - (unsigned long long)earlier->tv_usec;
    result += (unsigned long long)later->tv_usec;
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
  
  if (earlier->tv_sec < later->tv_sec) {
    return(1);
  } else if (earlier->tv_sec == later->tv_sec &&
             earlier->tv_usec < later->tv_usec) {
    return(1);
  } else {
    return(0);
  }
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
spindump_timetostring(const struct timeval* input,
                      char* output,
                      size_t outputLength) {
  spindump_assert(input != 0);
  spindump_assert(output != 0);
  spindump_assert(outputLength > 0);
  struct tm t;
  localtime_r(&input->tv_sec,&t);
  memset(output,0,outputLength);
  snprintf(output,outputLength - 1,"%02lu:%02lu:%02lu.%06lu",
           (unsigned long)t.tm_hour,
           (unsigned long)t.tm_min,
           (unsigned long)t.tm_sec,
           (unsigned long)input->tv_usec);
  return(output);
}

//
// Convert timeval (struct) to a timestamp (nr. useconds from 1970 Jan
// 1).
//

void
spindump_timeval_to_timestamp(const struct timeval* timev,
                              unsigned long long* timestamp) {
  spindump_assert(timev != 0);
  spindump_assert(timestamp != 0);
  *timestamp = (unsigned long long)(timev->tv_usec);
  *timestamp += 1000 * 1000 * (unsigned long long)(timev->tv_sec);
}

//
// Convert a timestamp (nr. useconds from 1970 Jan 1) to a timeval
// (struct).
//

void
spindump_timestamp_to_timeval(const unsigned long long timestamp,
                              struct timeval* timev) {
  spindump_deepdeepdebugf("spindump_timestamp_to_timeval %llu",
                          timestamp);
  spindump_assert(timestamp != 0);
  spindump_assert(timev != 0);
  timev->tv_sec = timestamp / (1000*1000);
  timev->tv_usec = timestamp % (1000*1000);
}

//
// Address comparison
//

int
spindump_address_equal(const spindump_address* address1,
                       const spindump_address* address2) {
  
  if (address1->ss_family != address2->ss_family) return(0);
  
  switch (address1->ss_family) {
    
  case AF_INET:
    {
      const struct sockaddr_in* address1v4 = (const struct sockaddr_in*)address1;
      const struct sockaddr_in* address2v4 = (const struct sockaddr_in*)address2;
      return(address1v4->sin_addr.s_addr == address2v4->sin_addr.s_addr);
    }
    
  case AF_INET6:
    {
      const struct sockaddr_in6* address1v6 = (const struct sockaddr_in6*)address1;
      const struct sockaddr_in6* address2v6 = (const struct sockaddr_in6*)address2;
      return(memcmp(address1v6->sin6_addr.s6_addr,address2v6->sin6_addr.s6_addr,16) == 0);
    }
    
  default:
    return(0);
  }
}

//
// How many bits is this address? Possible answers are 32 and 128
// (unless there is an internal error, which should not happen).
//

unsigned int
spindump_address_length(const spindump_address* address) {
  switch (address->ss_family) {
    
  case AF_INET: return(32);
  case AF_INET6: return(128);
  default:
    spindump_errorf("invalid address family");
    return(0);
  }
}

//
// Multicast address check
//
// Note: This function is not thread safe.
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
      struct sockaddr_in addressv4;
      struct sockaddr_in maskv4;
      memcpy((unsigned char*)&addressv4,(unsigned char*)(thisInterface->ifa_addr),sizeof(addressv4));
      memcpy((unsigned char*)&maskv4,(unsigned char*)(thisInterface->ifa_netmask),sizeof(maskv4));
      uint32_t thisBroadcast =
        (addressv4.sin_addr.s_addr & maskv4.sin_addr.s_addr) |
        (~(maskv4.sin_addr.s_addr));
      spindump_deepdebugf("address %08x netmask %08x broadcast %08x compare to %08x\n",
                          addressv4.sin_addr.s_addr,
                          maskv4.sin_addr.s_addr,
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

//
// Check whether the network represents a host network (i.e., a /32 or
// /128).
//

int
spindump_network_ishost(const spindump_network* network) {
  if (network->address.ss_family == AF_INET && network->length == 32) {
    return(1);
  } else if (network->address.ss_family == AF_INET6 && network->length == 128) {
    return(1);
  } else {
    return(0);
  }
}

//
// Check whether the given address is a multicast address
//

int
spindump_address_ismulticast(const spindump_address* address) {

  switch (address->ss_family) {

  case AF_INET:

    //
    // IPv4 per https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml
    //
    
    {
      const struct sockaddr_in* addressv4 = (const struct sockaddr_in*)address;
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
      const struct sockaddr_in6* addressv6 = (const struct sockaddr_in6*)address;
      const uint8_t* addressValue = addressv6->sin6_addr.s6_addr;
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
spindump_network_equal(const spindump_network* network1,
                       const spindump_network* network2) {
  return(network1->length == network2->length &&
         spindump_address_equal(&network1->address,
                                &network2->address));
}

//
// Checking if a network is multicast network
//

int
spindump_network_ismulticast(const spindump_network* network) {
  return(network->length >= 8 &&
         spindump_address_ismulticast(&network->address));
}

//
// Address comparison to a network prefix
//

int
spindump_address_innetwork(const spindump_address* address,
                           const spindump_network* network) {

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
      const struct sockaddr_in* addressv4 = (const struct sockaddr_in*)address;
      const struct sockaddr_in* networkv4 = (const struct sockaddr_in*)&network->address;
      uint32_t addressValue = htonl(addressv4->sin_addr.s_addr);
      uint32_t networkValue = htonl(networkv4->sin_addr.s_addr);
      spindump_assert(network->length <= 32);
      uint32_t addressMask = v4prefixmasks[network->length];
      return((addressValue & addressMask) ==
             (networkValue & addressMask));
    }
    
  case AF_INET6:
    {
      const struct sockaddr_in6* addressv6 = (const struct sockaddr_in6*)address;
      const struct sockaddr_in6* networkv6 = (const struct sockaddr_in6*)&network->address;
      const uint8_t* addressValue = addressv6->sin6_addr.s6_addr;
      const uint8_t* networkValue = networkv6->sin6_addr.s6_addr;
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
// Initialize an address as empty (0.0.0.0 or ::)
//

void
spindump_address_fromempty(sa_family_t af,
                           spindump_address* address) {
  memset(address,0,sizeof(*address));
  address->ss_family = af;
}

//
// Read address from packet
// 

void
spindump_address_frombytes(spindump_address* address,
                           sa_family_t af,
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

//
// Convert an address to a string. Returned string need not be freed,
// but will not survive the next call to this same function.
//
// Note: This function is not thread safe.
//

const char*
spindump_address_tostring(const spindump_address* address) {
  spindump_assert(address != 0);
  spindump_assert(address->ss_family != 0);
  static char buf[100];
  memset(buf,0,sizeof(buf));
  switch (address->ss_family) {
  case AF_INET:
    {
      const struct sockaddr_in* actual = (const struct sockaddr_in*)address;
      inet_ntop(AF_INET,&actual->sin_addr,buf,sizeof(buf)-1);
    }
    break;
  case AF_INET6:
    {
      const struct sockaddr_in6* actual = (const struct sockaddr_in6*)address;
      inet_ntop(AF_INET6,&actual->sin6_addr,buf,sizeof(buf)-1);
    }
    break;
  default:
    spindump_errorf("invalid address family");
    spindump_strlcpy(buf,"invalid",sizeof(buf));
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
// Note: This function is not thread safe.
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
  if (seed == 0) seed = (unsigned long)rand();
  
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
  network->length = (unsigned int)atoi(prefix+1);
  if (network->length > 128) {
    spindump_errorf("network length must be at most 32 or 128 bits, %us given", network->length);
    return(0);
  }
  char* addressString = spindump_strdup(string);
  if (addressString == 0) {
    spindump_errorf("cannot allocate memory for string of %lu bytes", strlen(string));
    return(0);
  }
  char* slashPlace = index(addressString,'/');
  spindump_assert(slashPlace != 0);
  *slashPlace = 0;
  int result = spindump_address_fromstring(&network->address,addressString);
  spindump_deepdebugf("freeing addressString");
  spindump_free(addressString);
  return(result);
}

//
// Convert a network (e.g., "1.2.3.0/24") to a string. Returned string
// need not be freed, but will not survive the next call to this same
// function.
//
// Note: This function is not thread safe.
//

const char*
spindump_network_tostring(const  spindump_network* network) {
  static char buf[100];
  memset(buf,0,sizeof(buf));
  snprintf(buf, sizeof(buf)-1, "%s/%u",
           spindump_address_tostring(&network->address),
           network->length);
  return(buf);
}

//
// Print a network to a string, or, if it is a host, just an
// address string
//

const char*
spindump_network_tostringoraddr(const spindump_network* network) {
  if (network->address.ss_family == AF_INET && network->length == 32) {
    return(spindump_address_tostring(&network->address));
  } else if (network->address.ss_family == AF_INET6 && network->length == 128) {
    return(spindump_address_tostring(&network->address));
  } else {
    return(spindump_network_tostring(network));
  }
}

//
// Read a network from a string that is either in the slash (/) format
// with a prefix length, or just an address.
//

int
spindump_network_fromstringoraddr(spindump_network* network,
                                  const char* string) {
  if (index(string,'/') == 0) {
    if (!spindump_address_fromstring(&network->address,string)) {
      return(0);
    } else if (network->address.ss_family == AF_INET6) {
      network->length = 128;
      return(1);
    } else if (network->address.ss_family == AF_INET) {
      network->length = 32;
      return(1);
    } else {
      return(0);
    }
  } else {
    return(spindump_network_fromstring(network,string));
  }
}

//
// Create a network based on an address, i.e., a.b.c.d/32 or
// foo::bar/128.
//

void
spindump_network_fromaddress(const spindump_address* address,
                             spindump_network* network) {
  spindump_assert(address != 0);
  spindump_assert(network != 0);
  network->address = *address;
  network->length = spindump_address_length(address);
}

//
// Create an empty network (0.0.0.0/0 or ::/0)
//

void
spindump_network_fromempty(sa_family_t af,
                           spindump_network* network) {
  spindump_address_fromempty(af,&network->address);
  network->length = 0;
}

//
// Convert a large number to a string, e.g., 1000000 would become
// "1M".
//
// Note: This function is not thread safe.
//

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

//
// Convert a large number to a string, e.g., 1000000 would become
// "1M". The input is a "long long".
//
// Note: This function is not thread safe.
//

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
// A copy of the BSD strlcpy function. As for Linux, as it does not exist
// there without extra installations.
//

size_t
spindump_strlcpy(char * restrict dst, const char * restrict src, size_t size) {
  spindump_assert(dst != 0);
  spindump_assert(src != 0);
  spindump_assert(size > 1);
  strncpy(dst,src,size-1);
  dst[size-1] = 0;
  return(strlen(dst));
}

//
// A copy of the BSD strlcat function. As for Linux, as it does not exist
// there without extra installations.
//

size_t
spindump_strlcat(char * restrict dst, const char * restrict src, size_t size) {
  spindump_assert(dst != 0);
  spindump_assert(src != 0);
  spindump_assert(size > 1);
  size_t sizeSofar = strlen(dst);
  spindump_assert(sizeSofar < size);
  size_t sizeRemains = size - sizeSofar;
  strncat(dst + sizeSofar,src,sizeRemains-1);
  dst[size-1] = 0;
  return(strlen(src));
}

