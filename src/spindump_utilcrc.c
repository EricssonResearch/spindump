
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

#include "spindump_util.h"

//
// Variables ----------------------------------------------------------------------------------
//

// Table of CRCs of all 8-bit messages. Taken from RFC 1952.
static unsigned long crc_table[256];

// Flag: has the table been computed? Initially false. Taken from RFC 1952.
static int crc_table_computed = 0;

// 32 lowest bits of CRC-32c (Castagnoli93) generator polynomial.
static const uint32_t spindump_crc32c_poly = 0x1edc6f41UL;

static uint32_t spindump_crc32c_table[256];
static int spindump_crc32c_setup_done;

//
// Function prototypes ------------------------------------------------------------------------
//

static void spindump_crc_maketable(void);

//
// Actual code --------------------------------------------------------------------------------
//

//
// Make the table for a fast CRC. Taken from RFC 1952.
//

static void
spindump_crc_maketable(void) {
  unsigned long c;
  
  int n, k;
  for (n = 0; n < 256; n++) {
    c = (unsigned long) n;
    for (k = 0; k < 8; k++) {
      if (c & 1) {
        c = 0xedb88320L ^ (c >> 1);
      } else {
        c = c >> 1;
      }
    }
    crc_table[n] = c;
  }
  crc_table_computed = 1;
}

//
// Update a running crc with the bytes buf[0..len-1] and return
// the updated crc. The crc should be initialized to zero. Pre- and
// post-conditioning (one's complement) is performed within this
// function so it shouldn't be done by the caller. Usage example:
//
//     unsigned long crc = 0L;
//
//     while (read_buffer(buffer, length) != EOF) {
//       crc = spindump_crc_update(crc, buffer, length);
//     }
//     if (crc != original_crc) error();
//
// Code taken from RFC 1952.
//

unsigned long
spindump_crc_update(unsigned long crc,
                    const unsigned char *buf,
                    size_t len) {
  
  unsigned long c = crc ^ 0xffffffffL;
  
  if (!crc_table_computed) {
    spindump_crc_maketable();
  }
  
  for (unsigned int n = 0; n < len; n++) {
    c = crc_table[(c ^ buf[n]) & 0xff] ^ (c >> 8);
  }
  
  return(c ^ 0xffffffffL);
}

//
// Return the CRC of the bytes buf[0..len-1]. Code taken from RFC 1952.
//

unsigned long
spindump_crc(const unsigned char *buf,
             size_t len) {
  return(spindump_crc_update(0L, buf, len));
}

//
// CRC-32c calculation.
//

static inline unsigned char
spindump_crc32c_bitrev8(unsigned char byte)
{
  unsigned char rev;

  rev = (byte >> 4 & 0x0f) | (byte << 4 & 0xf0);
  rev = (rev >> 2 & 0x33) | (rev << 2 & 0xcc);
  rev = (rev >> 1 & 0x55) | (rev << 1 & 0xaa);
  return rev;
}

static inline uint32_t
spindump_crc32c_bitrev32(uint32_t quad)
{
  uint32_t rev;

  rev = (quad >> 4 & 0x0f0f0f0f) | (quad << 4 & 0xf0f0f0f0);
  rev = (rev >> 2 & 0x33333333) | (rev << 2 & 0xcccccccc);
  rev = (rev >> 1 & 0x55555555) | (rev << 1 & 0xaaaaaaaa);
  return rev;
}

static void
spindump_crc32c_setup(void)
{
  uint32_t rem;
  unsigned i, j;

  for (i = 0; i < 256; i++) {
    rem = (uint32_t)i << 24;
    for (j = 0; j < 8; j++) {
      if ((rem & 0x80000000))
        rem = (rem << 1) ^ spindump_crc32c_poly;
      else
        rem = (rem << 1);
    }
    unsigned char idx = spindump_crc32c_bitrev8((unsigned char)i);
    spindump_crc32c_table[idx] = spindump_crc32c_bitrev32(rem);
  }
}

uint32_t
spindump_crc32c_init(void)
{
  if (!spindump_crc32c_setup_done) {
    spindump_crc32c_setup_done = 1;
    spindump_crc32c_setup();
  }
  return 0xffffffff;
}

uint32_t
spindump_crc32c_update(uint32_t digest, unsigned char* buf, size_t len)
{
  unsigned int i;
  uint32_t newdig = digest;
  unsigned char byte;

  for (i = 0; i < len; i++) {
    byte = (newdig >> 24) ^ buf[i];
    newdig = (newdig << 8) ^ spindump_crc32c_table[byte];
  }
  return newdig;
}

uint32_t
spindump_crc32c_finish(uint32_t digest)
{
  return ~digest;
}
