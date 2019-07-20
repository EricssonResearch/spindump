
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
//  AUTHOR: JARI ARKKO AND MARCUS IHLAR AND SZILVESZTER NADAS
//
// 

//
// Includes -----------------------------------------------------------------------------------
//

#include <stdlib.h>
#include <string.h>
#include "spindump_util.h"
#include "spindump_connections.h"
#include "spindump_analyze.h"
#include "spindump_analyze_quic.h"
#include "spindump_analyze_quic_parser.h"
#include "spindump_analyze_quic_parser_util.h"

//
// Function prototypes ------------------------------------------------------------------------
//

//
// Actual code --------------------------------------------------------------------------------
//

//
// Determine the length of a QUIC Connection ID based on the nibble
// that describes its length. The QUIC specification says that 0 maps
// to zero 0 length, but for all other lengths the value is the nibble
// value + 3.
//

unsigned int
spindump_analyze_quic_parser_util_onecidlength(uint8_t value) {
  spindump_assert(value < 16);
  if (value == 0) {
    return(0);
  } else {
    return(value + 3);
  }
}

//
// Helper function to parse Connection IDs from a QUIC long-form message.
//

void
spindump_analyze_quic_parser_util_cidlengths(uint8_t lengthsbyte,
                                             unsigned int* p_destinationLength,
                                             unsigned int* p_sourceLength) {
  *p_destinationLength = spindump_analyze_quic_parser_util_onecidlength(lengthsbyte >> 4);
  *p_sourceLength = spindump_analyze_quic_parser_util_onecidlength(lengthsbyte & 0x0F);
  spindump_deepdebugf("CID lengths destination = %u, source = %u",
                      *p_destinationLength,
                      *p_sourceLength);
}

int
spindump_analyze_quic_parser_util_parseint(const unsigned char* buffer,
                                           unsigned int bufferLength,
                                           unsigned int bufferRemainingCaplen,
                                           unsigned int* integerLength,
                                           uint64_t* integer) {

  //
  // Sanity checks
  //
  
  spindump_assert(buffer != 0);
  spindump_assert(integerLength != 0);
  spindump_assert(integer != 0);

  //
  // Initialize output values
  //

  *integerLength = 0;
  
  //
  // Check we have enough space left
  //
  
  if (bufferLength < 1 || bufferRemainingCaplen < 1) {
    return(0);
  }

  //
  // From the specification:
  //
  //    The QUIC variable-length integer encoding reserves the two
  //    most significant bits of the first byte to encode the base 2
  //    logarithm of the integer encoding length in bytes.  The
  //    integer value is encoded on the remaining bits, in network
  //    byte order.
  //
  //    This means that integers are encoded on 1, 2, 4, or 8 bytes
  //    and can encode 6, 14, 30, or 62 bit values respectively.
  //    Table 4 summarizes the encoding properties.
  //
  //        +------+--------+-------------+-----------------------+
  //        | 2Bit | Length | Usable Bits | Range                 |
  //        +------+--------+-------------+-----------------------+
  //        | 00   | 1      | 6           | 0-63                  |
  //        |      |        |             |                       |
  //        | 01   | 2      | 14          | 0-16383               |
  //        |      |        |             |                       |
  //        | 10   | 4      | 30          | 0-1073741823          |
  //        |      |        |             |                       |
  //        | 11   | 8      | 62          | 0-4611686018427387903 |
  //        +------+--------+-------------+-----------------------+
  //
  //                 Table 4: Summary of Integer Encodings
  //

  *integer = (uint64_t)((buffer[0]) & 0x3f);
  switch (((*buffer)>>6) & 0x03) {
  case 0x00:
    *integerLength = 1;
    return(1);
  case 0x01:
    *integerLength = 2;
    if (bufferLength < *integerLength || bufferRemainingCaplen < *integerLength) {
      *integerLength = 0;
      *integer = 0;
      return(0);
    }
    (*integer) <<= 8;
    *integer += (uint64_t)(buffer[1]);
    return(1);
  case 0x02:
    *integerLength = 4;
    if (bufferLength < *integerLength || bufferRemainingCaplen < *integerLength) {
      *integerLength = 0;
      *integer = 0;
      return(0);
    }
    (*integer) <<= 8;
    *integer += (uint64_t)(buffer[1]);
    (*integer) <<= 8;
    *integer += (uint64_t)(buffer[2]);
    (*integer) <<= 8;
    *integer += (uint64_t)(buffer[3]);
    return(1);
  case 0x03:
    *integerLength = 8;
    if (bufferLength < *integerLength || bufferRemainingCaplen < *integerLength) {
      *integerLength = 0;
      *integer = 0;
      return(0);
    }
    (*integer) <<= 8;
    *integer += (uint64_t)(buffer[1]);
    (*integer) <<= 8;
    *integer += (uint64_t)(buffer[2]);
    (*integer) <<= 8;
    *integer += (uint64_t)(buffer[3]);
    (*integer) <<= 8;
    *integer += (uint64_t)(buffer[4]);
    (*integer) <<= 8;
    *integer += (uint64_t)(buffer[5]);
    (*integer) <<= 8;
    *integer += (uint64_t)(buffer[6]);
    (*integer) <<= 8;
    *integer += (uint64_t)(buffer[7]);
    return(1);
  default:
    spindump_errorf("should not happen");
    return(0);
  }
}

#ifdef SPINDUMP_DEBUG

//
// Return a string describing a particular QUIC message
//

const char*
spindump_analyze_quic_parser_util_typetostring(enum spindump_quic_message_type type) {
  switch (type) {
  case spindump_quic_message_type_data: return("data");
  case spindump_quic_message_type_initial: return("initial");
  case spindump_quic_message_type_versionnegotiation: return("version negotiation");
  case spindump_quic_message_type_handshake: return("handshake");
  case spindump_quic_message_type_0rtt: return("0rtt");
  case spindump_quic_message_type_retry: return("retry");
  case spindump_quic_message_type_other: return("other");
  default:
    spindump_errorf("invalid QUIC message type %u", type);
    return("invalid");
  }
}

#endif // SPINDUMP_DEBUG

//
// Compare two QUIC Connection IDs. Return 1 if they are equal (same
// length, same content).
//

int
spindump_analyze_quic_quicidequal(struct spindump_quic_connectionid* id1,
                                  struct spindump_quic_connectionid* id2) {
  spindump_assert(id1 != 0);
  spindump_assert(id2 != 0);
  return(id1->len == id2->len &&
         memcmp(id1->id,id2->id,id2->len) == 0);
}

//
// Compare two QUIC Connection IDs. Return 1 if they are equal (same
// length, same content), but allow the first identifier to be of
// unknown length. So if all the bytes of the second identifier match
// the byte string in the first, we're return 1. This means that a
// zero-length identifier will match anything.
//

int
spindump_analyze_quic_partialquicidequal(const unsigned char* id1,
                                        struct spindump_quic_connectionid* id2) {
  spindump_assert(id1 != 0);
  spindump_assert(id2 != 0);
  return(memcmp(id1,id2->id,id2->len) == 0);
}
