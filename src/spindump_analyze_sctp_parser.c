
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
//  SPINDUMP (C) 2019 BY ERICSSON AB
//  AUTHOR: DENIS SCHERBAKOV, MAKSIM PROSHIN
//
// 

//
// Includes -----------------------------------------------------------------------------------
//

#include "spindump_util.h"
#include "spindump_protocols.h"
#include "spindump_analyze_sctp_parser.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static void
spindump_protocols_sctp_chunk_init_parse(const unsigned char* packet,
                                         struct spindump_sctp_chunk* decoded);

static void
spindump_protocols_sctp_chunk_init_ack_parse(const unsigned char* packet,
                                             struct spindump_sctp_chunk* decoded);

static void
spindump_protocols_sctp_chunk_data_parse(const unsigned char* packet,
                                         struct spindump_sctp_chunk* decoded);

static void
spindump_protocols_sctp_chunk_sack_parse(const unsigned char* packet,
                                        struct spindump_sctp_chunk* decoded);

static unsigned int
spindump_protocols_sctp_chunk_value_parse(const unsigned char* packet,
                                          struct spindump_sctp_chunk* decoded,
                                          unsigned int remainingLen);
#if 0
static void
spindump_protocols_sctp_chunk_header_parse(const unsigned char* packet,
                                           struct spindump_sctp_chunk* decoded);
#endif

//
// Actual code --------------------------------------------------------------------------------
//

//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |   Type = 1    |  Chunk Flags  |      Chunk Length             |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//

#if 0
static void
spindump_protocols_sctp_chunk_header_parse(const unsigned char* packet,
                                           struct spindump_sctp_chunk* decoded) {

  unsigned int pos = 0;
  spindump_decodebyte(decoded->ch_type,packet,pos);
  spindump_decodebyte(decoded->ch_flags,packet,pos);
  spindump_decode2byteint(decoded->ch_length,packet,pos);
}
#endif

//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |   Type = 1    |  Chunk Flags  |      Chunk Length             |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                         Initiate Tag                          |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |           Advertised Receiver Window Credit (a_rwnd)          |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |  Number of Outbound Streams   |  Number of Inbound Streams    |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                          Initial TSN                          |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                                                               |
//  |              Optional/Variable-Length Parameters              |
//  |                                                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Note, packet must point to chunk value
//

static void
spindump_protocols_sctp_chunk_init_parse(const unsigned char* packet,
                                     struct spindump_sctp_chunk* decoded) {
  
  unsigned int pos = 0;
  spindump_decode4byteint(decoded->ch.init.initiateTag,packet,pos);          // Initiate Tag
  spindump_decode4byteint(decoded->ch.init.arwnd,packet,pos);                // Advertised Receiver Window
  spindump_decode2byteint(decoded->ch.init.outStreams,packet,pos);           // Num of Outbound Streams
  spindump_decode2byteint(decoded->ch.init.inStreams,packet,pos);            // Num of Inbound Streams
  spindump_decode4byteint(decoded->ch.init.initTsn,packet,pos);              // Initial TSN
}

//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |   Type = 2    |  Chunk Flags  |      Chunk Length             |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                         Initiate Tag                          |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |              Advertised Receiver Window Credit                |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |  Number of Outbound Streams   |  Number of Inbound Streams    |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                          Initial TSN                          |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                                                               |
//  |              Optional/Variable-Length Parameters              |
//  |                                                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Note, packet must point to chunk value
//

static void
spindump_protocols_sctp_chunk_init_ack_parse(const unsigned char* packet,
                                             struct spindump_sctp_chunk* decoded) {

  unsigned int pos = 0;
  spindump_decode4byteint(decoded->ch.init_ack.initiateTag,packet,pos);          // Initiate Tag
  spindump_decode4byteint(decoded->ch.init_ack.arwnd,packet,pos);                // Advertised Receiver Window
  spindump_decode2byteint(decoded->ch.init_ack.outStreams,packet,pos);           // Num of Outbound Streams
  spindump_decode2byteint(decoded->ch.init_ack.inStreams,packet,pos);            // Num of Inbound Streams
  spindump_decode4byteint(decoded->ch.init_ack.initTsn,packet,pos);              // Initial TSN
}

//
// DATA chunk from RFC 4960:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |   Type = 0    | Reserved|U|B|E|    Length                     |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                              TSN                              |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |      Stream Identifier S      |   Stream Sequence Number n    |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                  Payload Protocol Identifier                  |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                                                               |
//  |                 User Data (seq n of Stream S)                 |
//  |                                                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//

static void
spindump_protocols_sctp_chunk_data_parse(const unsigned char* packet,
                                     struct spindump_sctp_chunk* decoded) {

  unsigned int pos = 0;
  spindump_decode4byteint(decoded->ch.data.tsn,packet,pos);                // TSN
  spindump_decode2byteint(decoded->ch.data.streamId,packet,pos);           // Stream ID
  spindump_decode2byteint(decoded->ch.data.streamSn,packet,pos);           // Stream Seq Number
  spindump_decode4byteint(decoded->ch.data.payloadProtoId,packet,pos);     // Payload Protocol Id
}

//
// SACK chunk from RFC 4960:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |   Type = 3    |Chunk  Flags   |      Chunk Length             |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                      Cumulative TSN Ack                       |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |          Advertised Receiver Window Credit (a_rwnd)           |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  | Number of Gap Ack Blocks = N  |  Number of Duplicate TSNs = X |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |  Gap Ack Block #1 Start       |   Gap Ack Block #1 End        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                                                               |
//  |                              ...                              |
//  |                                                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |   Gap Ack Block #N Start      |  Gap Ack Block #N End         |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                       Duplicate TSN 1                         |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                                                               |
//  |                              ...                              |
//  |                                                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                       Duplicate TSN X                         |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//

static void
spindump_protocols_sctp_chunk_sack_parse(const unsigned char* packet,
                                     struct spindump_sctp_chunk* decoded) {

  unsigned int pos = 0;
  spindump_decode4byteint(decoded->ch.sack.cumulativeTsnAck,packet,pos);  // Cumulative TSN Ack
  spindump_decode4byteint(decoded->ch.sack.arwnd,packet,pos);             // arwnd
  spindump_decode2byteint(decoded->ch.sack.nGapAckBlock,packet,pos);      // Number of Gap Ack blocks
  spindump_decode2byteint(decoded->ch.sack.nDupTsn,packet,pos);           // Number of Duplicate TSNs
}

static unsigned int
spindump_protocols_sctp_chunk_value_parse(const unsigned char* packet,
                                          struct spindump_sctp_chunk* decoded,
                                          unsigned int remainingLen) {

  switch (decoded->ch_type) {

    case spindump_sctp_chunk_type_init:
      if (remainingLen >= spindump_sctp_chunk_init_parse_length) {
        spindump_protocols_sctp_chunk_init_parse(packet, decoded);
        return spindump_sctp_parse_ok;
      } else {
        return spindump_sctp_parse_error;
      }

    case spindump_sctp_chunk_type_init_ack:
      if (remainingLen >= spindump_sctp_chunk_initack_parse_length) {
        spindump_protocols_sctp_chunk_init_ack_parse(packet, decoded);
        return spindump_sctp_parse_ok;
      } else {
        return spindump_sctp_parse_error;
      }

    case spindump_sctp_chunk_type_data:
      if (remainingLen >= spindump_sctp_chunk_data_parse_length) {
        spindump_protocols_sctp_chunk_data_parse(packet, decoded);
        return spindump_sctp_parse_ok;
      } else {
        return spindump_sctp_parse_error;
      }

    case spindump_sctp_chunk_type_sack:
      if (remainingLen >= spindump_sctp_chunk_sack_parse_length) {
        spindump_protocols_sctp_chunk_sack_parse(packet, decoded);
        return spindump_sctp_parse_ok;
      } else {
        return spindump_sctp_parse_error;
      }
      
    case spindump_sctp_chunk_type_cookie_echo:
    case spindump_sctp_chunk_type_cookie_ack:
    case spindump_sctp_chunk_type_shutdown:
    case spindump_sctp_chunk_type_shutdown_complete:
    case spindump_sctp_chunk_type_shutdown_ack:
    case spindump_sctp_chunk_type_abort:
    case spindump_sctp_chunk_type_heartbeat:
    case spindump_sctp_chunk_type_heartbeat_ack:
      return spindump_sctp_parse_ok;

    default:
      spindump_deepdeepdebugf("Unknown chunk received: %d", decoded->ch_type);
      return spindump_sctp_parse_error;
      
  }
}

unsigned int
spindump_protocols_sctp_chunk_parse(const unsigned char* packet,
                                    struct spindump_sctp_chunk* decoded,
                                    unsigned int remainingLen) {

  unsigned int result;
  unsigned int pos = 0;
  unsigned int remLen = remainingLen;

  if ( remLen < spindump_sctp_chunk_header_length ) return spindump_sctp_parse_error;

  spindump_decodebyte(decoded->ch_type,packet,pos);
  spindump_decodebyte(decoded->ch_flags,packet,pos);
  spindump_decode2byteint(decoded->ch_length,packet,pos);
  remLen -= spindump_sctp_chunk_header_length;

  result = spindump_protocols_sctp_chunk_value_parse(packet + spindump_sctp_chunk_header_length,
                                                    decoded,
                                                    remLen);

  return result;

}
