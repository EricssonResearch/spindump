
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

//
// Actual code --------------------------------------------------------------------------------
//

//
// Chunk Field from RFC 4960:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |   Chunk Type  | Chunk  Flags  |        Chunk Length           |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                                                               |
//  |                          Chunk Value                          |
//  |                                                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// TODO: Maksim Proshin: add checks on params length
void
spindump_protocols_sctp_chunk_header_parse(const unsigned char* header,
                                     struct spindump_sctp_chunk_header* decoded){
  unsigned int pos = 0;
  spindump_decodebyte(decoded->ch_type,header,pos);
  spindump_decodebyte(decoded->ch_flags,header,pos);
  spindump_decode2byteint(decoded->ch_length,header,pos);
}

// TODO: Maksim Proshin: add INIT chunk description and function description
// TODO: Maksim Proshin: add checks on params length
void
spindump_protocols_sctp_chunk_init_parse(const unsigned char* header,
                                     struct spindump_sctp_chunk_init* decoded){
  unsigned int pos = 0;
  spindump_decodebyte(decoded->header.ch_type,header,pos);           // Chunk Type
  spindump_decodebyte(decoded->header.ch_flags,header,pos);          // Chunk Flags
  spindump_decode2byteint(decoded->header.ch_length,header,pos);     // Chunk Length
  spindump_decode4byteint(decoded->initiateTag,header,pos);          // Initiate Tag
  spindump_decode4byteint(decoded->arwnd,header,pos);                // Advertised Receiver Window
  spindump_decode2byteint(decoded->outStreams,header,pos);           // Num of Outbound Streams
  spindump_decode2byteint(decoded->inStreams,header,pos);            // Num of Inbound Streams
  spindump_decode4byteint(decoded->initTsn,header,pos);              // Initial TSN
}

// TODO: Maksim Proshin: add INIT ACK chunk description and function description
// TODO: Maksim Proshin: add checks on params length
void
spindump_protocols_sctp_chunk_init_ack_parse(const unsigned char* header,
                                     struct spindump_sctp_chunk_init_ack* decoded){
  unsigned int pos = 0;
  spindump_decodebyte(decoded->header.ch_type,header,pos);           // Chunk Type
  spindump_decodebyte(decoded->header.ch_flags,header,pos);          // Chunk Flags
  spindump_decode2byteint(decoded->header.ch_length,header,pos);     // Chunk Length
  spindump_decode4byteint(decoded->initiateTag,header,pos);          // Initiate Tag
  spindump_decode4byteint(decoded->arwnd,header,pos);                // Advertised Receiver Window
  spindump_decode2byteint(decoded->outStreams,header,pos);           // Num of Outbound Streams
  spindump_decode2byteint(decoded->inStreams,header,pos);            // Num of Inbound Streams
  spindump_decode4byteint(decoded->initTsn,header,pos);              // Initial TSN
}
