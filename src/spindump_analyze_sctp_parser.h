
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

#ifndef SPINDUMP_ANALYZE_SCTP_PARSER_H
#define SPINDUMP_ANALYZE_SCTP_PARSER_H

//
// Includes -----------------------------------------------------------------------------------
//

//
// Convenient macros --------------------------------------------------------------------------
//

//
// Parameters ---------------------------------------------------------------------------------
//

#define spindump_sctp_chunk_type_data               0 // 0x00
#define spindump_sctp_chunk_type_init               1 // 0x01
#define spindump_sctp_chunk_type_init_ack           2 // 0x02
#define spindump_sctp_chunk_type_sack               3 // 0x03
#define spindump_sctp_chunk_type_heartbeat          4 // 0x04
#define spindump_sctp_chunk_type_heartbeat_ack      5 // 0x05
#define spindump_sctp_chunk_type_abort              6 // 0x06
#define spindump_sctp_chunk_type_shutdown           7 // 0x07
#define spindump_sctp_chunk_type_shutdown_ack       8 // 0x08
#define spindump_sctp_chunk_type_error              9 // 0x09
#define spindump_sctp_chunk_type_cookie_echo        10 // 0x0A
#define spindump_sctp_chunk_type_cookie_ack         11 // 0x0B
#define spindump_sctp_chunk_type_ecne               12 // 0x0C
#define spindump_sctp_chunk_type_cwr                13 // 0x0D
#define spindump_sctp_chunk_type_shutdown_complete  14 // 0x0E
#define spindump_sctp_chunk_type_auth               15 // 0x0F

#define spindump_sctp_chunk_header_length     (1+1+2)

// set max required amount of bytes to parse from chunk
#define spindump_sctp_chunk_init_parse_length       (4+4+2+2+4)
#define spindump_sctp_chunk_initack_parse_length    (4+4+2+2+4)
#define spindump_sctp_chunk_data_parse_length       (4+2+2+4)
#define spindump_sctp_chunk_sack_parse_length       (4+4+2+2)

#define spindump_sctp_parse_ok         0
#define spindump_sctp_parse_error      1

//
// External API interface to this module ------------------------------------------------------
//

// params
//      packet: 1st byte of chunk (header) in a captured packet
//      decoded: pointer to chunk struct to store parsed data
//      remLen: number of bytes available to read.
unsigned int
spindump_protocols_sctp_chunk_parse(const unsigned char* packet,
                                    struct spindump_sctp_chunk* decoded,
                                    unsigned int remLen);

#endif // SPINDUMP_ANALYZE_SCTP_PARSER_H
