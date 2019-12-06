
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
// External API interface to this module ------------------------------------------------------
//
void
spindump_protocols_sctp_chunk_header_parse(const unsigned char* header,
                                           struct spindump_sctp_chunk_header* decoded);

void
spindump_protocols_sctp_chunk_init_parse(const unsigned char* header,
                                         struct spindump_sctp_chunk_init* decoded);

void
spindump_protocols_sctp_chunk_init_ack_parse(const unsigned char* header,
                                             struct spindump_sctp_chunk_init_ack* decoded);

void
spindump_protocols_sctp_chunk_data_parse(const unsigned char* header,
                                     struct spindump_sctp_chunk_data* decoded);

void
spindump_protocols_sctp_chunk_sack_parse(const unsigned char* header,
                                     struct spindump_sctp_chunk_sack* decoded);

#endif // SPINDUMP_ANALYZE_SCTP_PARSER_H
