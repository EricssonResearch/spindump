
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
//  SPINDUMP (C) 2019 BY ERICSSON RESEARCH
//  AUTHOR: JARI ARKKO
//
// 

#ifndef SPINDUMP_ANALYZE_QUIC_PARSER_UTIL_H
#define SPINDUMP_ANALYZE_QUIC_PARSER_UTIL_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <stdlib.h>
#include "spindump_util.h"
#include "spindump_protocols.h"
#include "spindump_analyze_quic_parser.h"

//
// Parameters ---------------------------------------------------------------------------------
//

//
// External API interface to this module ------------------------------------------------------
//

unsigned int
spindump_analyze_quic_parser_util_onecidlength(uint8_t value);
void
spindump_analyze_quic_parser_util_cidlengths(uint8_t lengthsbyte,
                                             unsigned int* p_destinationLength,
                                             unsigned int* p_sourceLength);
int
spindump_analyze_quic_parser_util_parseint(const unsigned char* buffer,
                                           unsigned int bufferLength,
                                           unsigned int bufferRemainingCaplen,
                                           unsigned int* integerLength,
                                           uint64_t* integer);
int
spindump_analyze_quic_quicidequal(struct spindump_quic_connectionid* id1,
                                  struct spindump_quic_connectionid* id2);
int
spindump_analyze_quic_partialquicidequal(const unsigned char* id1,
                                         struct spindump_quic_connectionid* id2);
#ifdef SPINDUMP_DEBUG
const char*
spindump_analyze_quic_parser_util_typetostring(enum spindump_quic_message_type type);
#endif

#endif // SPINDUMP_ANALYZE_QUIC_PARSER_UTIL_H
