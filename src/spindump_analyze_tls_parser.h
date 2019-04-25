
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

#ifndef SPINDUMP_ANALYZE_TLS_H
#define SPINDUMP_ANALYZE_TLS_H

#include "spindump_protocols.h"
#include "spindump_analyze.h"

//
// External API interface to this module ------------------------------------------------------
//

const char*
spindump_analyze_tls_parser_versiontostring(const spindump_tls_version version);
int
spindump_analyze_tls_parser_isprobabletlspacket(const unsigned char* payload,
                                                unsigned int payload_len,
                                                int isDatagram);
int
spindump_analyze_tls_parser_parsepacket(const unsigned char* payload,
                                        unsigned int payload_len,
                                        unsigned int remainingCaplen,
                                        int isDatagram,
                                        int* p_isHandshake,
                                        int* p_isInitialHandshake,
                                        spindump_tls_version* p_tlsVersion,
                                        int* p_isResponse);

#endif // SPINDUMP_ANALYZE_COAP_H
