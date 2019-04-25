
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

#ifndef SPINDUMP_ANALYZE_COAP_H
#define SPINDUMP_ANALYZE_COAP_H

//
// Includes -----------------------------------------------------------------------------------
//

#include "spindump_analyze.h"

//
// Parameters ---------------------------------------------------------------------------------
//

#define SPINDUMP_COAP_PORT1         5683
#define SPINDUMP_COAP_PORT2         5684

//
// External API interface to this module ------------------------------------------------------
//

int
spindump_analyze_coap_isprobablecoappacket(const unsigned char* payload,
                                           unsigned int payload_len,
                                           uint16_t sourcePort,
                                           uint16_t destPort,
                                           int* p_isDtls);
void
spindump_analyze_process_coap(struct spindump_analyze* state,
                              struct spindump_packet* packet,
                              unsigned int ipHeaderPosition,
                              unsigned int ipHeaderSize,
                              uint8_t ipVersion,
                              uint8_t ecnFlags,
                              unsigned int ipPacketLength,
                              unsigned int udpHeaderPosition,
                              unsigned int udpLength,
                              unsigned int remainingCaplen,
                              int isDtls,
                              struct spindump_connection** p_connection);

#endif // SPINDUMP_ANALYZE_COAP_H
