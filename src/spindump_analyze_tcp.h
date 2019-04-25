
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

#ifndef SPINDUMP_ANALYZE_TCP_H
#define SPINDUMP_ANALYZE_TCP_H

//
// Includes -----------------------------------------------------------------------------------
//

#include "spindump_analyze.h"

//
// External API interface to this module ------------------------------------------------------
//

void
spindump_analyze_process_tcp(struct spindump_analyze* table,
                             struct spindump_packet* packet,
                             unsigned int ipHeaderPosition,
                             unsigned int ipHeaderSize,
                             uint8_t ipVersion,
                             uint8_t ecnFlags,
                             unsigned int ipPacketLength,
                             unsigned int tcpHeaderPosition,
                             unsigned int tcpLength,
                             unsigned int remainingCaplen,
                             struct spindump_connection** p_connection);

#endif // SPINDUMP_ANALYZE_TCP_H
