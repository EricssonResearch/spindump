
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

#ifndef SPINDUMP_ANALYZE_IP_H
#define SPINDUMP_ANALYZE_IP_H

//
// Includes -----------------------------------------------------------------------------------
//

#include "spindump_analyze.h"

//
// The internal API towards the analyzer ------------------------------------------------------
//

void
spindump_analyze_ip_decodeiphdr(struct spindump_analyze* state,
                                struct spindump_packet* packet,
                                unsigned int position,
                                struct spindump_connection** p_connection);
void
spindump_analyze_ip_decodeip6hdr(struct spindump_analyze* state,
                                 struct spindump_packet* packet,
                                 unsigned int position,
                                 struct spindump_connection** p_connection);

#endif // SPINDUMP_ANALYZE_IP_H
