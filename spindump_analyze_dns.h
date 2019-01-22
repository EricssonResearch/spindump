
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

#ifndef SPINDUMP_ANALYZE_DNS_H
#define SPINDUMP_ANALYZE_DNS_H

//
// Includes -----------------------------------------------------------------------------------
//

#include "spindump_analyze.h"

//
// Parameters ---------------------------------------------------------------------------------
//

#define SPINDUMP_DNS_PORT	    53

//
// External API interface to this module ------------------------------------------------------
//

int
spindump_analyze_dns_isprobablednspacket(const unsigned char* payload,
					 unsigned int payload_len,
					 uint16_t sourcePort,
					 uint16_t destPort);
void
spindump_analyze_process_dns(struct spindump_analyze* state,
			     struct spindump_packet* packet,
			     unsigned int ipHeaderPosition,
			     unsigned int ipHeaderSize,
			     uint8_t ipVersion,
			     unsigned int ipPacketLength,
			     unsigned int udpHeaderPosition,
			     unsigned int udpLength,
			     struct spindump_connection** p_connection);

#endif // SPINDUMP_ANALYZE_DNS_H
