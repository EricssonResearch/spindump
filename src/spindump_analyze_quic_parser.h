
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

#ifndef SPINDUMP_ANALYZE_QUIC_PARSER_H
#define SPINDUMP_ANALYZE_QUIC_PARSER_H

//
// Includes -----------------------------------------------------------------------------------
//

#include "spindump_protocols.h"
#include "spindump_connections.h"
#include "spindump_stats.h"

//
// Parameters ---------------------------------------------------------------------------------
//

#define SPINDUMP_QUIC_PORT1	    80
#define SPINDUMP_QUIC_PORT2	   443
#define SPINDUMP_QUIC_PORT3	  4433

//
// Convenient macros --------------------------------------------------------------------------
//

#define SPINDUMP_IS_QUIC_PORT(x)  ((x) == SPINDUMP_QUIC_PORT1 ||   \
                                   (x) == SPINDUMP_QUIC_PORT2 ||   \
                                   (x) == SPINDUMP_QUIC_PORT3)

//
// External API interface to this module ------------------------------------------------------
//

const char*
spindump_analyze_quic_parser_versiontostring(uint32_t version);
int
spindump_analyze_quic_quicidequal(struct spindump_quic_connectionid* id1,
				  struct spindump_quic_connectionid* id2);
int
spindump_analyze_quic_partialquicidequal(const unsigned char* id1,
					 struct spindump_quic_connectionid* id2);
int
spindump_analyze_quic_parser_isprobablequickpacket(const unsigned char* payload,
						   unsigned int payload_len,
						   uint16_t sourcePort,
						   uint16_t destPort);
int
spindump_analyze_quic_parser_parse(const unsigned char* payload,
				   unsigned int payload_len,
				   unsigned int remainingCaplen,
				   int* p_hasVersion,
				   uint32_t* p_version,
				   int* p_mayHaveSpinBit,
				   int* p_destinationCidLengthKnown,
				   struct spindump_quic_connectionid* p_destinationCid,
				   int* p_sourceCidPresent,
				   struct spindump_quic_connectionid* p_sourceCid,
				   enum spindump_quic_message_type* p_type,
				   struct spindump_stats* stats);
int
spindump_analyze_quic_parser_parse_google_quic(const unsigned char* payload,
				   unsigned int payload_len,
				   unsigned int remainingCaplen,
				   int* p_hasVersion,
				   uint32_t* p_version,
				   int* p_mayHaveSpinBit,
				   int* p_destinationCidLengthKnown,
				   struct spindump_quic_connectionid* p_destinationCid,
				   int* p_sourceCidPresent,
				   struct spindump_quic_connectionid* p_sourceCid,
				   enum spindump_quic_message_type* p_type,
				   struct spindump_stats* stats);
int
spindump_analyze_quic_parser_isgoogleversion(uint32_t version);
uint32_t
spindump_analyze_quic_parser_getgoogleversion(uint32_t version);
int
spindump_analyze_quic_parser_getspinbit(const unsigned char* payload,
					unsigned int payload_len,
					int longform,
					uint32_t version,
					int fromResponder,
					int* p_spin);

#endif // SPINDUMP_ANALYZE_QUIC_PARSER_H
