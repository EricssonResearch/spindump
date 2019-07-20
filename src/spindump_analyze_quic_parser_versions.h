
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

#ifndef SPINDUMP_ANALYZE_QUIC_PARSER_VERSIONS_H
#define SPINDUMP_ANALYZE_QUIC_PARSER_VERSIONS_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <stdlib.h>
#include "spindump_util.h"
#include "spindump_protocols.h"
#include "spindump_analyze_quic_parser.h"
#include "spindump_analyze_quic_parser_util.h"

//
// Parameters ---------------------------------------------------------------------------------
//

//
// Protocol definitions -----------------------------------------------------------------------
//

//
// QUIC versions
//

#define spindump_quic_version_negotiation      0x00000000
#define spindump_quic_version_rfc              0x00000001
#define spindump_quic_version_draft20          0xff000014
#define spindump_quic_version_draft19          0xff000013
#define spindump_quic_version_draft18          0xff000012
#define spindump_quic_version_draft17          0xff000011
#define spindump_quic_version_draft16          0xff000010
#define spindump_quic_version_draft15          0xff00000f
#define spindump_quic_version_draft14          0xff00000e
#define spindump_quic_version_draft13          0xff00000d
#define spindump_quic_version_draft12          0xff00000c
#define spindump_quic_version_draft11          0xff00000b
#define spindump_quic_version_draft10          0xff00000a
#define spindump_quic_version_draft09          0xff000009
#define spindump_quic_version_draft08          0xff000008
#define spindump_quic_version_draft07          0xff000007
#define spindump_quic_version_draft06          0xff000006
#define spindump_quic_version_draft05          0xff000005
#define spindump_quic_version_draft04          0xff000004
#define spindump_quic_version_draft03          0xff000003
#define spindump_quic_version_draft02          0xff000002
#define spindump_quic_version_draft01          0xff000001
#define spindump_quic_version_draft00          0xff000000
#define spindump_quic_version_quant19          0x45474713
#define spindump_quic_version_quant20          0x45474714
#define spindump_quic_version_huitema          0x50435131
#define spindump_quic_version_mozilla          0xf123f0c5
#define spindump_quic_version_googlemask       0xfff0f0f0
#define spindump_quic_version_google           0x51303030
#define spindump_quic_version_forcenegotmask   0x0f0f0f0f
#define spindump_quic_version_forcenegotiation 0x0a0a0a0a
#define spindump_quic_version_unknown          0xffffffff

//
// Data structures ----------------------------------------------------------------------------
//

typedef void
(*spindump_analyze_quic_parser_version_namefunc)(uint32_t version,
                                                 const char* basename,
                                                 char* buf,
                                                 size_t bufsize);
typedef int
(*spindump_analyze_quic_parser_version_messagetypefunc)(uint32_t version,
                                                        uint8_t headerByte,
                                                        enum spindump_quic_message_type* type);
typedef int
(*spindump_analyze_quic_parser_version_parsemessagelength)(const unsigned char* payload,
                                                           unsigned int payload_len,
                                                           unsigned int remainingCaplen,
                                                           enum spindump_quic_message_type type,
                                                           unsigned int cidLengthsInBytes,
                                                           unsigned int* p_messageLen,
                                                           struct spindump_stats* stats);

struct spindump_quic_versiondescr {
  uint32_t version;
  spindump_analyze_quic_parser_version_namefunc namefunction;
  const char* basename;
  int supported;
  spindump_analyze_quic_parser_version_messagetypefunc messagetypefunction;
  spindump_analyze_quic_parser_version_parsemessagelength parselengthsfunction;
};

//
// External API interface to this module ------------------------------------------------------
//

void
spindump_analyze_quic_parser_versiontostring(uint32_t version,
                                             char* buf,
                                             size_t bufsize);
#define spindump_quic_version_isforcenegot(v)  (((v) & spindump_quic_version_forcenegotmask) == spindump_quic_version_forcenegotiation)
int
spindump_analyze_quic_parser_isgoogleversion(uint32_t version);
uint32_t
spindump_analyze_quic_parser_getgoogleversion(uint32_t version);
const struct spindump_quic_versiondescr*
spindump_analyze_quic_parser_version_findversion(uint32_t version);

#endif // SPINDUMP_ANALYZE_QUIC_PARSER_VERSIONS_H
