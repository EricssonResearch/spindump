
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
//  SPINDUMP (C) 2019-2020 BY ERICSSON RESEARCH
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
#include "spindump_extrameas.h"

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
#define spindump_quic_version_draft34          0xff000022
#define spindump_quic_version_draft33          0xff000021
#define spindump_quic_version_draft32          0xff000020
#define spindump_quic_version_draft31          0xff00001f
#define spindump_quic_version_draft30          0xff00001e
#define spindump_quic_version_draft29          0xff00001d
#define spindump_quic_version_draft28          0xff00001c
#define spindump_quic_version_draft27          0xff00001b
#define spindump_quic_version_draft26          0xff00001a
#define spindump_quic_version_draft25          0xff000019
#define spindump_quic_version_draft24          0xff000018
#define spindump_quic_version_draft23          0xff000017
#define spindump_quic_version_draft22          0xff000016
#define spindump_quic_version_draft21          0xff000015
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
#define spindump_quic_version_quant34          0x45474722
#define spindump_quic_version_quant33          0x45474721
#define spindump_quic_version_quant32          0x45474720
#define spindump_quic_version_quant31          0x4547471f
#define spindump_quic_version_quant30          0x4547471e
#define spindump_quic_version_quant29          0x4547471d
#define spindump_quic_version_quant28          0x4547471c
#define spindump_quic_version_quant27          0x4547471b
#define spindump_quic_version_quant26          0x4547471a
#define spindump_quic_version_quant25          0x45474719
#define spindump_quic_version_quant24          0x45474718
#define spindump_quic_version_quant23          0x45474717
#define spindump_quic_version_quant22          0x45474716
#define spindump_quic_version_quant21          0x45474715
#define spindump_quic_version_quant20          0x45474714
#define spindump_quic_version_quant19          0x45474713
#define spindump_quic_version_huitema          0x50435131
#define spindump_quic_version_mozilla          0xf123f0c5
#define spindump_quic_version_googlemask       0xfff0f0f0
#define spindump_quic_version_google           0x51303030
#define spindump_quic_version_forcenegotmask   0x0f0f0f0f
#define spindump_quic_version_forcenegotiation 0x0a0a0a0a
#define spindump_quic_version_titrlo1          0xf0f0f1f0
#define spindump_quic_version_titrlo2          0xf0f0f1f1
#define spindump_quic_version_titqrlo          0xf0f0f1f2
#define spindump_quic_version_orqllos          0x50435132
#define spindump_quic_version_mvfst_d24        0xfaceb001
#define spindump_quic_version_mvfst            0xfaceb002
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
(*spindump_analyze_quic_parser_version_parsemessagelengthfunc)(const unsigned char* payload,
                                                               unsigned int payload_len,
                                                               unsigned int remainingCaplen,
                                                               enum spindump_quic_message_type type,
                                                               unsigned int cidLengthFieldsTotalSize,
                                                               unsigned int cidLengthsInBytes,
                                                               unsigned int* p_messageLen,
                                                               struct spindump_stats* stats);
typedef int
(*spindump_analyze_quic_parser_version_getspinbitvaluefunc)(uint32_t version,
                                                            uint8_t headerByte,
                                                            int* p_spinValue);

typedef int
(*spindump_analyze_quic_parser_version_getextrameasfunc)(uint32_t version,
                                                         uint8_t headerByte,
                                                         int spin,
                                                         struct spindump_extrameas* p_extrameasValue);


struct spindump_quic_versiondescr {
  uint32_t version;
  spindump_analyze_quic_parser_version_namefunc namefunction;
  const char* basename;
  int supported;
  int longCidLength;
  spindump_analyze_quic_parser_version_messagetypefunc messagetypefunction;
  spindump_analyze_quic_parser_version_parsemessagelengthfunc parselengthsfunction;
  spindump_analyze_quic_parser_version_getspinbitvaluefunc spinbitvaluefunction;
  spindump_analyze_quic_parser_version_getextrameasfunc extrameasvaluefunction;
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
int
spindump_analyze_quic_parser_version_getmessagetype(uint32_t version,
                                                    uint8_t headerByte,
                                                    enum spindump_quic_message_type* p_type);
int
spindump_analyze_quic_parser_version_parselengths(uint32_t version,
                                                  const unsigned char* payload,
                                                  unsigned int payload_len,
                                                  unsigned int remainingCaplen,
                                                  enum spindump_quic_message_type type,
                                                  unsigned int cidLengthFieldsTotalSize,
                                                  unsigned int cidLengthsInBytes,
                                                  unsigned int* p_messageLen,
                                                  struct spindump_stats* stats);
int
spindump_analyze_quic_parser_version_getspinbitvalue(uint32_t version,
                                                     uint8_t headerByte,
                                                     int* p_spinValue);

int
spindump_analyze_quic_parser_version_getextrameas(uint32_t version,
                                                 uint8_t headerByte,
                                                 int spin,
                                                 struct spindump_extrameas* p_extrameasValue);

int
spindump_analyze_quic_parser_version_useslongcidlength(uint32_t version);

#endif // SPINDUMP_ANALYZE_QUIC_PARSER_VERSIONS_H
