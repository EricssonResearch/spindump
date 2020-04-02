
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
//  SPINDUMP (C) 2018-2020 BY ERICSSON RESEARCH
//  AUTHOR: JARI ARKKO
//
// 

#ifndef SPINDUMP_STATS_H
#define SPINDUMP_STATS_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <stdio.h>
#include "spindump_util.h"

//
// Statistics data structures -----------------------------------------------------------------
//

struct spindump_stats {
  spindump_counter_32bit receivedFrames;
  spindump_counter_32bit analyzerHandlerCalls;
  spindump_counter_32bit notEnoughPacketForEthernetHdr;
  spindump_counter_32bit receivedIp;
  spindump_counter_32bit receivedIpv6;
  spindump_counter_64bit receivedIpBytes;
  spindump_counter_64bit receivedIpv6Bytes;
  spindump_counter_32bit invalidIpHdrSize;
  spindump_counter_32bit notEnoughPacketForIpHdr;
  spindump_counter_32bit versionMismatch;
  spindump_counter_32bit invalidIpLength;
  spindump_counter_32bit unhandledFragment;
  spindump_counter_32bit fragmentTooShort;
  spindump_counter_32bit receivedIcmp;
  spindump_counter_32bit invalidIcmpHdrSize;
  spindump_counter_32bit notEnoughPacketForIcmpHdr;
  spindump_counter_32bit unsupportedIcmpType;
  spindump_counter_32bit invalidIcmpCode;
  spindump_counter_32bit receivedIcmpEcho;
  spindump_counter_32bit receivedUdp;
  spindump_counter_32bit notEnoughPacketForUdpHdr;
  spindump_counter_32bit notEnoughPacketForDnsHdr;
  spindump_counter_32bit notEnoughPacketForCoapHdr;
  spindump_counter_32bit unrecognisedCoapVersion;
  spindump_counter_32bit untrackableCoapMessage;
  spindump_counter_32bit invalidTlsPacket;
  spindump_counter_32bit receivedQuic;
  spindump_counter_32bit notEnoughPacketForQuicHdr;
  spindump_counter_32bit notEnoughPacketForQuicHdrToken;
  spindump_counter_32bit notEnoughPacketForQuicHdrLength;
  spindump_counter_32bit notAbleToHandleGoogleQuicCoalescing;
  spindump_counter_32bit unrecognisedQuicVersion;
  spindump_counter_32bit unsupportedQuicVersion;
  spindump_counter_32bit unrecognisedQuicType;
  spindump_counter_32bit unsupportedQuicType;
  spindump_counter_32bit receivedTcp;
  spindump_counter_32bit notEnoughPacketForTcpHdr;
  spindump_counter_32bit invalidTcpHdrSize;
  spindump_counter_32bit unknownTcpConnection;
  spindump_counter_32bit unknownSctpConnection;
  spindump_counter_32bit receivedSctp;
  spindump_counter_32bit notEnoughPacketForSctpHdr;
  spindump_counter_32bit protocolNotSupported;
  spindump_counter_32bit unsupportedEthertype;
  spindump_counter_32bit unsupportedNulltype;
  spindump_counter_32bit invalidRtt;
  spindump_counter_32bit connections;
  spindump_counter_32bit connectionsIcmp;
  spindump_counter_32bit connectionsTcp;
  spindump_counter_32bit connectionsSctp;
  spindump_counter_32bit connectionsUdp;
  spindump_counter_32bit connectionsDns;
  spindump_counter_32bit connectionsCoap;
  spindump_counter_32bit connectionsQuic;
  spindump_counter_32bit connectionsDeletedClosed;
  spindump_counter_32bit connectionsDeletedInactive;
  uint8_t padding2[4]; // unused padding to align the next field properly
};

//
// Statistics module API interface ------------------------------------------------------------
//

struct spindump_stats*
spindump_stats_initialize(void);
void
spindump_stats_report(struct spindump_stats* stats,
                      FILE* file);
void
spindump_stats_uninitialize(struct spindump_stats* state);

#endif // SPINDUMP_STATS_H

