
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

#ifndef SPINDUMP_STATS_H
#define SPINDUMP_STATS_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <stdio.h>

//
// Statistics data structures -----------------------------------------------------------------
//

struct spindump_stats {
  unsigned int receivedFrames;
  unsigned int notEnoughPacketForEthernetHdr;
  unsigned int receivedIp;
  unsigned int receivedIpv6;
  unsigned long long receivedIpBytes;
  unsigned long long receivedIpv6Bytes;
  unsigned int invalidIpHdrSize;
  unsigned int notEnoughPacketForIpHdr;
  unsigned int versionMismatch;
  unsigned int invalidIpLength;
  unsigned int unhandledFragment;
  unsigned int fragmentTooShort;
  unsigned int receivedIcmp;
  unsigned int invalidIcmpHdrSize;
  unsigned int notEnoughPacketForIcmpHdr;
  unsigned int unsupportedIcmpType;
  unsigned int invalidIcmpCode;
  unsigned int receivedIcmpEcho;
  unsigned int receivedUdp;
  unsigned int notEnoughPacketForUdpHdr;
  unsigned int notEnoughPacketForDnsHdr;
  unsigned int notEnoughPacketForCoapHdr;
  unsigned int unrecognisedCoapVersion;
  unsigned int untrackableCoapMessage;
  unsigned int invalidTlsPacket;
  unsigned int receivedQuic;
  unsigned int notEnoughPacketForQuicHdr;
  unsigned int notEnoughPacketForQuicHdrToken;
  unsigned int notEnoughPacketForQuicHdrLength;
  unsigned int notAbleToHandleGoogleQuicCoalescing;
  unsigned int unrecognisedQuicVersion;
  unsigned int unsupportedQuicVersion;
  unsigned int unrecognisedQuicType;
  unsigned int unsupportedQuicType;
  unsigned int receivedTcp;
  unsigned int notEnoughPacketForTcpHdr;
  unsigned int invalidTcpHdrSize;
  unsigned int unknownTcpConnection;
  unsigned int receivedSctp;
  unsigned int notEnoughPacketForSctpHdr;
  unsigned int protocolNotSupported;
  unsigned int unsupportedEthertype;
  unsigned int unsupportedNulltype;
  unsigned int invalidRtt;
  unsigned int connections;
  unsigned int connectionsIcmp;
  unsigned int connectionsTcp;
  unsigned int connectionsSctp;
  unsigned int connectionsUdp;
  unsigned int connectionsDns;
  unsigned int connectionsCoap;
  unsigned int connectionsQuic;
  unsigned int connectionsDeletedClosed;
  unsigned int connectionsDeletedInactive;
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

