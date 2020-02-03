
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

//
// Includes -----------------------------------------------------------------------------------
//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "spindump_util.h"
#include "spindump_stats.h"

//
// Actual code --------------------------------------------------------------------------------
//

//
// Create a statistics tracking object
//

struct spindump_stats*
spindump_stats_initialize(void) {
  
  //
  // Calculate size and allocate state
  // 
      
  unsigned int size = sizeof(struct spindump_stats);
  struct spindump_stats* stats = (struct spindump_stats*)spindump_malloc(size);
  if (stats == 0) {
    spindump_errorf("cannot allocate statistics state of %u bytes", size);
    return(0);
  }
  
  //
  // Initialize state
  // 
  
  memset(stats,0,size);
  
  //
  // Done. Return state.
  // 
  
  return(stats);
}

//
// Print the statistics out
//

void
spindump_stats_report(struct spindump_stats* stats,
                      FILE* file) {
  fprintf(file,"received frames:                        %8u\n", stats->receivedFrames);
  fprintf(file,"analyzer handler calls:                 %8u\n", stats->analyzerHandlerCalls);
  fprintf(file,"frame not long enough for Ethernet hdr: %8u\n", stats->notEnoughPacketForEthernetHdr);
  fprintf(file,"received IPv4 packets:                  %8u\n", stats->receivedIp);
  fprintf(file,"received IPv4 bytes:                    %8sB\n",
          spindump_meganumberll_tostring(stats->receivedIpBytes));
  fprintf(file,"received IPv6 packets:                  %8u\n", stats->receivedIpv6);
  fprintf(file,"received IPv6 bytes:                    %8sB\n",
          spindump_meganumberll_tostring(stats->receivedIpv6Bytes));
  fprintf(file,"invalid IP header size:                 %8u\n", stats->invalidIpHdrSize);
  fprintf(file,"packet not long enough for IP hdr:      %8u\n", stats->notEnoughPacketForIpHdr);
  fprintf(file,"version mismatch:                       %8u\n", stats->versionMismatch);
  fprintf(file,"invalid IP length:                      %8u\n", stats->invalidIpLength);
  fprintf(file,"unprocessed IP fragment:                %8u\n", stats->unhandledFragment);
  fprintf(file,"packet not long enough for FH:          %8u\n", stats->fragmentTooShort);
  fprintf(file,"received ICMP packets:                  %8u\n", stats->receivedIcmp);
  fprintf(file,"invalid ICMP header size:               %8u\n", stats->invalidIcmpHdrSize);
  fprintf(file,"packet not long enough for ICMP hdr:    %8u\n", stats->notEnoughPacketForIcmpHdr);
  fprintf(file,"unsupported ICMP type:                  %8u\n", stats->unsupportedIcmpType);
  fprintf(file,"invalid ICMP code:                      %8u\n", stats->invalidIcmpCode);
  fprintf(file,"received ICMP echo packets:             %8u\n", stats->receivedIcmpEcho);
  fprintf(file,"received UDP packets:                   %8u\n", stats->receivedUdp);
  fprintf(file,"packet not long enough for UDP hdr:     %8u\n", stats->notEnoughPacketForUdpHdr);
  fprintf(file,"packet not long enough for DNS hdr:     %8u\n", stats->notEnoughPacketForDnsHdr);
  fprintf(file,"packet not long enough for COAP hdr:    %8u\n", stats->notEnoughPacketForCoapHdr);
  fprintf(file,"COAP version is not supported:          %8u\n", stats->unrecognisedCoapVersion);
  fprintf(file,"COAP message was not trackable:         %8u\n", stats->untrackableCoapMessage);
  fprintf(file,"TLS message not parsable:               %8u\n", stats->invalidTlsPacket);
  fprintf(file,"received QUIC packets:                  %8u\n", stats->receivedQuic);
  fprintf(file,"packet not long enough for QUIC hdr:    %8u\n", stats->notEnoughPacketForQuicHdr);
  fprintf(file,"packet not long enough for QUIC token:  %8u\n", stats->notEnoughPacketForQuicHdrToken);
  fprintf(file,"packet not long enough for QUIC length: %8u\n", stats->notEnoughPacketForQuicHdrLength);
  fprintf(file,"unable to parse coalesced Google QUIC:  %8u\n", stats->notAbleToHandleGoogleQuicCoalescing);
  fprintf(file,"unrecognised QUIC version:              %8u\n", stats->unrecognisedQuicVersion);
  fprintf(file,"unsupported QUIC message type:          %8u\n", stats->unsupportedQuicType);
  fprintf(file,"unrecognised QUIC message type:         %8u\n", stats->unrecognisedQuicType);
  fprintf(file,"received TCP packets:                   %8u\n", stats->receivedTcp);
  fprintf(file,"invalid TCP header size:                %8u\n", stats->invalidTcpHdrSize);
  fprintf(file,"packet not long enough for TCP hdr:     %8u\n", stats->notEnoughPacketForTcpHdr);
  fprintf(file,"unknown TCP connection:                 %8u\n", stats->unknownTcpConnection);
  fprintf(file,"protocol not supported:                 %8u\n", stats->protocolNotSupported);
  fprintf(file,"unsupported Ethertype:                  %8u\n", stats->unsupportedEthertype);
  fprintf(file,"unsupported Nulltype:                   %8u\n", stats->unsupportedNulltype);
  fprintf(file,"invalid RTT:                            %8u\n", stats->invalidRtt);
  fprintf(file,"connections:                            %8u\n", stats->connections);
  fprintf(file,"connections, ICMP:                      %8u\n", stats->connectionsIcmp);
  fprintf(file,"connections, TCP:                       %8u\n", stats->connectionsTcp);
  fprintf(file,"connections, UDP:                       %8u\n", stats->connectionsUdp);
  fprintf(file,"connections, DNS:                       %8u\n", stats->connectionsDns);
  fprintf(file,"connections, COAP:                      %8u\n", stats->connectionsCoap);
  fprintf(file,"connections, QUIC:                      %8u\n", stats->connectionsQuic);
  fprintf(file,"connections, deleted after closing:     %8u\n", stats->connectionsDeletedClosed);
  fprintf(file,"connections, deleted after inactive:    %8u\n", stats->connectionsDeletedInactive);
}

//
// Uninitialize, i.e., free up resources in the statistics object.
//

void
spindump_stats_uninitialize(struct spindump_stats* stats) {
  spindump_assert(stats != 0);
  memset(stats,0xFF,sizeof(*stats));
  spindump_free(stats);
}
