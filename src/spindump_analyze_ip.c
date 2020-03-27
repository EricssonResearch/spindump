
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

#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include "spindump_util.h"
#include "spindump_connections.h"
#include "spindump_connections_set.h"
#include "spindump_connections_set_iterator.h"
#include "spindump_analyze.h"
#include "spindump_analyze_ip.h"
#include "spindump_analyze_tcp.h"
#include "spindump_analyze_udp.h"
#include "spindump_analyze_quic.h"
#include "spindump_analyze_icmp.h"
#include "spindump_analyze_sctp.h"
#include "spindump_analyze_aggregate.h"

//
// ------- Macros and parameters --------------------------------------------------------------
//

#define MIN_IPV4_HL 20
#define IPV6_HL     40

//
// Function prototypes ------------------------------------------------------------------------
//

static void
spindump_analyze_ip_decodeippayload(struct spindump_analyze* state,
                                    struct spindump_packet* packet,
                                    unsigned int ipHeaderPosition,
                                    unsigned int ipHeaderSize,
                                    uint8_t ipVersion,
                                    uint8_t ecnFlags,
                                    const struct timeval* timestamp,
                                    unsigned int ipPacketLength,
                                    unsigned char proto,
                                    unsigned int payloadPosition,
                                    struct spindump_connection** p_connection);
static void
spindump_analyze_ip_otherippayload(struct spindump_analyze* state,
                                   struct spindump_packet* packet,
                                   unsigned int ipHeaderPosition,
                                   unsigned int ipHeaderSize,
                                   uint8_t ipVersion,
                                   uint8_t ecnFlags,
                                   const struct timeval* timestamp,
                                   unsigned int ipPacketLength,
                                   struct spindump_connection** p_connection);

//
// Actual code --------------------------------------------------------------------------------
//

//
// This is the primary analysis function for reception of an IPv4
// packet. It is called from spindump_analyze_process, if the
// ethertype points to an IPv4 packet.
//

void
spindump_analyze_ip_decodeiphdr(struct spindump_analyze* state,
                                struct spindump_packet* packet,
                                unsigned int position,
                                const struct timeval* timestamp,
                                struct spindump_connection** p_connection) {

  //
  // Some sanity checks
  //

  spindump_assert(state != 0);
  spindump_assert(spindump_packet_isvalid(packet));
  spindump_assert(p_connection != 0);

  //
  // Statistics update
  //

  state->stats->receivedIp++;

  //
  // Parse and verify IP header
  //

  if (packet->caplen < position + MIN_IPV4_HL) {
    state->stats->notEnoughPacketForIpHdr++;
    spindump_warnf("not enough bytes for the IP header (capture length only %u, %u required)", packet->caplen, position + MIN_IPV4_HL);
    *p_connection = 0;
    return;
  }
  
  struct spindump_ip ip;
  spindump_protocols_ip_header_decode(packet->contents + position,&ip);
  unsigned int ipHeaderSize = SPINDUMP_IP_HL(&ip)*4;
  if (ipHeaderSize < MIN_IPV4_HL) {
    state->stats->invalidIpHdrSize++;
    spindump_warnf("packet header length %u less than %u bytes", ipHeaderSize, MIN_IPV4_HL);
    *p_connection = 0;
    return;
  }
  
  uint8_t ipVersion = SPINDUMP_IP_V(&ip);
  if (ipVersion != 4) {
    state->stats->versionMismatch++;
    spindump_warnf("IP versions inconsistent in Ethernet frame and IP packet", SPINDUMP_IP_V(&ip));
    *p_connection = 0;
    return;
  }

  //
  // Verify packet length is appropriate
  //

  if (packet->caplen < position + ipHeaderSize) {
    state->stats->notEnoughPacketForIpHdr++;
    spindump_warnf("not enough bytes for the IP header (capture length only %u, IP header size %u)",
                   packet->caplen, ipHeaderSize);
    *p_connection = 0;
    return;
  }

  unsigned int ipPacketLength = ip.ip_len;
  if (ipPacketLength > packet->etherlen - position) {
    state->stats->invalidIpLength++;
    spindump_warnf("IP packet length is invalid (%u vs. %u)",
                   ipPacketLength,
                   packet->etherlen - position);
    *p_connection = 0;
    return;
  }

  uint8_t ecnFlags = SPINDUMP_IP_ECN(&ip);
  
  //
  // Check if the packet is a fragment
  //

  uint16_t off = ip.ip_off;
  if ((off & SPINDUMP_IP_OFFMASK) != 0) {
    state->stats->unhandledFragment++;
    spindump_debugf("ignored a fragment at offset %u", (off & SPINDUMP_IP_OFFMASK));
    *p_connection = 0;
    return;
  }

  //
  // Done with the IP header. Now look at what protocol (TCP, ICMP,
  // UDP, etc) is carried inside!
  //

  spindump_analyze_ip_decodeippayload(state,
                                      packet,
                                      position,
                                      ipHeaderSize,
                                      ipVersion,
                                      ecnFlags,
                                      timestamp,
                                      ipPacketLength,
                                      ip.ip_proto,
                                      position + ipHeaderSize,
                                      p_connection);
}

//
// This is the primary analysis function for reception of an IPv6
// packet. It is called from spindump_analyze_process, if the
// ethertype points to an IPv6 packet.
//

void
spindump_analyze_ip_decodeip6hdr(struct spindump_analyze* state,
                                 struct spindump_packet* packet,
                                 unsigned int position,
                                 const struct timeval* timestamp,
                                 struct spindump_connection** p_connection) {

  //
  // Some sanity checks
  //

  spindump_assert(state != 0);
  spindump_assert(spindump_packet_isvalid(packet));
  spindump_assert(p_connection != 0);

  //
  // Statistics update
  //

  state->stats->receivedIpv6++;

  //
  // Parse and verify IP header
  //

  if (packet->caplen < position + IPV6_HL) {
    state->stats->notEnoughPacketForIpHdr++;
    spindump_warnf("not enough bytes for the IPv6 header (capture length only %u, %u required)", packet->caplen, position + IPV6_HL);
    *p_connection = 0;
    return;
  }

  struct spindump_ip6 ip6;
  spindump_protocols_ip6_header_decode(packet->contents + position,&ip6);
  unsigned int ipHeaderSize = IPV6_HL;
  uint8_t ipVersion = SPINDUMP_IP6_V(&ip6);
  if (ipVersion != 6) {
    state->stats->versionMismatch++;
    spindump_warnf("IP versions inconsistent in Ethernet frame and IP packet", SPINDUMP_IP6_V(&ip6));
    *p_connection = 0;
    return;
  }

  unsigned int ipPacketLength = ipHeaderSize + (unsigned int)ip6.ip6_payloadlen;
  if (ipPacketLength > packet->etherlen - position) {
    state->stats->invalidIpLength++;
    spindump_warnf("IP packet length is invalid (%u vs. %u)",
                   ipPacketLength,
                   packet->etherlen - position);
    *p_connection = 0;
    return;
  }
  
  uint8_t ecnFlags = SPINDUMP_IP6_ECN(&ip6);
  
  //
  // Check if the packet is a fragment
  //

  uint8_t proto = ip6.ip6_nextheader;
  unsigned int passFh = 0;

  if (proto == SPINDUMP_IP6_FH_NEXTHDR) {

    unsigned int fhSize = spindump_ip6_fh_header_size;
    uint16_t pl = ip6.ip6_payloadlen;
    if (pl < fhSize || packet->caplen < position + ipHeaderSize + fhSize) {
      state->stats->fragmentTooShort++;
      spindump_debugf("not enough fragment header to process");
      *p_connection = 0;
      return;
    }
    struct spindump_ip6_fh fh;
    spindump_protocols_ip6_fh_header_decode(packet->contents + position + ipHeaderSize,&fh);
    uint16_t off = fh.fh_off;
    if (spindump_ip6_fh_fragoff(off) != 0) {
      state->stats->unhandledFragment++;
      spindump_debugf("ignored a fragment at offset %u", (off & SPINDUMP_IP_OFFMASK));
      *p_connection = 0;
      return;
    } else {
      passFh = fhSize;
      ipHeaderSize += fhSize;
    }
  }

  //
  // Done with the IP header. Now look at what protocol (TCP, ICMP,
  // UDP, etc) is carried inside!
  //

  spindump_analyze_ip_decodeippayload(state,
                                      packet,
                                      position,
                                      ipHeaderSize,
                                      ipVersion,
                                      ecnFlags,
                                      timestamp,
                                      ipPacketLength,
                                      proto,
                                      position + ipHeaderSize + passFh,
                                      p_connection);
}

//
// This is the primary IP payload processing function. An IP payload
// is, e.g., a TCP, ICMP, or UDP packet. If we get this far, the IP
// header (IPv4 or IPv6) has been checked and is valid.
//

static void
spindump_analyze_ip_decodeippayload(struct spindump_analyze* state,
                                    struct spindump_packet* packet,
                                    unsigned int ipHeaderPosition,
                                    unsigned int ipHeaderSize,
                                    uint8_t ipVersion,
                                    uint8_t ecnFlags,
                                    const struct timeval* timestamp,
                                    unsigned int ipPacketLength,
                                    unsigned char proto,
                                    unsigned int payloadPosition,
                                    struct spindump_connection** p_connection) {
  
  //
  // Sanity checks
  //

  spindump_assert(state != 0);
  spindump_assert(packet != 0);
  spindump_assert(spindump_packet_isvalid(packet));
  spindump_assert(ipHeaderPosition < payloadPosition);
  spindump_assert(ipHeaderSize > 0);
  spindump_assert(ipVersion == 4 || ipVersion == 6);
  spindump_assert(ipPacketLength > 0);
  spindump_assert(p_connection != 0);

  //
  // Check there is enough of the IP header
  //

  unsigned int iplen = packet->etherlen - ipHeaderPosition;
  if (iplen < ipHeaderSize ||
      packet->caplen < payloadPosition) {
    state->stats->notEnoughPacketForIpHdr++;
    spindump_warnf("not enough bytes for the IPv%u header (only %u bytes remain after Ethernet header)",
                   ipVersion,
                   iplen);
    *p_connection = 0;
    return;
  }

  //
  // Determine upper layer protocol lengths
  //

  unsigned int protolen = packet->etherlen - ipHeaderPosition - ipHeaderSize;
  spindump_deepdebugf("packet received with %u bytes, %u to ethernet, %u to ip (IPv%u), %u remains",
                      packet->etherlen,
                      ipHeaderPosition,
                      ipHeaderSize,
                      ipVersion,
                      protolen);
  spindump_assert(ipHeaderPosition + ipHeaderSize <= packet->caplen);
  unsigned int remainingCaplen = packet->caplen - ipHeaderPosition - ipHeaderSize;

  //
  // Account for statistics
  //

  if (ipVersion == 4) {
    state->stats->receivedIpBytes += (unsigned long long)(iplen);
  } else if (ipVersion == 6) {
    state->stats->receivedIpv6Bytes += (unsigned long long)(iplen);
  } else {
    spindump_errorf("should not process a non-IPv4 and non-IPv6 packet here");
    *p_connection = 0;
    return;
  }

  //
  // Branch based on the upper layer protocol
  //

  switch (proto) {

  case IPPROTO_TCP:
    spindump_analyze_process_tcp(state,
                                 packet,
                                 ipHeaderPosition,
                                 ipHeaderSize,
                                 ipVersion,
                                 ecnFlags,
                                 timestamp,
                                 ipPacketLength,
                                 ipHeaderPosition + ipHeaderSize,
                                 protolen,
                                 remainingCaplen,
                                 p_connection);
    break;

  case IPPROTO_UDP:
    spindump_analyze_process_udp(state,
                                 packet,
                                 ipHeaderPosition,
                                 ipHeaderSize,
                                 ipVersion,
                                 ecnFlags,
                                 timestamp,
                                 ipPacketLength,
                                 ipHeaderPosition + ipHeaderSize,
                                 protolen,
                                 remainingCaplen,
                                 p_connection);
    break;

  case IPPROTO_ICMP:
    spindump_analyze_process_icmp(state,
                                  packet,
                                  ipHeaderPosition,
                                  ipHeaderSize,
                                  ipVersion,
                                  ecnFlags,
                                  timestamp,
                                  ipPacketLength,
                                  ipHeaderPosition + ipHeaderSize,
                                  protolen,
                                  remainingCaplen,
                                  p_connection);
    break;

  case IPPROTO_ICMPV6:
    spindump_analyze_process_icmp6(state,
                                   packet,
                                   ipHeaderPosition,
                                   ipHeaderSize,
                                   ipVersion,
                                   ecnFlags,
                                   timestamp,
                                   ipPacketLength,
                                   ipHeaderPosition + ipHeaderSize,
                                   protolen,
                                   remainingCaplen,
                                   p_connection);
    break;

  case IPPROTO_SCTP:
    spindump_analyze_process_sctp(state,
                                  packet,
                                  ipHeaderPosition,
                                  ipHeaderSize,
                                  ipVersion,
                                  ecnFlags,
                                  timestamp,
                                  ipPacketLength,
                                  ipHeaderPosition + ipHeaderSize,
                                  protolen,
                                  remainingCaplen,
                                  p_connection);
    break;

  default:

    //
    // Debugs
    //

    spindump_debugf("received an unknown protocol %u", proto);

    //
    // Statistics update
    //

    state->stats->protocolNotSupported++;
    break;

  }

  //
  // If the packet was not a recognized protocol or if the relevant
  // TCP or other protocol analyzers failed to parse it an place into
  // an existing or new connection, the packet still needs to be
  // counted at least in the aggregate connections, e.g., host-to-host
  // or network-to-network stats.
  //

  if (*p_connection == 0) {
    spindump_analyze_ip_otherippayload(state,
                                       packet,
                                       ipHeaderPosition,
                                       ipHeaderSize,
                                       ipVersion,
                                       ecnFlags,
                                       timestamp,
                                       ipPacketLength,
                                       p_connection);
  }
}

//
// This function is called to process an IP packet that carries a
// protocol that this analyzer does not recognise, or if it
// recognises, the packet is not correct or at least not parseable by
// the analyzer. The latter can happen, for instance, if the TCP
// options, DNS request format, etc. is incorrect. Such packets do
// still get counted, but not in any of the individual connections (as
// they cannot be parsed). They get counted in any aggregate counters,
// e.g., host-to-host aggregate connections between the two IP
// addresses indicated in the packet.
//

static void
spindump_analyze_ip_otherippayload(struct spindump_analyze* state,
                                   struct spindump_packet* packet,
                                   unsigned int ipHeaderPosition,
                                   unsigned int ipHeaderSize,
                                   uint8_t ipVersion,
                                   uint8_t ecnFlags,
                                   const struct timeval* timestamp,
                                   unsigned int ipPacketLength,
                                   struct spindump_connection** p_connection) {
  //
  // Make some sanity checks on the input
  //

  spindump_assert(state != 0);
  spindump_assert(packet != 0);
  spindump_assert(spindump_packet_isvalid(packet));
  spindump_assert(ipHeaderSize > 0);
  spindump_assert(ipVersion == 4 || ipVersion == 6);
  spindump_assert(ipPacketLength > 0);
  spindump_assert(p_connection != 0);
  spindump_assert(*p_connection == 0);

  //
  // See if the packet falls under any of the aggregate connections,
  // and note the reception of an unmatching packet.
  //

  unsigned int i;
  spindump_address source;
  spindump_address destination;

  spindump_analyze_getsource(packet,ipVersion,ipHeaderPosition,&source);
  spindump_analyze_getdestination(packet,ipVersion,ipHeaderPosition,&destination);

  for (i = 0; i < state->table->nConnections; i++) {

    struct spindump_connection* connection = state->table->connections[i];
    if (connection != 0 &&
        spindump_connections_isaggregate(connection) &&
        spindump_connections_matches_aggregate_srcdst(&source,&destination,connection)) {

      //
      // Found a matching connection! Report it there.
      //
      
      spindump_analyze_process_aggregate(state,
                                         connection,
                                         packet,
                                         ipHeaderPosition,
                                         ipHeaderSize,
                                         ipVersion,
                                         ecnFlags,
                                         timestamp,
                                         ipPacketLength,
                                         state->stats);
      
      //
      // Return the first matching connection to the caller; note that
      // there may be more than one match!
      //

      if (*p_connection == 0) {
        *p_connection = connection;
      }

    }
  }

  //
  // Not found or not recognisable. Ignore.
  //

  *p_connection = 0;

  //
  // Debug printouts
  //

  spindump_debugf("non-matching packet...");
}
