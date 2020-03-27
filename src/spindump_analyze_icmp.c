
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
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include "spindump_util.h"
#include "spindump_connections.h"
#include "spindump_analyze.h"
#include "spindump_analyze_icmp.h"

//
// Actual code --------------------------------------------------------------------------------
//

//
// This is the main function to process an incoming (IPv4) ICMP
// packet, parse the packet as much as we can and process it
// appropriately. The function sets the p_connection output parameter
// to the connection that this packet belongs to (and possibly creates
// this connection if the packet is the first in a flow).
//
// It is assumed that prior modules, i.e., the capture module has
// filled in the relevant header pointers in the packet structure
// "packet" correctly.
//

void
spindump_analyze_process_icmp(struct spindump_analyze* state,
                              struct spindump_packet* packet,
                              unsigned int ipHeaderPosition,
                              unsigned int ipHeaderSize,
                              uint8_t ipVersion,
                              uint8_t ecnFlags,
                              const struct timeval* timestamp,
                              unsigned int ipPacketLength,
                              unsigned int icmpHeaderPosition,
                              unsigned int icmpLength,
                              unsigned int remainingCaplen,
                              struct spindump_connection** p_connection) {

  spindump_assert(state != 0);
  spindump_assert(packet != 0);
  spindump_assert(ipVersion == 4);
  spindump_assert(icmpHeaderPosition > ipHeaderPosition);
  spindump_assert(p_connection != 0);

  //
  // Parse the ICMP header
  //

  state->stats->receivedIcmp++;
  if (icmpLength < spindump_icmp_header_size) {
    state->stats->invalidIcmpHdrSize++;
    spindump_warnf("ICMP header length %u invalid", icmpLength);
    *p_connection = 0;
    return;
  }

  if (remainingCaplen < spindump_icmp_header_size) {
    state->stats->notEnoughPacketForIcmpHdr++;
    spindump_warnf("not enough payload bytes for an ICMP header", icmpLength);
    *p_connection = 0;
    return;
  }
  
  struct spindump_icmp icmp;
  spindump_protocols_icmp_header_decode(packet->contents + icmpHeaderPosition,&icmp);
  spindump_debugf("received an IPv%u ICMP packet of %u bytes",
                  ipVersion,
                  packet->etherlen);

  uint8_t peerType = icmp.ih_type;

  switch (peerType) {
  case ICMP_ECHO:
    if (icmpLength < spindump_icmp_echo_header_size ||
        remainingCaplen < spindump_icmp_echo_header_size) {
      state->stats->notEnoughPacketForIcmpHdr++;
      spindump_warnf("not enough payload bytes for an ICMP echo header", icmpLength);
      *p_connection = 0;
      return;
    }
    if (icmp.ih_code != 0) {
      state->stats->invalidIcmpCode++;
      *p_connection = 0;
      return;
    }
    state->stats->receivedIcmpEcho++;
    spindump_deepdebugf("received ICMP ECHO request for id=%u seq=%u",
                        icmp.ih_u.ih_echo.ih_id,
                        icmp.ih_u.ih_echo.ih_seq);
    break;

  case ICMP_ECHOREPLY:
    if (icmpLength < spindump_icmp_echo_header_size ||
        remainingCaplen < spindump_icmp_echo_header_size) {
      state->stats->notEnoughPacketForIcmpHdr++;
      spindump_warnf("not enough payload bytes for an ICMP echo header", icmpLength);
      *p_connection = 0;
      return;
    }
    if (icmp.ih_code != 0) {
      state->stats->invalidIcmpCode++;
      *p_connection = 0;
      return;
    }
    state->stats->receivedIcmpEcho++;
    spindump_deepdebugf("received ICMP ECHO reply for id=%u seq=%u",
                        icmp.ih_u.ih_echo.ih_id,
                        icmp.ih_u.ih_echo.ih_seq);
    break;

  default:
    state->stats->unsupportedIcmpType++;
    *p_connection = 0;
    return;
  }
  
  //
  // Check whether this is an ICMP ECHO or ECHO REPLY and if so, proceed
  //
  
  int new = 0;
  int fromResponder;
  
  if (peerType == ICMP_ECHO ||
      peerType == ICMP_ECHOREPLY) {

    spindump_address source;
    spindump_address destination;
    uint16_t peerId = icmp.ih_u.ih_echo.ih_id;
    uint16_t peerSeq = icmp.ih_u.ih_echo.ih_seq;

    if (peerType == ICMP_ECHO) {
      spindump_analyze_getsource(packet,ipVersion,ipHeaderPosition,&source);
      spindump_analyze_getdestination(packet,ipVersion,ipHeaderPosition,&destination);
    } else {
      spindump_analyze_getsource(packet,ipVersion,ipHeaderPosition,&destination);
      spindump_analyze_getdestination(packet,ipVersion,ipHeaderPosition,&source);
    }

    //
    // Look for existing connection
    //

    struct spindump_connection* connection =
      spindump_connections_searchconnection_icmp(&source,
                                                 &destination,
                                                 ICMP_ECHO,
                                                 peerId,
                                                 state->table);

    //
    // If not found, create a new one
    //

    if (connection == 0) {

      if (peerType == ICMP_ECHOREPLY) {

        //
        // We're only seeing a REPLY without corresponding REQUEST, so
        // we will drop this packet and not deal with the connection;
        // it packet may of course still be counted within some
        // aggregate statistics.
        //

        *p_connection = 0;
        return;

      } else {

        connection = spindump_connections_newconnection_icmp(&source,
                                                             &destination,
                                                             peerType,
                                                             peerId,
                                                             &packet->timestamp,
                                                             state->table);
        if (connection == 0) {
          *p_connection = 0;
          return;
        }
        new = 1;
        state->stats->connections++;
        state->stats->connectionsIcmp++;

      }
    }

    //
    // Mark the reception of a packet in the connection
    //

    if (peerType == ICMP_ECHOREPLY) {

      if (connection->state == spindump_connection_state_establishing) {
        spindump_connections_changestate(state,packet,timestamp,connection,spindump_connection_state_established);
      }

      spindump_deepdeepdebugf("looking for ICMP SEQ match of %u",
                              peerSeq);
      const struct timeval* ackto =
        spindump_messageidtracker_ackto(&connection->u.icmp.side1Seqs,peerSeq);
      if (ackto != 0) {
        spindump_deepdeepdebugf("found ackto for sequence %u", peerSeq);
        spindump_connections_newrttmeasurement(state,
                                               packet,
                                               connection,
                                               ipPacketLength,
                                               1,
                                               0,
                                               ackto,
                                               &packet->timestamp,
                                               "ICMP echo reply");
      } else {
        spindump_deepdeepdebugf("did not find ackto for sequence %u", peerSeq);
      }

      fromResponder = 1;

    } else {

      spindump_messageidtracker_add(&connection->u.icmp.side1Seqs,&packet->timestamp,peerSeq);
      fromResponder = 0;

    }

    //
    // Call some handlers based on what happened here, if needed
    //

    if (new) {
      spindump_analyze_process_handlers(state,
                                        spindump_analyze_event_newconnection,
                                        timestamp,
                                        fromResponder,
                                        ipPacketLength,
                                        packet,
                                        connection);
    }

    //
    // Update statistics
    //

    spindump_analyze_process_pakstats(state,
                                      connection,
                                      timestamp,
                                      fromResponder,
                                      packet,
                                      ipPacketLength,
                                      ecnFlags);

    //
    // Done. Return connection information to caller.
    //

    *p_connection = connection;

  } else {

    //
    // This isn't ICMP ECHO or REPLY so we don't support this; the
    // packet may still be counted among host-to-host or other
    // aggregate statistics, if the addresses match that aggregate.
    //

    *p_connection = 0;

  }
}

//
// This is the main function to process an incoming (IPv6) ICMP
// packet, parse the packet as much as we can and process it
// appropriately. The function sets the p_connection output parameter
// to the connection that this packet belongs to (and possibly creates
// this connection if the packet is the first in a flow).
//
// It is assumed that prior modules, i.e., the capture module has
// filled in the relevant header pointers in the packet structure
// "packet" correctly.
//

void
spindump_analyze_process_icmp6(struct spindump_analyze* state,
                               struct spindump_packet* packet,
                               unsigned int ipHeaderPosition,
                               unsigned int ipHeaderSize,
                               uint8_t ipVersion,
                               uint8_t ecnFlags,
                               const struct timeval* timestamp,
                               unsigned int ipPacketLength,
                               unsigned int icmpHeaderPosition,
                               unsigned int icmpLength,
                               unsigned int remainingCaplen,
                               struct spindump_connection** p_connection) {

  spindump_assert(state != 0);
  spindump_assert(packet != 0);
  spindump_assert(ipVersion == 6);
  spindump_assert(icmpHeaderPosition > ipHeaderPosition);
  spindump_assert(p_connection != 0);

  //
  // Parse the ICMPv6 header
  //

  state->stats->receivedIcmp++;
  if (icmpLength < spindump_icmp_header_size) {
    state->stats->invalidIcmpHdrSize++;
    spindump_warnf("ICMPv6 header length %u invalid", icmpLength);
    *p_connection = 0;
    return;
  }

  if (remainingCaplen < spindump_icmp_header_size) {
    state->stats->notEnoughPacketForIcmpHdr++;
    spindump_warnf("not enough payload bytes for an ICMPv6 header", icmpLength);
    *p_connection = 0;
    return;
  }
  
  struct spindump_icmpv6 icmp6;
  spindump_protocols_icmp6_header_decode(packet->contents + icmpHeaderPosition,&icmp6);
  spindump_debugf("received an IPv%u ICMP packet of %u bytes",
                  ipVersion,
                  packet->etherlen);

  uint8_t peerType = icmp6.ih6_type;
  int new = 0;
  int fromResponder;

  switch (peerType) {
  case ICMP6_ECHO_REQUEST:
    spindump_deepdebugf("ICMP6_ECHO_REQUEST sizes %u vs. %u",
                        icmpLength, spindump_icmp_echo_header_size);
    if (icmpLength < spindump_icmp_echo_header_size ||
        remainingCaplen < spindump_icmp_echo_header_size) {
      state->stats->notEnoughPacketForIcmpHdr++;
      spindump_warnf("not enough payload bytes for an ICMP echo header", icmpLength);
      *p_connection = 0;
      return;
    }
    if (icmp6.ih6_code != 0) {
      state->stats->invalidIcmpCode++;
      *p_connection = 0;
      return;
    }
    state->stats->receivedIcmpEcho++;
    spindump_deepdebugf("received ICMP ECHO request for id=%u seq=%u",
                        icmp6.ih6_u.ih6_echo.ih6_id,
                        icmp6.ih6_u.ih6_echo.ih6_seq);
    break;

  case ICMP6_ECHO_REPLY:
    if (icmpLength < spindump_icmp_echo_header_size ||
        remainingCaplen < spindump_icmp_echo_header_size) {
      state->stats->notEnoughPacketForIcmpHdr++;
      spindump_warnf("not enough payload bytes for an ICMP echo header", icmpLength);
      *p_connection = 0;
      return;
    }
    if (icmp6.ih6_code != 0) {
      state->stats->invalidIcmpCode++;
      *p_connection = 0;
      return;
    }
    state->stats->receivedIcmpEcho++;
    spindump_deepdebugf("received ICMP ECHO reply for id=%u seq=%u",
                        icmp6.ih6_u.ih6_echo.ih6_id,
                        icmp6.ih6_u.ih6_echo.ih6_seq);
    break;

  default:
    state->stats->unsupportedIcmpType++;
    *p_connection = 0;
    return;
  }

  //
  // Check whether this is an ICMP ECHO or ECHO REPLY and if so, proceed
  //

  if (peerType == ICMP6_ECHO_REQUEST ||
      peerType == ICMP6_ECHO_REPLY) {

    spindump_address source;
    spindump_address destination;
    uint16_t peerId = icmp6.ih6_u.ih6_echo.ih6_id;
    uint16_t peerSeq = icmp6.ih6_u.ih6_echo.ih6_seq;

    if (peerType == ICMP6_ECHO_REQUEST) {
      spindump_analyze_getsource(packet,ipVersion,ipHeaderPosition,&source);
      spindump_analyze_getdestination(packet,ipVersion,ipHeaderPosition,&destination);
    } else {
      spindump_analyze_getsource(packet,ipVersion,ipHeaderPosition,&destination);
      spindump_analyze_getdestination(packet,ipVersion,ipHeaderPosition,&source);
    }

    //
    // Look for existing connection
    //

    struct spindump_connection* connection =
      spindump_connections_searchconnection_icmp(&source,
                                                 &destination,
                                                 ICMP6_ECHO_REQUEST,
                                                 peerId,
                                                 state->table);

    //
    // If not found, create a new one
    //

    if (connection == 0) {
      if (peerType == ICMP6_ECHO_REPLY) {
        *p_connection = 0;
        return;
      } else {
        connection = spindump_connections_newconnection_icmp(&source,
                                                             &destination,
                                                             peerType,
                                                             peerId,
                                                             &packet->timestamp,
                                                             state->table);
        if (connection == 0) {
          *p_connection = 0;
          return;
        }
        new = 1;
        state->stats->connections++;
        state->stats->connectionsIcmp++;
      }
    }

    //
    // Mark the reception of a packet in the connection
    //

    if (peerType == ICMP6_ECHO_REPLY) {

      if (connection->state == spindump_connection_state_establishing) {
        spindump_connections_changestate(state,packet,timestamp,connection,spindump_connection_state_established);
      }
      
      spindump_deepdeepdebugf("looking for ICMPv6 SEQ match of %u",
                              peerSeq);
      const struct timeval* ackto =
        spindump_messageidtracker_ackto(&connection->u.icmp.side1Seqs,peerSeq);
      
      if (ackto != 0) {
        spindump_deepdeepdebugf("found ackto for sequence %u", peerSeq);
        spindump_connections_newrttmeasurement(state,
                                               packet,
                                               connection,
                                               ipPacketLength,
                                               1,
                                               0,
                                               ackto,
                                               &packet->timestamp,
                                               "ICMPv6 ECHO reply");
      } else {
        spindump_deepdeepdebugf("did not find ackto for sequence %u", peerSeq);
      }

      fromResponder = 1;

    } else {
      
      spindump_messageidtracker_add(&connection->u.icmp.side1Seqs,&packet->timestamp,peerSeq);
      fromResponder = 0;
      
    }

    //
    // Call some handlers based on what happened here, if needed
    //

    if (new) {
      spindump_analyze_process_handlers(state,
                                        spindump_analyze_event_newconnection,
                                        timestamp,
                                        fromResponder,
                                        ipPacketLength,
                                        packet,
                                        connection);
    }

    //
    // Update statistics
    //

    spindump_analyze_process_pakstats(state,
                                      connection,
                                      timestamp,
                                      fromResponder,
                                      packet,
                                      ipPacketLength,
                                      ecnFlags);

    //
    // Done. Return connection information to caller.
    //

    *p_connection = connection;

  } else {

    *p_connection = 0;

  }

}
