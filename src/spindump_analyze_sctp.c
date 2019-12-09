
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
//  SPINDUMP (C) 2019 BY ERICSSON AB
//  AUTHOR: MAKSIM PROSHIN, DENIS SCHERBAKOV
//
//

//
// Includes -----------------------------------------------------------------------------------
//

#include <string.h>
#include "spindump_util.h"
#include "spindump_connections.h"
#include "spindump_analyze.h"
#include "spindump_analyze_sctp.h"
#include "spindump_analyze_sctp_parser.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static void
spindump_analyze_process_sctp_marktsnsent(struct spindump_connection* connection,
                                          int fromResponder,
                                          sctp_tsn tsn,
                                          struct timeval* t);
static void
spindump_analyze_process_sctp_markackreceived(struct spindump_analyze* state,
                                              struct spindump_packet* packet,
                                              struct spindump_connection* connection,
                                              int fromResponder,
                                              sctp_tsn ackTsn,
                                              struct timeval* t);

//
// Actual code --------------------------------------------------------------------------------
//

//
// Mark the sending of a TSN from one of the peers.
//
// If fromResponder = 1, the sending party is the server of the
// connection, if fromResponder = 0, it is the client. Based on
// this TSN one can track RTT later when an ACK is received.
//
static void
spindump_analyze_process_sctp_marktsnsent(struct spindump_connection* connection,
                                          int fromResponder,
                                          sctp_tsn tsn,
                                          struct timeval* t) {

  spindump_assert(connection != 0);
  spindump_assert(spindump_isbool(fromResponder));
  spindump_assert(t != 0);
  if (fromResponder) {
    spindump_tsntracker_add(&connection->u.sctp.side2Seqs,t,tsn);
    spindump_deepdebugf("responder sent TSN %u", tsn);
  } else {
    spindump_tsntracker_add(&connection->u.sctp.side1Seqs,t,tsn);
    spindump_deepdebugf("initiator sent TSN %u", tsn);
  }
}

//
// Mark the reception of a TSN number ACK from one of the peers.
//
// If fromResponder = 1, the ACKing party is the server of the
// connection, if fromResponder = 0, it is the client. Seq is the
// sequence number from the other party that is being acked. Based on
// this sequence one can track RTT.
//
static void
spindump_analyze_process_sctp_markackreceived(struct spindump_analyze* state,
                                              struct spindump_packet* packet,
                                              struct spindump_connection* connection,
                                              int fromResponder,
                                              sctp_tsn ackTsn,
                                              struct timeval* t) {

  struct timeval* ackto;
  sctp_tsn sentTsn;
  spindump_assert(state != 0);
  spindump_assert(connection != 0);
  spindump_assert(spindump_packet_isvalid(packet));
  spindump_assert(spindump_isbool(fromResponder));
  spindump_assert(t != 0);

  if (fromResponder) {
    ackto = spindump_tsntracker_ackto(&connection->u.sctp.side1Seqs,ackTsn,&sentTsn);
  } else {
    ackto = spindump_tsntracker_ackto(&connection->u.sctp.side2Seqs,ackTsn,&sentTsn);
  }

  spindump_deepdebugf("spindump_analyze_process_sctp_markackreceived, fromResponder: %d", fromResponder);

  if (ackto != 0) {

      unsigned long long diff = spindump_timediffinusecs(t,ackto);
      spindump_deepdebugf("the SACK %u refers to SCTP message (TSN=%u) that came %llu ms earlier",
                          ackTsn,
                          sentTsn,
                          diff / 1000);

      spindump_connections_newrttmeasurement(state,
                                             packet,
                                             connection,
                                             fromResponder,
                                             0,
                                             ackto,
                                             t,
                                             "SCTP SACK");

  } else {

      spindump_deepdebugf("did not find the outgoing DATA message that responder SACK %u refers to", ackTsn);

  }

}

// TODO: Maksim Proshin: fix the function
//
// This is the main function to process an incoming SCTP packet, parse
// the packet as much as we can and process it appropriately. The
// function sets the p_connection output parameter to the connection
// that this packet belongs to (and possibly creates this connection
// if the packet is the first in a flow, e.g., for SCTP INIT
// packets).
//
// It is assumed that prior modules, i.e., the capture module has
// filled in the relevant fields in the packet structure "packet"
// correctly.
//
void
spindump_analyze_process_sctp(struct spindump_analyze* state,
                             struct spindump_packet* packet,
                             unsigned int ipHeaderPosition,
                             unsigned int ipHeaderSize,
                             uint8_t ipVersion,
                             uint8_t ecnFlags,
                             unsigned int ipPacketLength,
                             unsigned int sctpHeaderPosition,
                             unsigned int sctpLength,
                             unsigned int remainingCaplen,
                             struct spindump_connection** p_connection) {
  //
  // Some checks first
  //

  spindump_assert(state != 0);
  spindump_assert(packet != 0);
  spindump_assert(spindump_packet_isvalid(packet));
  spindump_assert(ipVersion == 4 || ipVersion == 6);
  spindump_assert(sctpHeaderPosition > ipHeaderPosition);
  spindump_assert(p_connection != 0);

  //
  // Parse the header
  //

  state->stats->receivedSctp++;
  if (sctpLength < (spindump_sctp_packet_header_length + spindump_sctp_chunk_header_length) ||
    remainingCaplen < (spindump_sctp_packet_header_length + spindump_sctp_chunk_header_length) ) {
    state->stats->notEnoughPacketForSctpHdr++;
    spindump_warnf("not enough payload bytes for a SCTP header", sctpLength);
    *p_connection = 0;
    return;
  }
  struct spindump_sctp_packet_header sctp;
  spindump_protocols_sctp_header_decode(packet->contents + sctpHeaderPosition,&sctp);
  spindump_deepdebugf("sctp header: sport = %u", sctp.sh_sport);
  spindump_deepdebugf("sctp header: dport = %u", sctp.sh_dport);
  spindump_deepdebugf("sctp header: vtag = %u", sctp.sh_vtag);
  spindump_deepdebugf("sctp header: checksum = %u", sctp.sh_checksum);

  //
  // Check what chunks are present in packet,
  // create, update or delete the connection accordingly
  //
  struct spindump_sctp_chunk_header sctp_chunk_header;
  spindump_protocols_sctp_chunk_header_parse(
      packet->contents + sctpHeaderPosition + spindump_sctp_packet_header_length, &sctp_chunk_header);
  spindump_deepdebugf("sctp chunk: type = %u", sctp_chunk_header.ch_type);
  spindump_deepdebugf("sctp chunk: flags = %u", sctp_chunk_header.ch_flags);
  spindump_deepdebugf("sctp chunk: length = %u", sctp_chunk_header.ch_length);

  struct spindump_connection* connection = 0;
  spindump_address source;
  spindump_address destination;
  spindump_analyze_getsource(packet,ipVersion,ipHeaderPosition,&source);
  spindump_analyze_getdestination(packet,ipVersion,ipHeaderPosition,&destination);
  uint16_t side1port = sctp.sh_sport;
  uint16_t side2port = sctp.sh_dport;
  int fromResponder;  // to be used in spindump_connections_searchconnection_sctp_either()

  //
  // Debugs
  //

  spindump_debugf("saw packet from %s (ports %u:%u)",
                  spindump_address_tostring(&source), side1port, side2port);

  // search the connection
  connection = spindump_connections_searchconnection_sctp_either(&source,
                                                                &destination,
                                                                side1port,
                                                                side2port,
                                                                state->table,
                                                                &fromResponder);
  if (connection != 0) {
    // Add this packet to bandwidth stats for connection
    spindump_analyze_process_pakstats(state,connection,0,packet,ipPacketLength,ecnFlags);
    *p_connection = connection;
  }

  switch (sctp_chunk_header.ch_type) {
    case spindump_sctp_chunk_type_init:
      // INIT
      
      // parse the chunk
      ;  // TODO: Maksim Proshin: fix this trick to avoid a C-lang error about the label 
      struct spindump_sctp_chunk_init sctp_chunk_init;
      spindump_protocols_sctp_chunk_init_parse(
          packet->contents + sctpHeaderPosition + spindump_sctp_packet_header_length, 
          &sctp_chunk_init);

      //
      // If connection not found, create a new one
      //
      if (connection == 0) {
        connection = spindump_connections_newconnection_sctp(&source,
                                                          &destination,
                                                          side1port,
                                                          side2port,
                                                          sctp_chunk_init.initiateTag,
                                                          &packet->timestamp,
                                                          state->table);

        if (connection == 0) {
          *p_connection = 0;
          return;
        }

        state->stats->connections++;
        state->stats->connectionsSctp++;

        // Bandwidth stat has not updated yet
        spindump_analyze_process_pakstats(state,connection,0,packet,ipPacketLength,ecnFlags);
      } else {
          // update side1Vtag for the existing connection if INIT was retransmitted
          if (fromResponder == 0)
          {
            connection->u.sctp.side1Vtag = sctp_chunk_init.initiateTag;
          }
          // TODO: Maksim Proshin: what if INIT has been received from the other side
      }

      break; // INIT
    case spindump_sctp_chunk_type_init_ack:
      // INIT ACK

      //
      // If connection found, parse the chunk, update side2.vTag and stats. If not found, ignore.
      //

      if (connection != 0) {
      
        struct spindump_sctp_chunk_init_ack sctp_chunk_init_ack;
        spindump_protocols_sctp_chunk_init_ack_parse(
          packet->contents + sctpHeaderPosition + spindump_sctp_packet_header_length, 
          &sctp_chunk_init_ack);

        connection->u.sctp.side2Vtag = sctp_chunk_init_ack.initiateTag;

      } else {

        state->stats->unknownSctpConnection++;
        *p_connection = 0;
        return;

      }
      break;  // INIT ACK
    case spindump_sctp_chunk_type_cookie_echo:
      // COOKIE ECHO
      
      //
      // If connection found, change state to established. If not found, ignore.
      //

      if (connection != 0) {

        if (connection->state == spindump_connection_state_establishing) {
          spindump_connections_changestate(state,
                                           packet,
                                           connection,
                                           spindump_connection_state_established);
        }

      } else {

        state->stats->unknownSctpConnection++;
        *p_connection = 0;
        return;

      }
      break;  // COOKIE ECHO
    case spindump_sctp_chunk_type_cookie_ack:
      // COOKIE ACK

      //
      // If connection not found, ignore.
      //

      if (connection == 0) {

        state->stats->unknownSctpConnection++;
        *p_connection = 0;
        return;

      }
      break;  // COOKIE ACK
    case spindump_sctp_chunk_type_shutdown:
      // SHUTDOWN

      //
      // If connection found, change state to closing. If not found, ignore.
      //

      if (connection != 0) {

        if (connection->state == spindump_connection_state_established) {
          spindump_connections_changestate(state,
                                          packet,
                                          connection,
                                          spindump_connection_state_closing);
        }

      } else {

        state->stats->unknownSctpConnection++;
        *p_connection = 0;
        return;

      }
      break; // SHUTDOWN
    case spindump_sctp_chunk_type_shutdown_complete:
      // SHUTDOWN_COMPLETE

      //
      // If connection found, change state to closed. If not found, ignore.
      //

      if (connection != 0) {

        if (connection->state == spindump_connection_state_closing) {
          spindump_connections_changestate(state,
                                          packet,
                                          connection,
                                          spindump_connection_state_closed);
          spindump_connections_markconnectiondeleted(connection);
        }

      } else {

        state->stats->unknownSctpConnection++;
        *p_connection = 0;
        return;

      }
      break; // SHUTDOWN_COMPLETE
    case spindump_sctp_chunk_type_shutdown_ack:
      // SHUTDOWN_ACK

      //
      // If connection found, change state to closed. If not found, ignore.
      //

      if (connection != 0) {

        if (connection->state != spindump_connection_state_closed) {
          spindump_connections_changestate(state,
                                          packet,
                                          connection,
                                          spindump_connection_state_closed);
          spindump_connections_markconnectiondeleted(connection);
        }

      } else {

        state->stats->unknownSctpConnection++;
        *p_connection = 0;
        return;

      }
      break; // SHUTDOWN_ACK
    case spindump_sctp_chunk_type_abort:
      // ABORT

      //
      // If connection found, change state to closed. If not found, ignore.
      //

      if (connection != 0) {

        if (connection->state != spindump_connection_state_closed) {
          spindump_connections_changestate(state,
                                          packet,
                                          connection,
                                          spindump_connection_state_closed);
          spindump_connections_markconnectiondeleted(connection);
        }

      } else {

        state->stats->unknownSctpConnection++;
        *p_connection = 0;
        return;

      }
      break; // ABORT
    case spindump_sctp_chunk_type_data:
      // DATA

      //
      // If connection found, remember TSN. If not found, ignore.
      //

      if (connection != 0) {
        ;  // TODO: Maksim Proshin: fix this trick to avoid a C-lang error about the label 
        struct spindump_sctp_chunk_data sctp_chunk_data;
        spindump_protocols_sctp_chunk_data_parse(
            packet->contents + sctpHeaderPosition + spindump_sctp_packet_header_length, 
            &sctp_chunk_data);

        spindump_analyze_process_sctp_marktsnsent(connection,
                                                fromResponder,
                                                sctp_chunk_data.tsn,
                                                &packet->timestamp);

      } else {

        state->stats->unknownSctpConnection++;
        *p_connection = 0;
        return;

      }
      break; // DATA
    case spindump_sctp_chunk_type_sack:
      // SACK

      //
      // If connection found, fetch cumulative TSN Ack. If not found, ignore.
      //

      if (connection != 0) {
        ;  // TODO: Maksim Proshin: fix this trick to avoid a C-lang error about the label 
        struct spindump_sctp_chunk_sack sctp_chunk_sack;
        spindump_protocols_sctp_chunk_sack_parse(
            packet->contents + sctpHeaderPosition + spindump_sctp_packet_header_length, 
            &sctp_chunk_sack);

        spindump_analyze_process_sctp_markackreceived(state,
                                                      packet,
                                                      connection,
                                                      fromResponder,
                                                      sctp_chunk_sack.cumulativeTsnAck,
                                                      &packet->timestamp);

      } else {

        state->stats->unknownSctpConnection++;
        *p_connection = 0;
        return;

      }
      break; // SACK
    case spindump_sctp_chunk_type_heartbeat:
      // HEARTBEAT (HB) 

      //
      // If found, calculate RTT. If not found, ignore.
      //

      if (connection != 0) {
      
        // ignore if not in Established state
        if (connection->state != spindump_connection_state_established) {

          // remember side and timestamp
          if (fromResponder == 0) {
            connection->u.sctp.side1HbCnt += 1;
            connection->u.sctp.side1hbTime = packet->timestamp;
          }
          else {
              
            connection->u.sctp.side2HbCnt += 1;
            connection->u.sctp.side2hbTime = packet->timestamp;
          }
        }

      } else {

        state->stats->unknownSctpConnection++;
        *p_connection = 0;
        return;

      }
      break; // HB
    case spindump_sctp_chunk_type_heartbeat_ack:
      // HEARTBEAT ACK (HB ACK) 

      //
      // If found, TODO. If not found, ignore.
      //

      if (connection != 0) {

      } else {

        state->stats->unknownSctpConnection++;
        *p_connection = 0;
        return;

      } 
      break;
  }

  // TODO: add additional event handler invocation below
  return;
}