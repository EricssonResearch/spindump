
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

//
// Actual code --------------------------------------------------------------------------------
//

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

  switch (sctp_chunk_header.ch_type) {
    case spindump_sctp_chunk_type_init:
      // INIT
      
      // parse the chunk
      ;  // TODO: Maksim Proshin: fix this trick to avoid a C-lang error about the label 
      struct spindump_sctp_chunk_init sctp_chunk_init;
      spindump_protocols_sctp_chunk_init_parse(
          packet->contents + sctpHeaderPosition + spindump_sctp_packet_header_length, 
	  &sctp_chunk_init);
        
      // search the connection
      // it can be created from any side so we need to find it in both directions
      connection = spindump_connections_searchconnection_sctp_either(&source,
                                                                     &destination,
                                                                     side1port,
                                                                     side2port,
                                                                     state->table,
								     &fromResponder);
      //
      // If not found, create a new one
      //
      if (connection == 0) {
        connection = spindump_connections_newconnection_sctp(&source,
                                                          &destination,
                                                          side1port,
                                                          side2port,
							  sctp_chunk_init.initiateTag,
                                                          &packet->timestamp,
                                                          state->table);
      } 
      else {
          // update side1Vtag for the existing connection if INIT was retransmitted
	  if (fromResponder == 0) {
	      connection->u.sctp.side1Vtag = sctp_chunk_init.initiateTag;
	  }
	  // TODO: Maksim Proshin: what if INIT has been received from the other side
      }

      spindump_analyze_process_pakstats(state,connection,0,packet,ipPacketLength,ecnFlags);

      *p_connection = connection;
      break; // INIT
    case spindump_sctp_chunk_type_init_ack:
      // INIT ACK
      
      //
      // First, look for existing connection
      //

      connection = spindump_connections_searchconnection_sctp_either(&source,
                                                                     &destination,
                                                                     side1port,
                                                                     side2port,
                                                                     state->table,
								     &fromResponder);
      //
      // If found, parse the chunk, update side2.vTag and stats. If not found, ignore.
      //

      if (connection != 0) {
      
        struct spindump_sctp_chunk_init_ack sctp_chunk_init_ack;
        spindump_protocols_sctp_chunk_init_ack_parse(
          packet->contents + sctpHeaderPosition + spindump_sctp_packet_header_length, 
	  &sctp_chunk_init_ack);

        connection->u.sctp.side2Vtag = sctp_chunk_init_ack.initiateTag;
	
	spindump_analyze_process_pakstats(state,connection,1,packet,ipPacketLength,ecnFlags);
        *p_connection = connection;

      } else {

        state->stats->unknownSctpConnection++;
        *p_connection = 0;
        return;
      }
      break;  // INIT ACK
    case spindump_sctp_chunk_type_cookie_echo:
      // COOKIE ECHO
      
      //
      // First, look for existing connection
      //

      connection = spindump_connections_searchconnection_sctp_either(&source,
                                                                     &destination,
                                                                     side1port,
                                                                     side2port,
                                                                     state->table,
								     &fromResponder);
      //
      // If found, change state to established. If not found, ignore.
      //

      if (connection != 0) {

        if (connection->state == spindump_connection_state_establishing) {
          spindump_connections_changestate(state,
                                           packet,
                                           connection,
                                           spindump_connection_state_established);
        }

        spindump_analyze_process_pakstats(state,connection,0,packet,ipPacketLength,ecnFlags);
        *p_connection = connection;

      } else {

        state->stats->unknownSctpConnection++;
        *p_connection = 0;
        return;

      }
      break;  // COOKIE ECHO
    case spindump_sctp_chunk_type_cookie_ack:
      // COOKIE ACK
      
      //
      // First, look for existing connection
      //

      connection = spindump_connections_searchconnection_sctp_either(&source,
                                                                     &destination,
                                                                     side1port,
                                                                     side2port,
                                                                     state->table,
								     &fromResponder);
      //
      // If found, update stats. If not found, ignore.
      //

      if (connection != 0) {

        spindump_analyze_process_pakstats(state,connection,1,packet,ipPacketLength,ecnFlags);
        *p_connection = connection;

      } else {

        state->stats->unknownSctpConnection++;
        *p_connection = 0;
        return;

      }
      break;  // COOKIE ACK
    case spindump_sctp_chunk_type_shutdown:
      //
      // First, look for existing connection
      //

      connection = spindump_connections_searchconnection_sctp_either(&source,
                                                                    &destination,
                                                                    side1port,
                                                                    side2port,
                                                                    state->table,
                                                                    &fromResponder);
      //
      // If found, change state to established. If not found, ignore.
      //

      if (connection != 0) {

        if (connection->state == spindump_connection_state_established) {
          spindump_connections_changestate(state,
                                          packet,
                                          connection,
                                          spindump_connection_state_closing);
        }

        spindump_analyze_process_pakstats(state,connection,fromResponder,packet,ipPacketLength,ecnFlags);
        *p_connection = connection;

      } else {

        state->stats->unknownSctpConnection++;
        *p_connection = 0;
        return;

      }
      break;
    case spindump_sctp_chunk_type_shutdown_complete:
      //
      // First, look for existing connection
      //

      connection = spindump_connections_searchconnection_sctp_either(&source,
                                                                    &destination,
                                                                    side1port,
                                                                    side2port,
                                                                    state->table,
                                                                    &fromResponder);
      //
      // If found, change state to established. If not found, ignore.
      //

      if (connection != 0) {

        if (connection->state == spindump_connection_state_closing) {
          spindump_connections_changestate(state,
                                          packet,
                                          connection,
                                          spindump_connection_state_closed);
          spindump_connections_markconnectiondeleted(connection);
        }

        spindump_analyze_process_pakstats(state,connection,fromResponder,packet,ipPacketLength,ecnFlags);
        *p_connection = connection;

      } else {

        state->stats->unknownSctpConnection++;
        *p_connection = 0;
        return;

      }
      break;
    case spindump_sctp_chunk_type_shutdown_ack:
      //
      // First, look for existing connection
      //

      connection = spindump_connections_searchconnection_sctp_either(&source,
                                                                    &destination,
                                                                    side1port,
                                                                    side2port,
                                                                    state->table,
                                                                    &fromResponder);
      //
      // If found, change state to established. If not found, ignore.
      //

      if (connection != 0) {

        if (connection->state != spindump_connection_state_closed) {
          spindump_connections_changestate(state,
                                          packet,
                                          connection,
                                          spindump_connection_state_closed);
          spindump_connections_markconnectiondeleted(connection);
        }

        spindump_analyze_process_pakstats(state,connection,fromResponder,packet,ipPacketLength,ecnFlags);
        *p_connection = connection;

      } else {

        state->stats->unknownSctpConnection++;
        *p_connection = 0;
        return;

      }
      break;
    case spindump_sctp_chunk_type_abort:
      //
      // First, look for existing connection
      //

      connection = spindump_connections_searchconnection_sctp_either(&source,
                                                                    &destination,
                                                                    side1port,
                                                                    side2port,
                                                                    state->table,
                                                                    &fromResponder);
      //
      // If found, change state to established. If not found, ignore.
      //

      if (connection != 0) {

        if (connection->state != spindump_connection_state_closed) {
          spindump_connections_changestate(state,
                                          packet,
                                          connection,
                                          spindump_connection_state_closed);
          spindump_connections_markconnectiondeleted(connection);
        }

        spindump_analyze_process_pakstats(state,connection,fromResponder,packet,ipPacketLength,ecnFlags);
        *p_connection = connection;

      } else {

        state->stats->unknownSctpConnection++;
        *p_connection = 0;
        return;

      }
      break; 
    case spindump_sctp_chunk_type_data:
      // TODO: Denis S: remember TSN for RTT measurement
      break;
    case spindump_sctp_chunk_type_sack:
      // TODO: Denis S: RTT measurement for ack'ed TSN
      break;
  }

  // TODO: remove below
  return;
}
