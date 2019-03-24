
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

#include "spindump_util.h"
#include "spindump_connections.h"
#include "spindump_analyze.h"
#include "spindump_analyze_quic.h"
#include "spindump_analyze_quic_parser.h"
#include "spindump_spin.h"

//
// Actual code --------------------------------------------------------------------------------
//

//
// This is the main function to process an incoming QUIC packet, parse
// the packet as much as we can and process it appropriately. The
// function sets the p_connection output parameter to the connection
// that this packet belongs to (and possibly creates this connection
// if the packet is the first in a flow, e.g., for QUIC initial
// packets).
//
// It is assumed that prior modules, e.g., the capture module or the
// UDP analyzer module, have filled in the fields inside the packet
// structure.
//

void
spindump_analyze_process_quic(struct spindump_analyze* state,
			      struct spindump_packet* packet,
			      unsigned int ipHeaderPosition,
			      unsigned int ipHeaderSize,
			      uint8_t ipVersion,
						uint8_t ecnFlags,
			      unsigned int ipPacketLength,
			      unsigned int udpHeaderPosition,
			      unsigned int udpLength,
			      unsigned int remainingCaplen,
			      struct spindump_connection** p_connection) {

  //
  // Some checks first
  //

  spindump_assert(state != 0);
  spindump_assert(packet != 0);
  spindump_assert(spindump_packet_isvalid(packet));
  spindump_assert(ipVersion == 4 || ipVersion == 6);
  spindump_assert(udpHeaderPosition > ipHeaderPosition);
  spindump_assert(p_connection != 0);

  //
  // Find out some information about the packet
  //

  struct spindump_udp udp;
  spindump_protocols_udp_header_decode(packet->contents + udpHeaderPosition,&udp);
  const unsigned char* udpPayload = packet->contents + udpHeaderPosition + spindump_udp_header_size;
  unsigned int size_udppayload = packet->etherlen - udpHeaderPosition - spindump_udp_header_size;
  struct spindump_connection* connection = 0;
  spindump_address source;
  spindump_address destination;
  spindump_analyze_getsource(packet,ipVersion,ipHeaderPosition,&source);
  spindump_analyze_getdestination(packet,ipVersion,ipHeaderPosition,&destination);
  uint16_t side1port = udp.uh_sport;
  uint16_t side2port = udp.uh_dport;
  int fromResponder;
  int new = 0;

  //
  // Increase statistics because the capturer cannot recognise QUIC
  // packets
  //

  state->stats->receivedQuic++;

  //
  // Debugs
  //

  spindump_debugf("saw QUIC packet from %s (ports %u:%u) payload = %02x%02x%02x",
		  spindump_address_tostring(&source), side1port, side2port,
		  udpPayload[0], udpPayload[1], udpPayload[2]);

  //
  // Attempt to parse the packet
  //

  int hasVersion = 0;
  int mayHaveSpinBit = 0;
  uint32_t quicVersion;
  int destinationCidLengthKnown;
  struct spindump_quic_connectionid destinationCid;
  int sourceCidPresent;
  struct spindump_quic_connectionid sourceCid;
  enum spindump_quic_message_type type;

  if (!spindump_analyze_quic_parser_parse(udpPayload,
					  size_udppayload,
					  remainingCaplen - spindump_udp_header_size,
					  &hasVersion,
					  &quicVersion,
					  &mayHaveSpinBit,
					  &destinationCidLengthKnown,
					  &destinationCid,
					  &sourceCidPresent,
					  &sourceCid,
					  &type,
					  state->stats)) {

    //
    // Parsing failed. Bail out.
    //

    *p_connection = 0;
    return;

  }

  //
  // But if parsing succeeded, then look for existing connection based
  // on the outer 5-tuple (UDP, source and destination addresses and
  // ports).
  //

  connection = spindump_connections_searchconnection_quic_5tuple_either(&source,
									&destination,
									side1port,
									side2port,
									state->table,
									&fromResponder);

  //
  // If not found, and we know the CIDs, search based on them instead.
  //

  if (connection == 0 && destinationCidLengthKnown && sourceCidPresent) {

    connection = spindump_connections_searchconnection_quic_cids_either(&destinationCid,
									&sourceCid,
									state->table,
									&fromResponder);
  }

  //
  // If not found, and we know the destination CID, search based on it
  // instead (as the source CID may have changed during the QUIC
  // initial message exchange).
  //

  if (connection == 0 && destinationCidLengthKnown) {

    connection = spindump_connections_searchconnection_quic_destcid(&destinationCid,
								    state->table);
    if (connection != 0) fromResponder = 1;
  }

  //
  // If not found, search based on the partially known destination CID
  //

  if (connection == 0 && !destinationCidLengthKnown) {

    connection = spindump_connections_searchconnection_quic_partialcid_either(&destinationCid.id[0],
									      state->table,
									      &fromResponder);
  }

  //
  // If finally not found, create a new one
  //

  if (connection == 0) {

    if (destinationCidLengthKnown && sourceCidPresent) {
      connection = spindump_connections_newconnection_quic_5tupleandcids(&source,
									 &destination,
									 side1port,
									 side2port,
									 &destinationCid,
									 &sourceCid,
									 &packet->timestamp,
									 state->table);
    } else {
      connection = spindump_connections_newconnection_quic_5tuple(&source,
								  &destination,
								  side1port,
								  side2port,
								  &packet->timestamp,
								  state->table);
    }

    if (connection == 0) {
      *p_connection = 0;
      return;
    }

    connection->u.quic.version =
      connection->u.quic.originalVersion = quicVersion;
    spindump_debugf("initialized QUIC connection %u state to ESTABLISHING, version %08x", connection->id, quicVersion);
    fromResponder = 0;
    new = 1;

    state->stats->connections++;
    state->stats->connectionsQuic++;

  }

  //
  // Look at the version. Update if different.
  //

  if (hasVersion && connection->u.quic.version != quicVersion) {
    spindump_debugf("re-setting QUIC connection %u version to %08x", connection->id, quicVersion);
    connection->u.quic.version = quicVersion;
  }

  //
  // Look at the state. If the connection is establishing, and we have
  // a packet from the responder, and that packet is type initial,
  // then we can move the state to established. Plus we also need to record
  // the latest sent negotiation/initial packet from the initiator, etc.
  //

  if (connection->state == spindump_connection_state_establishing) {

    //
    // Remember the latest time a packet from the initiator or responder was sent
    //

    if (fromResponder) {
      connection->u.quic.side2initialResponsePacket = packet->timestamp;
    } else {
      connection->u.quic.side1initialPacket = packet->timestamp;
    }

    //
    // Check for a state update
    //

    if (fromResponder && type == spindump_quic_message_type_initial) {

      spindump_connections_changestate(state,packet,connection,spindump_connection_state_established);
      spindump_debugf("moved QUIC connection %u state to ESTABLISHED", connection->id);

    }

    //
    // See if we can update RTT based on the initial packet
    // exchange. This can happen both when the responder responds to
    // an INITIAL message with another INITIAL (or VERSION
    // NEGOTIATION) message. Or when the initiator responds with an
    // INITIAL message after having seen a VERSION NEGOTIATION message
    // from the responder.
    //

    if (fromResponder &&
	(type == spindump_quic_message_type_initial ||
	 type == spindump_quic_message_type_versionnegotiation)) {

      connection->u.quic.initialRightRTT =
	spindump_connections_newrttmeasurement(state,
					       packet,
					       connection,
					       1,
								 0,
					       &connection->u.quic.side1initialPacket,
					       &connection->u.quic.side2initialResponsePacket,
					       "initial QUIC message from responder");

    }

    if (!fromResponder &&
	!spindump_iszerotime(&connection->u.quic.side2initialResponsePacket) &&
	type == spindump_quic_message_type_initial) {

      connection->u.quic.initialLeftRTT =
	spindump_connections_newrttmeasurement(state,
					       packet,
					       connection,
					       0,
								 0,
					       &connection->u.quic.side2initialResponsePacket,
					       &connection->u.quic.side1initialPacket,
					       "initial QUIC message re-send from initiator");

    }

  }

  //
  // If we know the CIDs from the QUIC packet, and they differ from
  // the ones in the current connection, update them.
  //

  if (destinationCidLengthKnown) {

    if (fromResponder) {

      if (!spindump_analyze_quic_quicidequal(&destinationCid,&connection->u.quic.peer1ConnectionID)) {

	connection->u.quic.peer1ConnectionID = destinationCid;
	spindump_deepdebugf("changed peer 1 connection id to %s",
			    spindump_connection_quicconnectionid_tostring(&connection->u.quic.peer1ConnectionID));

      }

    }

  }

  if (sourceCidPresent) {

    if (fromResponder) {

      if (!spindump_analyze_quic_quicidequal(&sourceCid,&connection->u.quic.peer2ConnectionID)) {

	connection->u.quic.peer2ConnectionID = sourceCid;
	spindump_deepdebugf("changed peer 2 connection id to %s",
			    spindump_connection_quicconnectionid_tostring(&connection->u.quic.peer2ConnectionID));

      }

    }

  }

  //
  // Call some handlers based on what happened here, if needed
  //

  if (new) {
    spindump_analyze_process_handlers(state,spindump_analyze_event_newconnection,packet,connection);
  }

  //
  // Determine if there's a spin bit in the packet, and record its
  // value.
  //

  int spin;
  spindump_deepdebugf("checking for the spin bit (may have = %u)", mayHaveSpinBit);
  if (spindump_analyze_quic_parser_getspinbit(udpPayload,
					      size_udppayload,
					      mayHaveSpinBit,
					      connection->u.quic.version,
					      fromResponder,
					      &spin)) {
    if (fromResponder) {
      spindump_spintracker_observespinandcalculatertt(state,
						      packet,
						      connection,
						      &connection->u.quic.spinFromPeer2to1,
						      &connection->u.quic.spinFromPeer1to2,
						      &packet->timestamp,
						      spin,
						      fromResponder);
    } else {
      spindump_spintracker_observespinandcalculatertt(state,
						      packet,
						      connection,
						      &connection->u.quic.spinFromPeer1to2,
						      &connection->u.quic.spinFromPeer2to1,
						      &packet->timestamp,
						      spin,
						      fromResponder);
    }
  }

  //
  // Update stats.
  //

  spindump_analyze_process_pakstats(state,connection,fromResponder,packet,ipPacketLength,ecnFlags);

  //
  // Done. Update stats and tell caller which connection we used.
  //

  *p_connection = connection;
}
