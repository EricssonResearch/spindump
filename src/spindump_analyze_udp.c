
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
#include "spindump_analyze_udp.h"
#include "spindump_analyze_dns.h"
#include "spindump_analyze_coap.h"
#include "spindump_analyze_quic.h"
#include "spindump_analyze_quic_parser.h"

//
// Actual code --------------------------------------------------------------------------------
//

//
// This is the main function to process an incoming UDP packet, parse
// the packet as much as we can and process it appropriately. The
// function sets the p_connection output parameter to the connection
// that this packet belongs to (and possibly creates this connection
// if the packet is the first in a flow).
//
// It is assumed that prior modules, i.e., the capture module has
// filled in the relevant header pointers in the packet structure
// "packet" correctly. For instance, the packet->udp pointer needs to
// have already been set.
//
// Note that this function for UDP processing branches out immediately
// to some other protocol analyzers for DNS, COAP, and QUIC packets,
// if the UDP flow looks heuristically like one for those
// protocols. This determination is made based on port numbers and the
// ability to perform a rudimentary parsing of the relevant header.
//

void
spindump_analyze_process_udp(struct spindump_analyze* state,
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
  // Verify that the UDP header is valid
  //

  state->stats->receivedUdp++;
  if (udpLength < spindump_udp_header_size ||
      remainingCaplen < spindump_udp_header_size) {
    state->stats->notEnoughPacketForUdpHdr++;
    spindump_warnf("not enough payload bytes for an UDP header", udpLength);
    *p_connection = 0;
    return;
  }

  const struct spindump_udp* udp = (const struct spindump_udp*)(packet->contents + udpHeaderPosition);
  unsigned int udpHeaderSize = spindump_udp_header_size;
  spindump_deepdebugf("udp header: sport = %u", htons(udp->uh_sport));
  spindump_deepdebugf("udp header: dport = %u", htons(udp->uh_dport));
  spindump_deepdebugf("udp header: len = %u", htons(udp->uh_len));
  spindump_deepdebugf("udp header: csum = %x", htons(udp->uh_csum));

  const unsigned char* payload = packet->contents + udpHeaderPosition + udpHeaderSize;
  unsigned int size_udppayload = spindump_max(ntohs(udp->uh_len),udpLength) - udpHeaderSize;

  spindump_debugf("received an IPv%u UDP packet of %u bytes (eth %u ip %u udp %u) size_payload = %u payload = %02x%02x%02x...",
		  ipVersion,
		  packet->etherlen,
		  ipHeaderPosition,
		  ipHeaderSize,
		  udpHeaderSize,
		  size_udppayload,
		  (unsigned int)payload[0],
		  (unsigned int)payload[1],
		  (unsigned int)payload[2]);

  //
  // Find out some information about the packet
  //

  struct spindump_connection* connection = 0;
  spindump_address source;
  spindump_address destination;
  spindump_analyze_getsource(packet,ipVersion,ipHeaderPosition,&source);
  spindump_analyze_getdestination(packet,ipVersion,ipHeaderPosition,&destination);
  uint16_t side1port = ntohs(udp->uh_sport);
  uint16_t side2port = ntohs(udp->uh_dport);
  int fromResponder;
  int new = 0;

  //
  // Debugs
  //

  spindump_debugf("saw UDP packet from %s (ports %u:%u) payload = %02x%02x%02x... (payload length %u)",
		  spindump_address_tostring(&source), side1port, side2port,
		  payload[0], payload[1], payload[2],
		  size_udppayload);

  //
  // If the packet uses DNS ports, hand control over to the DNS
  // module.
  //

  if (spindump_analyze_dns_isprobablednspacket(payload,
					       size_udppayload,
					       side1port,
					       side2port)) {
    spindump_analyze_process_dns(state,
				 packet,
				 ipHeaderPosition,
				 ipHeaderSize,
				 ipVersion,
				 ecnFlags,
				 ipPacketLength,
				 ipHeaderPosition + ipHeaderSize,
				 udpLength,
				 remainingCaplen,
				 p_connection);
    return;
  }

  //
  // If the packet uses DNS ports, hand control over to the DNS
  // module.
  //

  int dtls;
  if (spindump_analyze_coap_isprobablecoappacket(payload,
						 size_udppayload,
						 side1port,
						 side2port,
						 &dtls)) {
    spindump_analyze_process_coap(state,
				  packet,
				  ipHeaderPosition,
				  ipHeaderSize,
				  ipVersion,
					ecnFlags,
				  ipPacketLength,
				  ipHeaderPosition + ipHeaderSize,
				  udpLength,
				  remainingCaplen,
				  dtls,
				  p_connection);
    return;
  }

  //
  // If the packet uses web ports or is a registered QUIC connection,
  // hand control over to the QUIC module.
  //

  if (spindump_analyze_quic_parser_isprobablequickpacket(payload,
							 size_udppayload,
							 side1port,
							 side2port)) {
    spindump_analyze_process_quic(state,
				  packet,
				  ipHeaderPosition,
				  ipHeaderSize,
				  ipVersion,
					ecnFlags,
				  ipPacketLength,
				  udpHeaderPosition,
				  udpLength,
				  remainingCaplen,
				  p_connection);
    return;
  }

  connection = spindump_connections_searchconnection_quic_5tuple_either(&source,
									&destination,
									side1port,
									side2port,
									state->table,
									&fromResponder);
  if (connection != 0) {
    spindump_analyze_process_quic(state,
				  packet,
				  ipHeaderPosition,
				  ipHeaderSize,
				  ipVersion,
					ecnFlags,
				  ipPacketLength,
				  udpHeaderPosition,
				  udpLength,
				  remainingCaplen,
				  p_connection);
    return;
  }

  //
  // Then, look for existing connection
  //

  connection = spindump_connections_searchconnection_udp_either(&source,
								&destination,
								side1port,
								side2port,
								state->table,
								&fromResponder);

  //
  // If not found, create a new one
  //

  if (connection == 0) {

    connection = spindump_connections_newconnection_udp(&source,
							&destination,
							side1port,
							side2port,
							&packet->timestamp,
							state->table);

    fromResponder = 0;
    new = 1;

    if (connection == 0) {
      *p_connection = 0;
      return;
    }

    state->stats->connections++;
    state->stats->connectionsUdp++;

  }

  //
  // Call some handlers based on what happened here, if needed
  //

  if (new) {
    spindump_analyze_process_handlers(state,spindump_analyze_event_newconnection,packet,connection);
  }

  //
  // If we've seen a response from the responder, mark state as
  // established (even if we don't really know what's going on in the
  // actual application, as this is UDP).
  //

  if (fromResponder && connection->state == spindump_connection_state_establishing) {
    spindump_connections_changestate(state,packet,connection,spindump_connection_state_established);
  }

  //
  // Update stats
  //

  spindump_analyze_process_pakstats(state,connection,fromResponder,packet,ipPacketLength,ecnFlags);

  //
  // Done. Inform caller of the connection.
  //

  *p_connection = connection;

}
