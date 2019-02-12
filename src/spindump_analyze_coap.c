
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
#include "spindump_util.h"
#include "spindump_protocols.h"
#include "spindump_connections.h"
#include "spindump_analyze.h"
#include "spindump_analyze_udp.h"
#include "spindump_analyze_coap.h"
#include "spindump_analyze_tls_parser.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static void
spindump_analyze_process_coap_dtls(struct spindump_analyze* state,
				   struct spindump_packet* packet,
					 uint8_t ecnFlags,
				   unsigned int ipPacketLength,
				   unsigned int udpLength,
				   unsigned int remainingCaplen,
				   spindump_address* source,
				   spindump_address* destination,
				   uint16_t side1port,
				   uint16_t side2port,
				   const unsigned char* payload,
				   struct spindump_connection** p_connection);
static void
spindump_analyze_process_coap_cleartext(struct spindump_analyze* state,
					struct spindump_packet* packet,
					uint8_t ecnFlags,
					unsigned int ipPacketLength,
					unsigned int udpLength,
					unsigned int remainingCaplen,
					spindump_address* source,
					spindump_address* destination,
					uint16_t side1port,
					uint16_t side2port,
					const unsigned char* payload,
					struct spindump_connection** p_connection);
static void
spindump_analyze_coap_markmidsent(struct spindump_connection* connection,
				  const int fromResponder,
				  const uint16_t mid,
				  const struct timeval* t);
static int
spindump_analyze_coap_markmidreceived(struct spindump_analyze* state,
				      struct spindump_packet* packet,
				      struct spindump_connection* connection,
				      const int fromResponder,
				      const uint16_t mid,
				      const struct timeval* t);
static void
spindump_analyze_coap_markinitialresponsereceived(struct spindump_analyze* state,
						  struct spindump_packet* packet,
						  struct spindump_connection* connection,
						  const int fromResponder,
						  const struct timeval* t);

//
// Actual code --------------------------------------------------------------------------------
//

//
// Look to see if an UDP packet is a likely COAP packet. This check is
// basef on port numbers and the basics of packet format (length
// sufficient etc)
//

int
spindump_analyze_coap_isprobablecoappacket(const unsigned char* payload,
					   unsigned int payload_len,
					   uint16_t sourcePort,
					   uint16_t destPort,
					   int* p_isDtls) {

  //
  // Do ports look like COAP?
  //

  int dtls = 0;
  if (sourcePort == SPINDUMP_COAP_PORT1 || destPort == SPINDUMP_COAP_PORT1) {
    dtls = 0;
  } else if (sourcePort == SPINDUMP_COAP_PORT2 || destPort == SPINDUMP_COAP_PORT2) {
    dtls = 1;
  } else {
    return(0);
  }

  //
  // Does packet format look right?
  //

  if (dtls) {

    if (!spindump_analyze_tls_parser_isprobabletlspacket(payload,payload_len,1)) {
      return(0);
    }

  } else {

    if (payload_len < sizeof(struct spindump_coap)) {
      return(0);
    }

  }

  //
  // Probable COAP packet!
  //

  *p_isDtls = dtls;
  return(1);
}

//
// Mark the sending of a message ID from one of the peers.
//
// If fromResponder = 1, the sending party is the server of the
// connection, if fromResponder = 0, it is the client. Mid is the
// message ID from the other party that is being acked. Based on this,
// one one can track RTT later when a COAP response is sent.
//

static void
spindump_analyze_coap_markmidsent(struct spindump_connection* connection,
				  const int fromResponder,
				  const uint16_t mid,
				  const struct timeval* t) {

  spindump_assert(connection != 0);
  spindump_assert(fromResponder == 0 || fromResponder == 1);
  spindump_assert(t != 0);

  if (fromResponder) {
    spindump_messageidtracker_add(&connection->u.coap.side2MIDs,t,mid);
    spindump_deepdebugf("responder sent MID %u", mid);
  } else {
    spindump_messageidtracker_add(&connection->u.coap.side1MIDs,t,mid);
    spindump_deepdebugf("initiator sent MID %u", mid);
  }
}

//
// Mark the reception of a message ID response from one of the peers.
//
// If fromResponder = 1, the responding party is the server of the
// connection, if fromResponder = 0, it is the client. Mid is the
// message id from the other party that is being acked. Based on this,
// one one can track RTT.
//

static int
spindump_analyze_coap_markmidreceived(struct spindump_analyze* state,
				      struct spindump_packet* packet,
				      struct spindump_connection* connection,
				      const int fromResponder,
				      const uint16_t mid,
				      const struct timeval* t) {

  //
  // Some sanity checks
  //

  spindump_assert(state != 0);
  spindump_assert(packet != 0);
  spindump_assert(spindump_packet_isvalid(packet));
  spindump_assert(connection != 0);
  spindump_assert(spindump_isbool(fromResponder));
  spindump_assert(t != 0);

  //
  // Based on whether this is a response or request, either look for a
  // matching message id in the COAP header, or store the message id
  // for a later match
  //

  const struct timeval* ackto;

  if (fromResponder) {

    ackto = spindump_messageidtracker_ackto(&connection->u.coap.side1MIDs,mid);

    if (ackto != 0) {

      unsigned long long diff = spindump_timediffinusecs(t,ackto);
      spindump_deepdebugf("the responder COAP response %u refers to initiator COAP message that came %llu ms earlier",
			  mid,
			  diff / 1000);
      spindump_connections_newrttmeasurement(state,
					     packet,
					     connection,
					     1,
							 0,
					     ackto,
					     t,
					     "COAP response");
      return(1);

    } else {

      spindump_deepdebugf("did not find the initiator COAP message that responder mid %u refers to", mid);
      return(0);

    }

  } else {

    ackto = spindump_messageidtracker_ackto(&connection->u.coap.side2MIDs,mid);

    if (ackto != 0) {

      unsigned long long diff = spindump_timediffinusecs(t,ackto);
      spindump_deepdebugf("the initiator response MID %u refers to responder COAP message that came %llu ms earlier",
			  mid,
			  diff / 1000);
      spindump_connections_newrttmeasurement(state,
					     packet,
					     connection,
					     0,
							 0,
					     ackto,
					     t,
					     "COAP response");
      return(1);

    } else {

      spindump_deepdebugf("did not find the responder COAP message that initiator mid %u refers to", mid);
      return(0);

    }
  }
}

//
// When an encrypted COAP connection is established, we can see an
// initial RTT in the DTLS establishment packets, but thereafter we
// don't know what's going on. This function marks the initial RTT.
//

static void
spindump_analyze_coap_markinitialresponsereceived(struct spindump_analyze* state,
						  struct spindump_packet* packet,
						  struct spindump_connection* connection,
						  const int fromResponder,
						  const struct timeval* t) {

  //
  // Some sanity checks
  //

  spindump_assert(state != 0);
  spindump_assert(packet != 0);
  spindump_assert(spindump_packet_isvalid(packet));
  spindump_assert(connection != 0);
  spindump_assert(spindump_isbool(fromResponder));
  spindump_assert(t != 0);

  //
  // Calculate the time for the initial request-response
  //

  const struct timeval* ackto = &connection->creationTime;
  unsigned long long diff = spindump_timediffinusecs(t,ackto);
  spindump_deepdebugf("the responder COAP TLS initial response refers to initiator COAP message that came %llu ms earlier",
		      diff / 1000);
  spindump_connections_newrttmeasurement(state,
					 packet,
					 connection,
					 1,
					 0,
					 ackto,
					 t,
					 "initial COAP TLS response");
}

//
// This is the main function to process an incoming UDP/COAP packet, parse
// the packet as much as we can and process it appropriately. The
// function sets the p_connection output parameter to the connection
// that this packet belongs to (and possibly creates this connection
// if the packet is the first in a flow).
//
// It is assumed that prior modules, i.e., the capture and UDP modules
// have filled in the relevant header pointers in the packet structure
// "packet" correctly. The etherlen, caplen, timestamp, and the actual
// packet (the contents field) needs to have been set.
//
// Note that this function is not called directly by the top-level
// analyzer, but rather by the UDP module, if the UDP flow looks
// heuristically like one that matches COAP characteristics. This
// determination is made based on port numbers and the ability to
// perform a rudimentary parsing of the COAP header.
//

void
spindump_analyze_process_coap(struct spindump_analyze* state,
			      struct spindump_packet* packet,
			      unsigned int ipHeaderPosition,
			      unsigned int ipHeaderSize,
			      uint8_t ipVersion,
						uint8_t ecnFlags,
			      unsigned int ipPacketLength,
			      unsigned int udpHeaderPosition,
			      unsigned int udpLength,
			      unsigned int remainingCaplen,
			      int isDtls,
			      struct spindump_connection** p_connection) {

  //
  // Some checks first
  //

  spindump_assert(state != 0);
  spindump_assert(packet != 0);
  spindump_assert(spindump_packet_isvalid(packet));
  spindump_assert(ipVersion == 4 || ipVersion == 6);
  spindump_assert(udpHeaderPosition > ipHeaderPosition);
  spindump_assert(spindump_isbool(isDtls));
  spindump_assert(p_connection != 0);

  //
  // Find out some information about the packet
  //

  spindump_address source;
  spindump_address destination;
  spindump_analyze_getsource(packet,ipVersion,ipHeaderPosition,&source);
  spindump_analyze_getdestination(packet,ipVersion,ipHeaderPosition,&destination);
  struct spindump_udp udp;
  spindump_protocols_udp_header_decode(packet->contents + udpHeaderPosition,&udp);
  uint16_t side1port = udp.uh_sport;
  uint16_t side2port = udp.uh_dport;
  const unsigned char* payload = (const unsigned char*)(packet->contents + udpHeaderPosition + spindump_udp_header_size);
  
  if (isDtls) {

    spindump_analyze_process_coap_dtls(state,
				       packet,
				       ecnFlags,
				       ipPacketLength,
				       udpLength,
				       remainingCaplen,
				       &source,
				       &destination,
				       side1port,
				       side2port,
				       payload,
				       p_connection);

  } else {

    spindump_analyze_process_coap_cleartext(state,
					    packet,
					    ecnFlags,
					    ipPacketLength,
					    udpLength,
					    remainingCaplen,
					    &source,
					    &destination,
					    side1port,
					    side2port,
					    payload,
					    p_connection);

  }

}

//
// This is the main function to process an incoming UDP/COAP packet
// when that packet is in cleartext. We parse the packet as much as we
// can and process it appropriately. The function sets the
// p_connection output parameter to the connection that this packet
// belongs to (and possibly creates this connection if the packet is
// the first in a flow).
//
// It is assumed that prior modules, i.e., the capture and UDP modules
// have filled in the relevant header pointers in the packet structure
// "packet" correctly. The etherlen, caplen, timestamp, and the actual
// packet (the contents field) needs to have been set.
//

static void
spindump_analyze_process_coap_cleartext(struct spindump_analyze* state,
					struct spindump_packet* packet,
					uint8_t ecnFlags,
					unsigned int ipPacketLength,
					unsigned int udpLength,
					unsigned int remainingCaplen,
					spindump_address* source,
					spindump_address* destination,
					uint16_t side1port,
					uint16_t side2port,
					const unsigned char* payload,
					struct spindump_connection** p_connection) {

  //
  // Some sanity checks first
  //

  spindump_assert(state != 0);
  spindump_assert(packet != 0);
  spindump_assert(spindump_packet_isvalid(packet));
  spindump_assert(ipPacketLength > 0);
  spindump_assert(udpLength > 0);
  spindump_assert(source != 0);
  spindump_assert(destination != 0);
  spindump_assert(payload != 0);
  spindump_assert(p_connection != 0);

  //
  // Initialize our analysis
  //

  struct spindump_coap coap;
  spindump_protocols_coap_header_decode(payload,&coap);
  struct spindump_connection* connection = 0;
  int fromResponder;
  int new = 0;

  //
  // Check that the packet looks sensible
  //

  unsigned int coapSize = udpLength - spindump_udp_header_size;
  if (coapSize < spindump_coap_header_size ||
      remainingCaplen < spindump_udp_header_size + spindump_coap_header_size) {
    spindump_debugf("packet too short for COAP");
    state->stats->notEnoughPacketForCoapHdr++;
    *p_connection = 0;
    return;
  }
  
  //
  // Parse the packet enough to determine what is going on
  //

  uint8_t ver = (coap.verttkl & spindump_coap_verttkl_vermask);
  uint8_t type = (coap.verttkl & spindump_coap_verttkl_tmask);
  uint8_t classf = (coap.code & spindump_coap_code_classmask);
  uint16_t mid = coap.id;
  unsigned int coappayloadsize = coapSize - spindump_coap_header_size;
  const unsigned char* coappayload = payload + spindump_coap_header_size;
  
  //
  // Debugs
  //
  
  spindump_debugf("saw COAP packet from %s (ports %u:%u) Byte1=%02x (Ver=%02x, Type=%02x) Code=%02x (Class=%02x) MID=%04x payload = %02x%02x%02x... (size %u)",
		  spindump_address_tostring(source), side1port, side2port,
		  coap.verttkl, ver, type,
		  coap.code, classf,
		  mid,
		  coappayload[0], coappayload[1], coappayload[2],
		  coappayloadsize);

  //
  // Then, look for existing connection
  //

  connection = spindump_connections_searchconnection_coap_either(source,
								 destination,
								 side1port,
								 side2port,
								 state->table,
								 &fromResponder);

  //
  // If not found, create a new one
  //

  if (connection == 0) {

    connection = spindump_connections_newconnection_coap(source,
							 destination,
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

    connection->u.coap.dtls = 0;

    state->stats->connections++;
    state->stats->connectionsCoap++;

  }

  //
  // Check version
  //

  if (ver != spindump_coap_verttkl_ver1) {
    spindump_debugf("COAP version %02x is not supported", ver);
    state->stats->unrecognisedCoapVersion++;
    *p_connection = 0;
    return;
  }

  //
  // Track message IDs of requests and responses
  //

  int foundmid = 0;
  if (type == spindump_coap_verttkl_tcomfirmable &&
      classf == spindump_coap_code_classrequest) {
    spindump_analyze_coap_markmidsent(connection,
				      fromResponder,
				      mid,
				      &packet->timestamp);
  } else if (type == spindump_coap_verttkl_tacknowledgement &&
	     (classf == spindump_coap_code_classsuccessresponse ||
	      classf == spindump_coap_code_classclienterrorresponse ||
	      classf == spindump_coap_code_classservererrorresponse)) {
    foundmid = spindump_analyze_coap_markmidreceived(state,
						     packet,
						     connection,
						     fromResponder,
						     mid,
						     &packet->timestamp);
  } else {
    spindump_debugf("COAP type %02x and class %02x do not represent request or response", type, classf);
    state->stats->untrackableCoapMessage++;
    *p_connection = 0;
    return;
  }

  //
  // Call some handlers based on what happened here, if needed
  //

  if (new) {
    spindump_analyze_process_handlers(state,spindump_analyze_event_newconnection,packet,connection);
  }

  //
  // Update stats.
  //

  spindump_analyze_process_pakstats(state,connection,fromResponder,packet,ipPacketLength,ecnFlags);

  //
  // If we've seen a response from the responder, mark state as
  // established and then closed, as the response is complete.
  //

  if (fromResponder && foundmid && connection->state == spindump_connection_state_establishing) {
    spindump_connections_changestate(state,packet,connection,spindump_connection_state_established);
    spindump_connections_changestate(state,packet,connection,spindump_connection_state_closed);
  }

  //
  // Done. Inform caller of the connection.
  //

  *p_connection = connection;

}

//
// This is the main function to process an incoming UDP/COAP packet
// when that packet is encrypted. We parse the packet as much as we
// can and process it appropriately. The function sets the
// p_connection output parameter to the connection that this packet
// belongs to (and possibly creates this connection if the packet is
// the first in a flow).
//
// It is assumed that prior modules, i.e., the capture and UDP modules
// have filled in the relevant header pointers in the packet structure
// "packet" correctly. The etherlen, caplen, timestamp, and the actual
// packet (the contents field) needs to have been set.
//

static void
spindump_analyze_process_coap_dtls(struct spindump_analyze* state,
                                   struct spindump_packet* packet,
                                   uint8_t ecnFlags,
																	 unsigned int ipPacketLength,
                                   unsigned int udpLength,
                                   unsigned int remainingCaplen,
                                   spindump_address* source,
                                   spindump_address* destination,
                                   uint16_t side1port,
                                   uint16_t side2port,
                                   const unsigned char* payload,
                                   struct spindump_connection** p_connection) {

  //
  // Some sanity checks first
  //

  spindump_assert(state != 0);
  spindump_assert(packet != 0);
  spindump_assert(spindump_packet_isvalid(packet));
  spindump_assert(ipPacketLength > 0);
  spindump_assert(udpLength > 0);
  spindump_assert(source != 0);
  spindump_assert(destination != 0);
  spindump_assert(payload != 0);
  spindump_assert(p_connection != 0);

  //
  // Initialize our analysis
  //

  struct spindump_connection* connection = 0;
  int fromResponder;

  //
  // Check that the packet looks sensible
  //

  unsigned int tlsLength = udpLength - spindump_udp_header_size;
  int isHandshake;
  int isInitialHandshake;
  spindump_tls_version dtlsVersion;
  int isResponse;
  if (!spindump_analyze_tls_parser_parsepacket(payload,
					       tlsLength,
					       remainingCaplen - spindump_udp_header_size,
					       1,
					       &isHandshake,
					       &isInitialHandshake,
					       &dtlsVersion,
					       &isResponse)) {
    spindump_debugf("unable to parse TLS packet in COAP");
    state->stats->invalidTlsPacket++;
    *p_connection = 0;
    return;
  }

  //
  // Debugs
  //

  spindump_debugf("saw COAP DTLS packet from %s (ports %u:%u) handshake %u initial %u response %u tls version %04x",
		  spindump_address_tostring(source), side1port, side2port,
		  isHandshake,
		  isInitialHandshake,
		  isResponse,
		  dtlsVersion);

  //
  // Then, look for existing connection
  //

  connection = spindump_connections_searchconnection_coap_either(source,
								 destination,
								 side1port,
								 side2port,
								 state->table,
								 &fromResponder);

  //
  // If not found, create a new one
  //

  if (connection == 0) {

    connection = spindump_connections_newconnection_coap(source,
							 destination,
							 side1port,
							 side2port,
							 &packet->timestamp,
							 state->table);

    fromResponder = 0;

    if (connection == 0) {
      *p_connection = 0;
      return;
    }

    connection->u.coap.dtls = 1;

    state->stats->connections++;
    state->stats->connectionsCoap++;

  }

  //
  // Set or update version number
  //

  if (isHandshake && dtlsVersion != 0) {
    spindump_deepdebugf("updating COAP DTLS version to %04x",
			dtlsVersion);
    connection->u.coap.dtlsVersion = dtlsVersion;
  }

  //
  // Calculate RTT based on initial hello exchange
  //

  if (fromResponder) {

    if (isHandshake && isInitialHandshake && isResponse && connection->packetsFromSide2 == 0) {

      spindump_analyze_coap_markinitialresponsereceived(state,packet,connection,1,&packet->timestamp);

    } else {

      spindump_debugf("this COAP DTLS response does not update RTT");

    }

  }

  //
  // If we've seen a response from the responder, mark state as
  // established.
  //

  if (fromResponder && isHandshake && isInitialHandshake && isResponse &&
      connection->state == spindump_connection_state_establishing) {

    spindump_connections_changestate(state,packet,connection,spindump_connection_state_established);

  }

  //
  // Done. Inform caller of the connection and update stats.
  //

  *p_connection = connection;
  spindump_analyze_process_pakstats(state,connection,fromResponder,packet,ipPacketLength,ecnFlags);

}
