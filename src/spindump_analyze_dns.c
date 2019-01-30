
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
#include "spindump_connections.h"
#include "spindump_analyze.h"
#include "spindump_analyze_udp.h"
#include "spindump_analyze_dns.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static void
spindump_analyzer_dns_markmidsent(struct spindump_connection* connection,
				  int fromResponder,
				  const uint16_t mid,
				  const struct timeval* t);
static int
spindump_analyzer_dns_markmidreceived(struct spindump_analyze* state,
				      struct spindump_packet* packet,
				      struct spindump_connection* connection,
				      int fromResponder,
				      const uint16_t mid,
				      const struct timeval* t);

//
// Actual code --------------------------------------------------------------------------------
//

//
// The function spindump_analyze_dns_isprobablednspacket is one of the
// two main entrypoints for the DNS analyzer. It checks whether a
// packet is likely a DNS packet. The parameter payload points to the
// beginning of the UDP payload. payload_len is the length of that.
//

int
spindump_analyze_dns_isprobablednspacket(const unsigned char* payload,
					 unsigned int payload_len,
					 uint16_t sourcePort,
					 uint16_t destPort) {

  //
  // Do ports look like DNS?
  //

  if (sourcePort != SPINDUMP_DNS_PORT && destPort != SPINDUMP_DNS_PORT) {
    return(0);
  }

  //
  // Does packet format look right?
  //

  if (payload_len < sizeof(struct spindump_dns)) {
    return(0);
  }

  //
  // Probable DNS packet!
  //

  return(1);
}

//
// Parse a DNS name from a DNS packet, returning the usual DNS name
// representation as a string, e.g., "www.example.com". The returned
// string need not be freed, but it will not survive the next call to
// this same function.
//
// Note: This function is not thread safe.
//

const char*
spindump_analyzer_dns_parsename(const char* dnspayload,
				unsigned int dnspayloadsize) {
  static char buf[200];
  memset(buf,0,sizeof(buf));
  if (dnspayloadsize == 0) {
    spindump_deepdebugf("DNS payload size 0 is not allowed, failing");
    return(0);
  }
  uint8_t labelsize = *(dnspayload++);
  dnspayloadsize--;
  while (labelsize > 0) {
    if (labelsize > dnspayloadsize - 1) {
      spindump_deepdebugf("DNS label size %u is longer than remaining message bytes, failing", labelsize);
      return(0);
    }
    while (labelsize > 0) {
      if (strlen(buf) < sizeof(buf) - 1) buf[strlen(buf)] = *dnspayload;
      labelsize--;
      dnspayloadsize--;
      dnspayload++;
    }
    if (strlen(buf) < sizeof(buf) - 1) buf[strlen(buf)] = '.';
    spindump_assert(dnspayloadsize > 0);
    labelsize = *(dnspayload++);
  }
  return(buf);
}

//
// Mark the sending of a message ID from one of the peers.
//
// If fromResponder = 1, the sending party is the server of the
// connection, if fromResponder = 0, it is the client. Mid is the
// message ID from the other party that is being acked. Based on this,
// one one can track RTT later when a DNS response is sent.
//

static void
spindump_analyzer_dns_markmidsent(struct spindump_connection* connection,
				  int fromResponder,
				  const uint16_t mid,
				  const struct timeval* t) {

  spindump_assert(connection != 0);
  spindump_assert(fromResponder == 0 || fromResponder == 1);
  spindump_assert(t != 0);

  if (fromResponder) {
    spindump_messageidtracker_add(&connection->u.dns.side2MIDs,t,mid);
    spindump_deepdebugf("responder sent MID %u", mid);
  } else {
    spindump_messageidtracker_add(&connection->u.dns.side1MIDs,t,mid);
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
spindump_analyzer_dns_markmidreceived(struct spindump_analyze* state,
				      struct spindump_packet* packet,
				      struct spindump_connection* connection,
				      int fromResponder,
				      const uint16_t mid,
				      const struct timeval* t) {

  const struct timeval* ackto;

  spindump_assert(connection != 0);
  spindump_assert(spindump_packet_isvalid(packet));
  spindump_assert(spindump_isbool(fromResponder));
  spindump_assert(t != 0);

  if (fromResponder) {

    ackto = spindump_messageidtracker_ackto(&connection->u.dns.side1MIDs,mid);

    if (ackto != 0) {

      unsigned long long diff = spindump_timediffinusecs(t,ackto);
      spindump_deepdebugf("the responder DNS response %u refers to initiator DNS message that came %llu ms earlier",
			  mid,
			  diff / 1000);
      spindump_connections_newrttmeasurement(state,
					     packet,
					     connection,
					     1,
							 0,
					     ackto,
					     t,
					     "DNS response");
      return(1);

    } else {

      spindump_deepdebugf("did not find the initiator DNS message that responder mid %u refers to", mid);
      return(0);

    }

  } else {

    ackto = spindump_messageidtracker_ackto(&connection->u.dns.side2MIDs,mid);

    if (ackto != 0) {

      unsigned long long diff = spindump_timediffinusecs(t,ackto);
      spindump_deepdebugf("the initiator response MID %u refers to responder DNS message that came %llu ms earlier",
			  mid,
			  diff / 1000);
      spindump_connections_newrttmeasurement(state,
					     packet,
					     connection,
					     0,
							 0,
					     ackto,
					     t,
					     "DNS response");
      return(1);

    } else {

      spindump_deepdebugf("did not find the responder DNS message that initiator mid %u refers to", mid);
      return(0);

    }
  }
}

//
// This is the main function to process an incoming UDP/DNS packet, parse
// the packet as much as we can and process it appropriately. The
// function sets the p_connection output parameter to the connection
// that this packet belongs to (and possibly creates this connection
// if the packet is the first in a flow).
//
// It is assumed that prior modules, i.e., the capture module has
// filled in the relevant header pointers in the packet structure
// "packet" correctly.
//
// Note that this function is not called directly by the top-level
// analyzer, but rather by the UDP module, if the UDP flow looks
// heuristically like one that matches DNS characteristics. This
// determination is made based on port numbers and the ability to
// perform a rudimentary parsing of the DNS header.
//

void
spindump_analyze_process_dns(struct spindump_analyze* state,
			     struct spindump_packet* packet,
			     unsigned int ipHeaderPosition,
			     unsigned int ipHeaderSize,
			     uint8_t ipVersion,
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

  struct spindump_connection* connection = 0;
  spindump_address source;
  spindump_address destination;
  spindump_analyze_getsource(packet,ipVersion,ipHeaderPosition,&source);
  spindump_analyze_getdestination(packet,ipVersion,ipHeaderPosition,&destination);
  const struct spindump_udp* udp = (const struct spindump_udp*)(packet->contents + udpHeaderPosition);
  uint16_t side1port = ntohs(udp->uh_sport);
  uint16_t side2port = ntohs(udp->uh_dport);
  int fromResponder;
  int new = 0;

  //
  // Check that the packet looks sensible
  //

  unsigned int dnsSize = udpLength - spindump_udp_header_size;
  if (dnsSize < sizeof(struct spindump_dns) ||
      remainingCaplen < spindump_udp_header_size + sizeof(struct spindump_dns)) {
    spindump_debugf("packet too short for DNS");
    state->stats->notEnoughPacketForDnsHdr++;
    *p_connection = 0;
    return;
  }

  //
  // Parse the packet enough to determine what is going on
  //

  const struct spindump_dns* dns = (const struct spindump_dns*)(packet->contents + udpHeaderPosition + spindump_udp_header_size);
  uint16_t mid = dns->id;
  int qr = ((dns->flagsOpcode & spindump_dns_flagsopcode_qr) >> spindump_dns_flagsopcode_qr_shift);
  uint8_t opcode = ((dns->flagsOpcode & spindump_dns_flagsopcode_opcode) >> spindump_dns_flagsopcode_opcode_shift);
  uint16_t qdcount = dns->QDCount;
  unsigned int dnspayloadsize = dnsSize - sizeof(struct spindump_dns);
  const char* dnspayload = ((const char*)dns + sizeof(struct spindump_dns));

  //
  // Debugs
  //

  spindump_debugf("saw DNS packet from %s (ports %u:%u) QR=%u MID=%04x OP=%u QD=%u payload = %02x%02x%02x...",
		  spindump_address_tostring(&source), side1port, side2port,
		  mid,
		  qr,
		  opcode,
		  qdcount,
		  dnspayload[0], dnspayload[1], dnspayload[2]);

  //
  // Then, look for existing connection
  //

  connection = spindump_connections_searchconnection_dns_either(&source,
								&destination,
								side1port,
								side2port,
								state->table,
								&fromResponder);

  //
  // If not found, create a new one
  //

  if (connection == 0) {

    connection = spindump_connections_newconnection_dns(&source,
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
    state->stats->connectionsDns++;

  }

  //
  // Record the queried name, if any
  //

  if (qr == 0 &&
      opcode == spindump_dns_opcode_query &&
      qdcount > 0 &&
      dnspayloadsize > 0) {
    const char* queriedName = spindump_analyzer_dns_parsename(dnspayload,dnspayloadsize);
    if (queriedName != 0) {
      memset(connection->u.dns.lastQueriedName,0,sizeof(connection->u.dns.lastQueriedName));
      strncpy(connection->u.dns.lastQueriedName,queriedName,sizeof(connection->u.dns.lastQueriedName)-1);
      spindump_deepdebugf("storing queried DNS name %s for interest", connection->u.dns.lastQueriedName);
    }
  }

  //
  // Track message IDs of requests and responses
  //

  int foundmid = 0;
  if (qr == 0) {
    spindump_analyzer_dns_markmidsent(connection,
				      fromResponder,
				      mid,
				      &packet->timestamp);
  } else {
    foundmid = spindump_analyzer_dns_markmidreceived(state,
						     packet,
						     connection,
						     fromResponder,
						     mid,
						     &packet->timestamp);
  }

  //
  // Call some handlers based on what happened here, if needed
  //

  if (new) {
    spindump_analyze_process_handlers(state,spindump_analyze_event_newconnection,packet,connection);
  }

  //
  // If we've seen a response from the responder, mark state as
  // established and then closed, as the response is complete.
  //

  if (fromResponder && foundmid && connection->state == spindump_connection_state_establishing) {
    spindump_connections_changestate(state,packet,connection,spindump_connection_state_established);
    spindump_connections_changestate(state,packet,connection,spindump_connection_state_closed);
  }

  //
  // Update stats.
  //

  spindump_analyze_process_pakstats(state,connection,fromResponder,packet,ipPacketLength);

  //
  // Done. Inform caller of the connection.
  //

  *p_connection = connection;

}
