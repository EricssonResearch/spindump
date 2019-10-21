
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
//  AUTHOR: JARI ARKKO AND MARCUS IHLAR
//
//

//
// Includes -----------------------------------------------------------------------------------
//

#include <string.h>
#include "spindump_util.h"
#include "spindump_connections.h"
#include "spindump_analyze.h"
#include "spindump_analyze_tcp.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static void
spindump_analyze_process_tcp_markseqsent(struct spindump_connection* connection,
                                         int fromResponder,
                                         tcp_seq seq,
                                         unsigned int payloadlen,
                                         struct timeval* t,
                                         int finset);
static void
spindump_analyze_process_tcp_markackreceived(struct spindump_analyze* state,
                                             struct spindump_packet* packet,
                                             struct spindump_connection* connection,
                                             int fromResponder,
                                             tcp_seq seq,
                                             struct timeval* t,
                                             int* finset);

//
// Actual code --------------------------------------------------------------------------------
//

//
// Mark the sending of a sequence number SEQ from one of the peers.
//
// If fromResponder = 1, the sending party is the server of the
// connection, if fromResponder = 0, it is the client. Seq is the
// sequence number from the other party that is being acked. Based on
// this sequence one one can track RTT later when an ACK is received.
//

static void
spindump_analyze_process_tcp_markseqsent(struct spindump_connection* connection,
                                         int fromResponder,
                                         tcp_seq seq,
                                         unsigned int payloadlen,
                                         struct timeval* t,
                                         int finset) {

  spindump_assert(connection != 0);
  spindump_assert(fromResponder == 0 || fromResponder == 1);
  spindump_assert(t != 0);
  spindump_assert(spindump_isbool(finset));

  if (fromResponder) {
    spindump_seqtracker_add(&connection->u.tcp.side2Seqs,t,seq,payloadlen,finset);
    spindump_deepdebugf("responder sent SEQ %u..%u (FIN=%u)", seq, seq + payloadlen, finset);
  } else {
    spindump_seqtracker_add(&connection->u.tcp.side1Seqs,t,seq,payloadlen,finset);
    spindump_deepdebugf("initiator sent SEQ %u..%u (FIN=%u)", seq, seq + payloadlen, finset);
  }
}

//
// Mark the reception of a sequence number ACK from one of the peers.
//
// If fromResponder = 1, the ACKing party is the server of the
// connection, if fromResponder = 0, it is the client. Seq is the
// sequence number from the other party that is being acked. Based on
// this sequence one one can track RTT.
//

static void
spindump_analyze_process_tcp_markackreceived(struct spindump_analyze* state,
                                             struct spindump_packet* packet,
                                             struct spindump_connection* connection,
                                             int fromResponder,
                                             tcp_seq seq,
                                             struct timeval* t,
                                             int* finset) {

  struct timeval* ackto;
  tcp_seq sentSeq;

  spindump_assert(state != 0);
  spindump_assert(connection != 0);
  spindump_assert(spindump_packet_isvalid(packet));
  spindump_assert(spindump_isbool(fromResponder));
  spindump_assert(t != 0);
  spindump_assert(finset != 0);

  if (fromResponder) {

    ackto = spindump_seqtracker_ackto(&connection->u.tcp.side1Seqs,seq,&sentSeq,finset);

    if (ackto != 0) {

      spindump_deepdebugf("spindump_analyze_process_tcp_markackreceived");
      unsigned long long diff = spindump_timediffinusecs(t,ackto);
      spindump_deepdebugf("the responder ack %u refers to initiator TCP message (seq=%u) that came %llu ms earlier (its FIN was %u)",
                          seq,
                          sentSeq,
                          diff / 1000,
                          *finset);
      spindump_connections_newrttmeasurement(state,
                                             packet,
                                             connection,
                                             1,
                                             0,
                                             ackto,
                                             t,
                                             "TCP ACK");

    } else {

      spindump_deepdebugf("did not find the initiator TCP message that responder ack %u refers to", seq);

    }

  } else {

    ackto = spindump_seqtracker_ackto(&connection->u.tcp.side2Seqs,seq,&sentSeq,finset);

    if (ackto != 0) {

      spindump_deepdebugf("spindump_analyze_process_tcp_markackreceived 2");
      unsigned long long diff = spindump_timediffinusecs(t,ackto);
      spindump_deepdebugf("the initiator ack %u refers to responder TCP message (seq=%u) that came %llu ms earlier (its FIN was %u)",
                          seq,
                          sentSeq,
                          diff / 1000,
                          *finset);
      spindump_connections_newrttmeasurement(state,
                                             packet,
                                             connection,
                                             0,
                                             0,
                                             ackto,
                                             t,
                                             "TCP ACK");

    } else {

      spindump_deepdebugf("did not find the responder TCP message that initiator ack %u refers to", seq);

    }
  }
}

//
// This is the main function to process an incoming TCP packet, parse
// the packet as much as we can and process it appropriately. The
// function sets the p_connection output parameter to the connection
// that this packet belongs to (and possibly creates this connection
// if the packet is the first in a flow, e.g., for TCP SYN
// packets).
//
// It is assumed that prior modules, i.e., the capture module has
// filled in the relevant fields in the packet structure "packet"
// correctly.
//

void
spindump_analyze_process_tcp(struct spindump_analyze* state,
                             struct spindump_packet* packet,
                             unsigned int ipHeaderPosition,
                             unsigned int ipHeaderSize,
                             uint8_t ipVersion,
                                         uint8_t ecnFlags,
                             unsigned int ipPacketLength,
                             unsigned int tcpHeaderPosition,
                             unsigned int tcpLength,
                             unsigned int remainingCaplen,
                             struct spindump_connection** p_connection) {

  //
  // Some checks first
  //

  spindump_assert(state != 0);
  spindump_assert(packet != 0);
  spindump_assert(spindump_packet_isvalid(packet));
  spindump_assert(ipVersion == 4 || ipVersion == 6);
  spindump_assert(tcpHeaderPosition > ipHeaderPosition);
  spindump_assert(p_connection != 0);

  //
  // Parse the header
  //

  state->stats->receivedTcp++;
  if (tcpLength < spindump_tcp_header_length) {
    state->stats->notEnoughPacketForTcpHdr++;
    spindump_warnf("not enough payload bytes for a TCP header", tcpLength);
    *p_connection = 0;
    return;
  }
  struct spindump_tcp tcp;
  spindump_protocols_tcp_header_decode(packet->contents + tcpHeaderPosition,&tcp);
  unsigned int tcpHeaderSize = SPINDUMP_TH_OFF(&tcp)*4;
  spindump_deepdebugf("tcp header: sport = %u", tcp.th_sport);
  spindump_deepdebugf("tcp header: dport = %u", tcp.th_dport);
  spindump_deepdebugf("tcp header: seq = %u", tcp.th_seq);
  spindump_deepdebugf("tcp header: ack = %u", tcp.th_ack);
  spindump_deepdebugf("tcp header: off = %u (raw %02x)", SPINDUMP_TH_OFF(&tcp), tcp.th_offx2);
  spindump_deepdebugf("tcp header: flags = %x", tcp.th_flags);
  if (tcpHeaderSize < 20 || remainingCaplen < tcpHeaderSize) {
    state->stats->invalidTcpHdrSize++;
    spindump_warnf("TCP header length %u invalid", tcpHeaderSize);
    *p_connection = 0;
    return;
  }
  unsigned int size_tcppayload = tcpLength - tcpHeaderSize;
  spindump_debugf("received an IPv%u TCP packet of %u bytes, payload size %u bytes",
                  ipVersion,
                  packet->etherlen,
                  size_tcppayload);

  //
  // Find out some information about the packet
  //

  struct spindump_connection* connection = 0;
  spindump_address source;
  spindump_address destination;
  spindump_analyze_getsource(packet,ipVersion,ipHeaderPosition,&source);
  spindump_analyze_getdestination(packet,ipVersion,ipHeaderPosition,&destination);
  uint16_t side1port = tcp.th_sport;
  uint16_t side2port = tcp.th_dport;
  tcp_seq seq = tcp.th_seq;
  tcp_seq ack = tcp.th_ack;
  int fromResponder;
  int finreceived = ((tcp.th_flags & SPINDUMP_TH_FIN) != 0);
  int ackedfin = 0;
  int new = 0;

  //
  // Debugs
  //

  spindump_debugf("saw packet from %s (ports %u:%u)",
                  spindump_address_tostring(&source), side1port, side2port);
  spindump_deepdebugf("flags = %s", spindump_protocols_tcp_flagstostring(tcp.th_flags));

  //
  // Check whether this is a SYN, SYN ACK, FIN, FIN ACK, or RST
  // packet, create or delete the connection accordingly
  //

  if ((tcp.th_flags & SPINDUMP_TH_SYN) &&
      (tcp.th_flags & SPINDUMP_TH_ACK) == 0) {

    //
    // SYN packet. Create a connection in stable establishing,
    // if it doesn't exist yet.
    //
    
    spindump_deepdebugf("case 1: SYN (seq = %u, ack = %u)", seq, ack);
    
    //
    // First, look for existing connection
    //

    connection = spindump_connections_searchconnection_tcp(&source,
                                                           &destination,
                                                           side1port,
                                                           side2port,
                                                           state->table);

    //
    // If not found, create a new one
    //

    if (connection == 0) {

      connection = spindump_connections_newconnection_tcp(&source,
                                                          &destination,
                                                          side1port,
                                                          side2port,
                                                          &packet->timestamp,
                                                          state->table);
      new = 1;

      if (connection == 0) {
        *p_connection = 0;
        return;
      }
      
      state->stats->connections++;
      state->stats->connectionsTcp++;

    }

    spindump_analyze_process_pakstats(state,connection,0,packet,ipPacketLength,ecnFlags);
    spindump_analyze_process_tcp_markseqsent(connection,
                                             0,
                                             seq,
                                             1,
                                             &packet->timestamp,
                                             finreceived);
    *p_connection = connection;

  } else if ((tcp.th_flags & SPINDUMP_TH_SYN) &&
             (tcp.th_flags & SPINDUMP_TH_ACK)) {

    //
    // SYN ACK packet. Mark the connection as established, if
    // the connection is already found. Otherwise ignore.
    //

    spindump_deepdebugf("case 2: SYN ACK (seq = %u, ack = %u)", seq, ack);

    //
    // First, look for existing connection
    //

    connection = spindump_connections_searchconnection_tcp(&destination,
                                                           &source,
                                                           side2port,
                                                           side1port,
                                                           state->table);

    //
    // If found, change state and mark reception of an ACK. If not
    // found, ignore.
    //

    if (connection != 0) {

      if (connection->state == spindump_connection_state_establishing) {
        spindump_connections_changestate(state,
                                         packet,
                                         connection,
                                         spindump_connection_state_established);
      }

      spindump_analyze_process_pakstats(state,connection,1,packet,ipPacketLength,ecnFlags);
      spindump_analyze_process_tcp_markseqsent(connection,
                                               1,
                                               seq,
                                               1,
                                               &packet->timestamp,
                                               finreceived);
      spindump_analyze_process_tcp_markackreceived(state,packet,connection,1,ack,&packet->timestamp,&ackedfin);
      *p_connection = connection;

    } else {

      state->stats->unknownTcpConnection++;

    }

  } else if ((tcp.th_flags & SPINDUMP_TH_FIN)) {

    //
    // FIN packet. Mark the connection as closing, if the
    // connection exists.
    //

    spindump_deepdebugf("case 3: FIN (seq = %u, ack = %u)", seq, ack);

    //
    // First, look for existing connection
    //

    connection = spindump_connections_searchconnection_tcp_either(&source,
                                                                  &destination,
                                                                  side1port,
                                                                  side2port,
                                                                  state->table,
                                                                  &fromResponder);

    //
    // If found, change state and mark reception of an ACK. If not
    // found, ignore.
    //

    if (connection != 0) {

      if (connection->state == spindump_connection_state_establishing ||
          connection->state == spindump_connection_state_established ||
          connection->state == spindump_connection_state_closing) {
        spindump_connections_changestate(state,packet,connection,spindump_connection_state_closing);
      }

      if (fromResponder)
        connection->u.tcp.finFromSide2 = 1;
      else
        connection->u.tcp.finFromSide1 = 1;
      
      spindump_analyze_process_pakstats(state,connection,fromResponder,packet,ipPacketLength,ecnFlags);
      spindump_analyze_process_tcp_markseqsent(connection,
                                               fromResponder,
                                               seq,
                                               size_tcppayload,
                                               &packet->timestamp,
                                               finreceived);
      spindump_analyze_process_tcp_markackreceived(state,packet,connection,fromResponder,ack,&packet->timestamp,&ackedfin);
      if (ackedfin) {
        spindump_deepdebugf("this was an ack to a FIN");
        if (fromResponder)
          connection->u.tcp.finFromSide1 = 1;
        else
          connection->u.tcp.finFromSide2 = 1;
      }
      
      //
      // Both sides have sent a FIN?
      //

      spindump_deepdebugf("seen FIN from %u and %u",
                          connection->u.tcp.finFromSide1,
                          connection->u.tcp.finFromSide2);

      if (connection->u.tcp.finFromSide1 && connection->u.tcp.finFromSide2) {
        if (connection->state == spindump_connection_state_closing) {
          spindump_connections_changestate(state,packet,connection,spindump_connection_state_closed);
          spindump_connections_markconnectiondeleted(connection);
        }
      }
      
      *p_connection = connection;
      
    } else {
      
      state->stats->unknownTcpConnection++;
      
    }

  } else if ((tcp.th_flags & SPINDUMP_TH_RST)) {

    //
    // RST packet. Delete the connection, if there was one
    //

    spindump_deepdebugf("case 5: RST (seq = %u, ack = %u)", seq, ack);

    //
    // First, look for existing connection
    //

    connection = spindump_connections_searchconnection_tcp_either(&source,
                                                                  &destination,
                                                                  side1port,
                                                                  side2port,
                                                                  state->table,
                                                                  &fromResponder);

    //
    // If found, delete connection and mark reception of an ACK. If not
    // found, ignore.
    //

    if (connection != 0) {

      spindump_analyze_process_pakstats(state,connection,fromResponder,packet,ipPacketLength,ecnFlags);
      spindump_analyze_process_tcp_markackreceived(state,packet,connection,fromResponder,ack,&packet->timestamp,&ackedfin);
      spindump_connections_changestate(state,packet,connection,spindump_connection_state_closed);
      spindump_connections_markconnectiondeleted(connection);

      *p_connection = connection;

    } else {

      state->stats->unknownTcpConnection++;

    }

  } else {

    //
    // Normal packet. Update the connection, if there was one.
    //

    spindump_deepdebugf("case 6: OTHER (seq = %u, ack = %u)", seq, ack);

    //
    // First, look for existing connection
    //

    connection = spindump_connections_searchconnection_tcp_either(&source,
                                                                  &destination,
                                                                  side1port,
                                                                  side2port,
                                                                  state->table,
                                                                  &fromResponder);
    
    //
    // If found, mark reception of an ACK and sent SEQ. If not
    // found, ignore.
    //

    if (connection != 0) {

      spindump_analyze_process_tcp_markseqsent(connection,
                                               fromResponder,
                                               seq,
                                               size_tcppayload,
                                               &packet->timestamp,
                                               finreceived);
      spindump_analyze_process_tcp_markackreceived(state,packet,connection,fromResponder,ack,&packet->timestamp,&ackedfin);
      if (ackedfin) {
        spindump_deepdebugf("this was an ack to a FIN");
        if (fromResponder) {
          connection->u.tcp.finFromSide1 = 1;
        } else {
          connection->u.tcp.finFromSide2 = 1;
        }
        
        //
        // Both sides have sent a FIN?
        //
        
        spindump_deepdebugf("seen acked FIN from %u and %u",
                            connection->u.tcp.finFromSide1,
                            connection->u.tcp.finFromSide2);
        
        if (connection->u.tcp.finFromSide1 && connection->u.tcp.finFromSide2) {
          if (connection->state == spindump_connection_state_closing) {
            spindump_connections_changestate(state,packet,connection,spindump_connection_state_closed);
            spindump_connections_markconnectiondeleted(connection);
          }
        }
      }
      
      //
      // Update statistics
      //
      
      spindump_analyze_process_pakstats(state,connection,fromResponder,packet,ipPacketLength,ecnFlags);
      *p_connection = connection;
      
    } else {

      state->stats->unknownTcpConnection++;
      *p_connection = 0;
      return;

    }

  }
  
  //
  // Call some handlers based on what happened here, if needed
  //
  
  if (new) {
    spindump_analyze_process_handlers(state,spindump_analyze_event_newconnection,packet,connection);
  }
  
}
