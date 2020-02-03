
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
spindump_analyze_process_sctp_markackreceived_data(struct spindump_analyze* state,
                                                   struct spindump_packet* packet,
                                                   struct spindump_connection* connection,
                                                   int fromResponder,
                                                   sctp_tsn ackTsn,
                                                   struct timeval* t);

static void
spindump_analyze_process_sctp_marksent_hb(struct spindump_connection* connection,
                                          int fromResponder,
                                          struct timeval* t);

static void
spindump_analyze_process_sctp_markackreceived_hb(struct spindump_analyze* state,
                                                 struct spindump_packet* packet,
                                                 struct spindump_connection* connection,
                                                 int fromResponder,
                                                 struct timeval* t);
static const char*
spindump_analyze_sctp_chunk_type_to_string(enum spindump_sctp_chunk_type type);

//
// Actual code --------------------------------------------------------------------------------
//

//
// Returns the chunk type as a string. The returned string is a
// static value, and need not be deallocated.
//

static const char*
spindump_analyze_sctp_chunk_type_to_string(enum spindump_sctp_chunk_type type) {
  switch (type) {
  case spindump_sctp_chunk_type_data: return("DATA");              
  case spindump_sctp_chunk_type_init: return("INIT");              
  case spindump_sctp_chunk_type_init_ack: return("INIT ACK");          
  case spindump_sctp_chunk_type_sack: return("SACK");              
  case spindump_sctp_chunk_type_heartbeat: return("HEARTBEAT");          
  case spindump_sctp_chunk_type_heartbeat_ack: return("HEARTBEAT ACK");     
  case spindump_sctp_chunk_type_abort: return("ABORT");             
  case spindump_sctp_chunk_type_shutdown: return("SHUTDOWN");          
  case spindump_sctp_chunk_type_shutdown_ack: return("SHUTDOWN ACK");       
  case spindump_sctp_chunk_type_error: return("ERROR");             
  case spindump_sctp_chunk_type_cookie_echo: return("COOKIE ECHO");        
  case spindump_sctp_chunk_type_cookie_ack: return("COOKIE ACK");        
  case spindump_sctp_chunk_type_ecne: return("ECNE");              
  case spindump_sctp_chunk_type_cwr: return("CWR");               
  case spindump_sctp_chunk_type_shutdown_complete:  return("SHUTDOWN COMPLETE");
  case spindump_sctp_chunk_type_auth: return("AUTH");
  default: return("UNKNOWN CHUNK TYPE");
  }
}

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
spindump_analyze_process_sctp_markackreceived_data(struct spindump_analyze* state,
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

  spindump_deepdebugf("spindump_analyze_process_sctp_markackreceived_data, fromResponder: %d", fromResponder);

  if (ackto != 0) {

      unsigned long long diff = spindump_timediffinusecs(t,ackto);
      spindump_deepdebugf("SACK %u refers to SCTP message (TSN=%u) that came %llu us earlier",
                          ackTsn,
                          sentTsn,
                          diff);

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

//
// Remember HB info.
//
// If fromResponder = 1, the sending party is the server of the
// connection, if fromResponder = 0, it is the client. Based on
// this HB one can track RTT later when HB ACK is received.
//
static void
spindump_analyze_process_sctp_marksent_hb(struct spindump_connection* connection,
                                          int fromResponder,
                                          struct timeval* t)
{
  // ignore if not in Established state
  if (connection->state == spindump_connection_state_established) {

  spindump_deepdeepdebugf("HB received, fromResponder %d", fromResponder);

  // increment number of HBs inflight and remember timestamp
  if (fromResponder) {

    connection->u.sctp.side2HbCnt += 1;
    connection->u.sctp.side2hbTime = *t;
    spindump_deepdeepdebugf("After processing side2HbCnt %d, side2hbTime %llu", 
                            connection->u.sctp.side2HbCnt, connection->u.sctp.side2hbTime.tv_sec);

    } else {
                
      connection->u.sctp.side1HbCnt += 1;
      connection->u.sctp.side1hbTime = *t;
      spindump_deepdeepdebugf("After processing side1HbCnt %d, side1hbTime %llu", 
                              connection->u.sctp.side1HbCnt, connection->u.sctp.side1hbTime.tv_sec);

      }
    } else {

      spindump_deepdeepdebugf("HB hasn't been processed cause the connection is not in Established state");
      
    }
}

//
// Mark the reception of HB ACK from one of the peers.
// Perform RTT measurement if HB ACK acknowledges a sole HB.
//
// If fromResponder = 1, the ACKing party is the server of the
// connection, if fromResponder = 0, it is the client. Seq is the
// sequence number from the other party that is being acked. Based on
// this sequence one can track RTT.
//
static void
spindump_analyze_process_sctp_markackreceived_hb(struct spindump_analyze* state,
                                                 struct spindump_packet* packet,
                                                 struct spindump_connection* connection,
                                                 int fromResponder,
                                                 struct timeval* t) {

  struct timeval* ackto = 0;
  spindump_assert(state != 0);
  spindump_assert(connection != 0);
  spindump_assert(spindump_packet_isvalid(packet));
  spindump_assert(spindump_isbool(fromResponder));
  spindump_assert(t != 0);
  
  spindump_deepdebugf("spindump_analyze_process_sctp_markackreceived_hb, fromResponder: %d", fromResponder);
  
  // calculate RTT if only one HB was inflight
  // note that the measurment is made for the opposite side towards HB ACK
  if (fromResponder) {
        
    if (connection->u.sctp.side1HbCnt == 1) {
      ackto = &connection->u.sctp.side1hbTime;
    }    
    // reset the counter of HBs in any case
    connection->u.sctp.side1HbCnt = 0;
    
  } else {
              
    if (connection->u.sctp.side2HbCnt == 1) {
      ackto = &connection->u.sctp.side2hbTime;
    }    
    // reset the counter of HBs in any case
    connection->u.sctp.side2HbCnt = 0;
    
  }

  if (ackto != 0) {

    unsigned long long diff = spindump_timediffinusecs(t,ackto);
    spindump_deepdebugf("HB ACK refers to HB that came %llu us earlier", diff);

    spindump_connections_newrttmeasurement(state,
                                           packet,
                                           connection,
                                           fromResponder,
                                           0,
                                           ackto,
                                           t,
                                           "SCTP HB ACK");

  } else {

    spindump_deepdebugf("did not find the outgoing HB message that received HB ACK refers to");

  }

}

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
  unsigned int remainingLen = (remainingCaplen < sctpLength) ? remainingCaplen : sctpLength;
  const unsigned char* position = packet->contents + sctpHeaderPosition;

  state->stats->receivedSctp++;

  if ( remainingLen < spindump_sctp_packet_header_length ) {
    state->stats->notEnoughPacketForSctpHdr++;
    spindump_warnf("not enough payload bytes for a SCTP header: %u", remainingLen);
    *p_connection = 0;
    return;
  }

  struct spindump_sctp_packet_header sctp;
  spindump_protocols_sctp_header_decode(position,&sctp);
  spindump_deepdebugf("sctp header: sport = %u", sctp.sh_sport);
  spindump_deepdebugf("sctp header: dport = %u", sctp.sh_dport);
  spindump_deepdebugf("sctp header: vtag = %u", sctp.sh_vtag);
  spindump_deepdebugf("sctp header: checksum = %u", sctp.sh_checksum);

  struct spindump_connection* connection = 0;
  spindump_address source;
  spindump_address destination;
  spindump_analyze_getsource(packet,ipVersion,ipHeaderPosition,&source);
  spindump_analyze_getdestination(packet,ipVersion,ipHeaderPosition,&destination);
  uint16_t side1port = sctp.sh_sport;
  uint16_t side2port = sctp.sh_dport;
  int fromResponder;  // to be used in spindump_connections_searchconnection_sctp_either()
  int new = 0;

  // search the connection
  connection = spindump_connections_searchconnection_sctp_either(&source,
                                                                &destination,
                                                                side1port,
                                                                side2port,
                                                                state->table,
                                                                &fromResponder);

  //
  // Parse all chunks
  //
  unsigned int nParsedChunks = 0;
  remainingLen -= spindump_sctp_packet_header_length;
  position += spindump_sctp_packet_header_length;

  struct spindump_sctp_chunk sctp_chunk;
  while ( ( remainingLen > 0 ) && 
    (spindump_sctp_parse_error != spindump_protocols_sctp_chunk_parse(position,&sctp_chunk,remainingLen)) ) {
    //
    // Check what chunks are present in packet,
    // create, update or delete the connection accordingly
    //
    spindump_deepdebugf("sctp chunk: type = %s", spindump_analyze_sctp_chunk_type_to_string(sctp_chunk.ch_type));
    spindump_deepdebugf("sctp chunk: flags = %u", sctp_chunk.ch_flags);
    spindump_deepdebugf("sctp chunk: length = %u", sctp_chunk.ch_length);

    // if chunk length is not multiple of 4 bytes, then packet has padding bytes.
    // next chunk is located after padding.
    unsigned int padded = (sctp_chunk.ch_length%4) ? 
        sctp_chunk.ch_length + (4 - (sctp_chunk.ch_length%4)) : sctp_chunk.ch_length;
    spindump_deepdeepdebugf("padded length: %u", padded);
    position += padded;
    remainingLen -= padded;

    nParsedChunks++;

    switch (sctp_chunk.ch_type) {
        case spindump_sctp_chunk_type_data:
        // DATA

        //
        // If connection found, remember TSN. If not found, ignore.
        //
        if (connection != 0) {

          spindump_analyze_process_sctp_marktsnsent(connection,
                                                  fromResponder,
                                                  sctp_chunk.ch.data.tsn,
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

          spindump_analyze_process_sctp_markackreceived_data(state,
                                                        packet,
                                                        connection,
                                                        fromResponder,
                                                        sctp_chunk.ch.sack.cumulativeTsnAck,
                                                        &packet->timestamp);

        } else {

          state->stats->unknownSctpConnection++;
          *p_connection = 0;
          return;

        }
        break; // SACK
      case spindump_sctp_chunk_type_init:
        // INIT

        //
        // If connection not found, create a new one
        //
        if (connection == 0) {
          connection = spindump_connections_newconnection_sctp(&source,
                                                               &destination,
                                                               side1port,
                                                               side2port,
                                                               sctp_chunk.ch.init.initiateTag,
                                                               &packet->timestamp,
                                                               state->table);

          if (connection == 0) {
            *p_connection = 0;
            return;
          }

          new = 1;
          state->stats->connections++;
          state->stats->connectionsSctp++;
          spindump_analyze_process_pakstats(state,connection,0,packet,ipPacketLength,ecnFlags);

        } else {

            if (fromResponder == 0)
            {
              // Assoc is restarted, update side1Vtag for the existing connection
              connection->u.sctp.side1Vtag = sctp_chunk.ch.init.initiateTag;
            } else if (connection->state == spindump_connection_state_establishing) {
              // Initialization collision case, update side2Vtag for the existing connection
              connection->u.sctp.side2Vtag = sctp_chunk.ch.init.initiateTag;
            }

        }

        break; // INIT
      case spindump_sctp_chunk_type_init_ack:
        // INIT ACK

        //
        // If connection found, update side2.vTag. If not found, ignore.
        //

        if (connection != 0) {

          if ((fromResponder == 1) && 
              (connection->state == spindump_connection_state_establishing)) {
            // this is INIT ACK to original (created connection) or retransmitted INIT
            connection->u.sctp.side2Vtag = sctp_chunk.ch.init_ack.initiateTag;
          }

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
      case spindump_sctp_chunk_type_heartbeat:

        // HEARTBEAT (HB) 

        //
        // If found, remember HB info. If not found, ignore.
        //

        if (connection != 0) {
        
          spindump_analyze_process_sctp_marksent_hb(connection, fromResponder, &packet->timestamp);
          
        } else {

          state->stats->unknownSctpConnection++;
          *p_connection = 0;
          return;

        }
        break; // HB
      case spindump_sctp_chunk_type_heartbeat_ack:
        // HEARTBEAT ACK (HB ACK) 

        //
        // If found, process it to calculate RTT. If not found, ignore.
        //

        if (connection != 0) {
        
          spindump_analyze_process_sctp_markackreceived_hb(state,
                                                           packet,
                                                           connection,
                                                           fromResponder,
                                                           &packet->timestamp);
        } else {


          state->stats->unknownSctpConnection++;
          *p_connection = 0;
          return;

        } 
        break;
      default:
        spindump_deepdebugf("sctp chunk hasn't been processed by spindump");
        break;
    }
  }

  if ( 0 == nParsedChunks ) {

    state->stats->notEnoughPacketForSctpHdr++;
    spindump_warnf("not enough payload bytes for a SCTP chunk", remainingLen);
    *p_connection = 0;
    return;

  } 

  //
  // Call some handlers based on what happened here, if needed
  //

  if (new) {
    spindump_analyze_process_handlers(state,spindump_analyze_event_newconnection,packet,connection);
  } else {
    spindump_analyze_process_pakstats(state,connection,fromResponder,packet,ipPacketLength,ecnFlags);
  }

  *p_connection = connection;
  return;
}
