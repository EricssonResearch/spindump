
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

void
spindump_analyze_process_icmp(struct spindump_analyze* state,
			      struct spindump_packet* packet,
			      unsigned int ipHeaderPosition,
			      unsigned int ipHeaderSize,
			      uint8_t ipVersion,
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
  if (icmpLength <= 4) {
    state->stats->notEnoughPacketForIcmpHdr++;
    spindump_warnf("not enough payload bytes for an ICMP header", icmpLength);
    *p_connection = 0;
    return;
  }
  unsigned int hdrsize_icmp = spindump_max(4,icmpLength);
  if (hdrsize_icmp < 4) {
    state->stats->invalidIcmpHdrSize++;
    spindump_warnf("ICMP header length %u invalid", hdrsize_icmp);
    *p_connection = 0;
    return;
  }
  const struct spindump_icmp* icmp = (const struct spindump_icmp*)(packet->contents + icmpHeaderPosition);
  spindump_debugf("received an IPv%u ICMP packet of %u bytes",
		  ipVersion,
		  packet->etherlen);
  
  uint8_t peerType = icmp->ih_type;
  
  switch (peerType) {
  case ICMP_ECHO:
    if (icmp->ih_code != 0) {
      state->stats->invalidIcmpCode++;
      *p_connection = 0;
      return;
    }
    state->stats->receivedIcmpEcho++;
    spindump_deepdebugf("received ICMP ECHO request for id=%u seq=%u",
			ntohs(icmp->ih_u.ih_echo.ih_id),
			ntohs(icmp->ih_u.ih_echo.ih_seq));
    break;
    
  case ICMP_ECHOREPLY:
    if (icmp->ih_code != 0) {
      state->stats->invalidIcmpCode++;
      *p_connection = 0;
      return;
    }
    state->stats->receivedIcmpEcho++;
    spindump_deepdebugf("received ICMP ECHO reply for id=%u seq=%u",
			ntohs(icmp->ih_u.ih_echo.ih_id),
			ntohs(icmp->ih_u.ih_echo.ih_seq));
    break;
    
  default:
    state->stats->unsupportedIcmpType++;
    *p_connection = 0;
    return;
  }
  
  //
  // Check whether this is an ICMP ECHO or ECHO REPLY and if so, proceed
  // 
  
  if (peerType == ICMP_ECHO ||
      peerType == ICMP_ECHOREPLY) {
    
    spindump_address source;
    spindump_address destination;
    uint16_t peerId = icmp->ih_u.ih_echo.ih_id;
    uint16_t peerSeq = icmp->ih_u.ih_echo.ih_seq;
    
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
	state->stats->connections++;
	state->stats->connectionsIcmp++;
	
      }
    }

    //
    // Mark the reception of a packet in the connection
    // 
    
    if (peerType == ICMP_ECHOREPLY) {
      
      if (connection->state == spindump_connection_state_establishing) {
	spindump_connections_changestate(state,packet,connection,spindump_connection_state_established);
      }

      spindump_analyze_process_pakstats(state,connection,1,packet,ipPacketLength);
      if (peerSeq == connection->u.icmp.side1peerLatestSequence) {
	spindump_connections_newrttmeasurement(state,
					       packet,
					       connection,
					       1,
					       &connection->latestPacketFromSide1,
					       &connection->latestPacketFromSide2,
					       "ICMP echo reply");
      }
      
    } else {
      
      spindump_analyze_process_pakstats(state,connection,0,packet,ipPacketLength);
      connection->u.icmp.side1peerLatestSequence = peerSeq;
      
    }
    
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

void
spindump_analyze_process_icmp6(struct spindump_analyze* state,
			       struct spindump_packet* packet,
			       unsigned int ipHeaderPosition,
			       unsigned int ipHeaderSize,
			       uint8_t ipVersion,
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
  if (icmpLength <= 4) {
    state->stats->notEnoughPacketForIcmpHdr++;
    spindump_warnf("not enough payload bytes for an ICMPv6 header", icmpLength);
    *p_connection = 0;
    return;
  }
  const struct spindump_icmpv6* icmp6 = (const struct spindump_icmpv6*)(packet->contents + icmpHeaderPosition);
  unsigned int hdrsize_icmp6 = spindump_max(4,icmpLength);
  if (hdrsize_icmp6 < 4) {
    state->stats->invalidIcmpHdrSize++;
    spindump_warnf("ICMPv6 header length %u invalid", hdrsize_icmp6);
    *p_connection = 0;
    return;
  }
  spindump_debugf("received an IPv%u ICMP packet of %u bytes",
		  ipVersion,
		  packet->etherlen);
  
  uint8_t peerType = icmp6->ih6_type;
  
  switch (peerType) {
  case ICMP6_ECHO_REQUEST:
    if (icmp6->ih6_code != 0) {
      state->stats->invalidIcmpCode++;
      *p_connection = 0;
      return;
    }
    state->stats->receivedIcmpEcho++;
    spindump_deepdebugf("received ICMP ECHO request for id=%u seq=%u",
			ntohs(icmp6->ih6_u.ih6_echo.ih6_id),
			ntohs(icmp6->ih6_u.ih6_echo.ih6_seq));
    break;
    
  case ICMP6_ECHO_REPLY:
    if (icmp6->ih6_code != 0) {
      state->stats->invalidIcmpCode++;
      *p_connection = 0;
      return;
    }
    state->stats->receivedIcmpEcho++;
    spindump_deepdebugf("received ICMP ECHO reply for id=%u seq=%u",
			ntohs(icmp6->ih6_u.ih6_echo.ih6_id),
			ntohs(icmp6->ih6_u.ih6_echo.ih6_seq));
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
    uint16_t peerId = icmp6->ih6_u.ih6_echo.ih6_id;
    uint16_t peerSeq = icmp6->ih6_u.ih6_echo.ih6_seq;

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
	state->stats->connections++;
	state->stats->connectionsIcmp++;
      }
    }

    //
    // Mark the reception of a packet in the connection
    // 
    
    if (peerType == ICMP6_ECHO_REPLY) {
      
      spindump_analyze_process_pakstats(state,connection,1,packet,ipPacketLength);
      if (connection->state == spindump_connection_state_establishing) {
	spindump_connections_changestate(state,packet,connection,spindump_connection_state_established);
      }
      if (peerSeq == connection->u.icmp.side1peerLatestSequence) {
	spindump_connections_newrttmeasurement(state,
					       packet,
					       connection,
					       1,
					       &connection->latestPacketFromSide1,
					       &connection->latestPacketFromSide2,
					       "ICMPv6 ECHO reply");
      }
      
    } else {
      
      spindump_analyze_process_pakstats(state,connection,0,packet,ipPacketLength);
      connection->u.icmp.side1peerLatestSequence = peerSeq;
      
    }
    
    *p_connection = connection;
    
  } else {
    
    *p_connection = 0;
    
  }

}
