
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
//  AUTHOR: MAKSIM PROSHIN
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
// if the packet is the first in a flow, e.g., TBD).
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
                              unsigned int tcpHeaderPosition,
                              unsigned int tcpLength,
                              unsigned int remainingCaplen,
                              struct spindump_connection** p_connection) {

  spindump_deepdebugf("==>spindump_analyze_process_sctp(): Inside the func!");
  
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

  
}
