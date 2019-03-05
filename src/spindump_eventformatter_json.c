
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "spindump_util.h"
#include "spindump_eventformatter.h"
#include "spindump_eventformatter_json.h"

//
// Return the length of the preamble
//

unsigned long
spindump_eventformatter_measurement_beginlength_json(struct spindump_eventformatter* formatter) {
  return(2);
}

//
// Print what is needed as a preface to the actual records
//

const uint8_t*
spindump_eventformatter_measurement_begin_json(struct spindump_eventformatter* formatter) {
  return((uint8_t*)"[\n");
}

//
// Return the length of the postamble
//

unsigned long
spindump_eventformatter_measurement_endlength_json(struct spindump_eventformatter* formatter) {
  return(2);
}

//
// Print what is needed as an end after the actual records
//

const uint8_t*
spindump_eventformatter_measurement_end_json(struct spindump_eventformatter* formatter) {
  return((uint8_t*)"]\n");
}

//
// Print out one --textual measurement event, when the format is set
// to --format json
//

void
spindump_eventformatter_measurement_one_json(struct spindump_eventformatter* formatter,
					     spindump_analyze_event event,
					     struct spindump_connection* connection,
					     const char* type,
					     const char* addrs,
					     const char* session,
					     const struct timeval* timestamp) {
  
  char buf[250];
  char what[100];
  char when[40];

  //
  // Construct the time stamp
  //

  snprintf(when,sizeof(when)-1,"%llu",
	   ((unsigned long long)timestamp->tv_sec) * 1000 * 1000 + (unsigned long long)timestamp->tv_usec);

  //
  // Get the (variable) data related to the specific event (such as a
  // spin flip in a QUIC connection).
  //

  memset(what,0,sizeof(what));

  switch (event) {

  case spindump_analyze_event_newconnection:
    spindump_strlcpy(what,"\"event\": \"new\",",sizeof(what));
    break;

  case spindump_analyze_event_connectiondelete:
    spindump_strlcpy(what,"\"event\": \"delete\",",sizeof(what));
    break;

  case spindump_analyze_event_newleftrttmeasurement:
  case spindump_analyze_event_newrightrttmeasurement:
    snprintf(what,sizeof(what)-1,"\"event\": \"measurement\", ");
    if (connection->leftRTT.lastRTT != spindump_rtt_infinite &&
	connection->rightRTT.lastRTT != spindump_rtt_infinite) {
      unsigned long sumRtt = connection->leftRTT.lastRTT + connection->rightRTT.lastRTT;
      snprintf(what+strlen(what),sizeof(what)-strlen(what)-1," \"sum_rtt\": %lu,",
	       sumRtt);
    }
    if (connection->leftRTT.lastRTT != spindump_rtt_infinite) {
      snprintf(what+strlen(what),sizeof(what)-strlen(what)-1," \"left_rtt\": %lu,",
	       connection->leftRTT.lastRTT);
    }
    if (connection->rightRTT.lastRTT != spindump_rtt_infinite) {
      snprintf(what+strlen(what),sizeof(what)-strlen(what)-1," \"right_rtt\": %lu,",
	       connection->rightRTT.lastRTT);
    }
    break;

  case spindump_analyze_event_newinitrespfullrttmeasurement:
    snprintf(what,sizeof(what)-1,"\"event\": \"measurement\", ");
    snprintf(what,sizeof(what)-1,"\"full_rtt_initiator\": %lu", connection->initToRespFullRTT.lastRTT);
    break;

  case spindump_analyze_event_newrespinitfullrttmeasurement:
    snprintf(what,sizeof(what)-1,"\"event\": \"measurement\", ");
    snprintf(what,sizeof(what)-1,"\"full_rtt_responder\": %lu", connection->respToInitFullRTT.lastRTT);
    break;

  case spindump_analyze_event_initiatorspinflip:
    spindump_assert(connection->type == spindump_connection_transport_quic);
    snprintf(what,sizeof(what)-1,"\"event\": \"spinflip\", \"transition\": \"%s\", \"who\": \"%s\",",
	     connection->u.quic.spinFromPeer1to2.lastSpin ? "0-1" : "1-0",
	     "initiator");
    break;

  case spindump_analyze_event_responderspinflip:
    spindump_assert(connection->type == spindump_connection_transport_quic);
    snprintf(what,sizeof(what)-1,"\"event\": \"spinflip\", \"transition\": \"%s\", \"who\": \"%s\",",
	     connection->u.quic.spinFromPeer2to1.lastSpin ? "0-1" : "1-0",
	     "responder");
    break;

  case spindump_analyze_event_initiatorspinvalue:
    spindump_assert(connection->type == spindump_connection_transport_quic);
    snprintf(what,sizeof(what)-1,"\"event\": \"spin\", \"value\": \"%u\", \"who\": \"%s\",",
	     connection->u.quic.spinFromPeer1to2.lastSpin,
	     "initiator");
    break;

  case spindump_analyze_event_responderspinvalue:
    spindump_assert(connection->type == spindump_connection_transport_quic);
    snprintf(what,sizeof(what)-1,"\"event\": \"spin\", \"value\": \"%u\", \"who\": \"%s\",",
	     connection->u.quic.spinFromPeer2to1.lastSpin,
	     "responder");
    break;

  case spindump_analyze_event_initiatorecnce:
    snprintf(what,sizeof(what)-1,"\"event\": \"ECN CE initiator\"");
    break;

  case spindump_analyze_event_responderecnce:
    snprintf(what,sizeof(what)-1,"\"event\": \"ECN CE responder\"");
    break;

  default:
    return;

  }

  //
  // With all the information collected, put that now in final text
  // format, hold it in "buf"
  //

  memset(buf,0,sizeof(buf));
  snprintf(buf,sizeof(buf)-1,"{ \"type\": \"%s\", \"addrs\": \"%s\", \"session\": \"%s\", \"ts\": %s,%s \"packets\": %u, \"ECT(0)\": %u, \"ECT(1)\": %u, \"CE\": %u }\n",
	   type,
	   addrs,
	   session,
	   when,
	   what,
	   connection->packetsFromSide1 + connection->packetsFromSide2,
     connection->ect0FromInitiator + connection->ect0FromResponder,
     connection->ect1FromInitiator + connection->ect1FromResponder,
     connection->ceFromInitiator + connection->ceFromResponder);

  //
  // Print the buffer out
  //
  
  spindump_eventformatter_deliverdata(formatter,strlen(buf),(uint8_t*)buf);
  
}

