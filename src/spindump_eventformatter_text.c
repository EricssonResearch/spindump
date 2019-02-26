
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
#include "spindump_eventformatter_text.h"

//
// Print what is needed as a preface to the actual records
//

void
spindump_eventformatter_measurement_begin_text(struct spindump_eventformatter* formatter) {
}

//
// Print what is needed as an end after the actual records
//

void
spindump_eventformatter_measurement_end_text(struct spindump_eventformatter* formatter) {
}

//
// Print out one --textual measurement event, when the format is set
// to --format text
//

void
spindump_eventformatter_measurement_one_text(struct spindump_eventformatter* formatter,
					     spindump_analyze_event event,
					     struct spindump_connection* connection,
					     const char* type,
					     const char* addrs,
					     const char* session,
					     const struct timeval* timestamp) {
  
  char buf[250];
  char what[100];
  char rttbuf1[20];
  char rttbuf2[20];

  //
  // Construct the time stamp
  //

  const char* when = spindump_timetostring(timestamp);

  //
  // Get the (variable) data related to the specific event (such as a
  // spin flip in a QUIC connection).
  //

  memset(what,0,sizeof(what));
  switch (event) {

  case spindump_analyze_event_newconnection:
    spindump_strlcpy(what,"new connection",sizeof(what));
    break;

  case spindump_analyze_event_connectiondelete:
    spindump_strlcpy(what,"connection deleted",sizeof(what));
    break;

  case spindump_analyze_event_newleftrttmeasurement:
  case spindump_analyze_event_newrightrttmeasurement:
    spindump_strlcpy(rttbuf1,spindump_rtt_tostring(connection->leftRTT.lastRTT),sizeof(rttbuf1));
    spindump_strlcpy(rttbuf2,spindump_rtt_tostring(connection->rightRTT.lastRTT),sizeof(rttbuf2));
    memset(what,0,sizeof(what));
    snprintf(what,sizeof(what)-1,"left %s right %s",
	     rttbuf1, rttbuf2);
    break;

  case spindump_analyze_event_newinitrespfullrttmeasurement:
    spindump_strlcpy(rttbuf1,spindump_rtt_tostring(connection->initToRespFullRTT.lastRTT),sizeof(rttbuf1));
    memset(what,0,sizeof(what));
    snprintf(what,sizeof(what)-1,"full RTT, init to resp %s", rttbuf1);
    break;

  case spindump_analyze_event_newrespinitfullrttmeasurement:
    spindump_strlcpy(rttbuf1,spindump_rtt_tostring(connection->respToInitFullRTT.lastRTT),sizeof(rttbuf1));
    memset(what,0,sizeof(what));
    snprintf(what,sizeof(what)-1,"full RTT, resp to init %s", rttbuf1);
    break;

  case spindump_analyze_event_initiatorspinflip:
    spindump_strlcpy(what,"initiator spin flip",sizeof(what));
    break;

  case spindump_analyze_event_responderspinflip:
    spindump_strlcpy(what,"responder spin flip",sizeof(what));
    break;

  case spindump_analyze_event_initiatorspinvalue:
    snprintf(what,sizeof(what)-1,"initiator spin %u",
	     connection->u.quic.spinFromPeer1to2.lastSpin);
    break;

  case spindump_analyze_event_responderspinvalue:
    snprintf(what,sizeof(what)-1,"responder spin %u",
	     connection->u.quic.spinFromPeer2to1.lastSpin);
    break;

  case spindump_analyze_event_initiatorecnce:
    snprintf(what,sizeof(what)-1,"ECN CE Initiator");
    break;

  case spindump_analyze_event_responderecnce:
    snprintf(what,sizeof(what)-1,"ECN CE Responder");
    break;

  default:
    return;
  }

  //
  // With all the information collected, put that now in final text
  // format, hold it in "buf"
  //

  memset(buf,0,sizeof(buf));
  snprintf(buf,sizeof(buf)-1,"%s %s %s at %s %s",
	   type, addrs, session, when, what);

  //
  // Print the buffer out
  //

  fprintf(formatter->file,"%s\n", buf);
}
