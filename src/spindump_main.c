
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

#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>
#include "spindump_util.h"
#include "spindump_capture.h"
#include "spindump_analyze.h"
#include "spindump_report.h"
#include "spindump_remote.h"
#include "spindump_main.h"

//
// Configuration variables --------------------------------------------------------------------
//

static const char* interface = 0;
static const char* inputFile = 0;
static char* filter = 0;
enum spindump_toolmode {
  spindump_toolmode_silent,
  spindump_toolmode_textual,
  spindump_toolmode_visual
};
static enum spindump_toolmode toolmode = spindump_toolmode_visual;
enum spindump_outputformat {
  spindump_outputformat_text,
  spindump_outputformat_json
};
static enum spindump_outputformat format = spindump_outputformat_text;
static unsigned int maxReceive = 0;
static int showStats = 0;
static int reverseDns = 0;
static int reportSpins = 0;
static int reportSpinFlips = 0;
static int anonymizeLeft = 0;
static int anonymizeRight = 0;
static unsigned long long updateperiod = 0.5 * 1000 * 1000; // 0.5s//
static unsigned int nAggregates = 0;
static struct spindump_main_aggregate aggregates[spindump_main_maxnaggregates];

//
// Other Variables ----------------------------------------------------------------------------
//

static int interrupt = 0;
static unsigned int nRemotes = 0;
static struct spindump_remote_client* remotes[SPINDUMP_REMOTE_CLIENT_MAX_CONNECTIONS];
static FILE* debugfile = 0;

//
// Function prototypes ------------------------------------------------------------------------
//

static void
help();
static void
spindump_main_processargs(int argc,char** argv);
static void
spindump_main_operation();
static enum spindump_outputformat
spindump_main_parseformat(const char* string);
static void
spindump_main_textualmeasurement_text(spindump_analyze_event event,
				      struct spindump_connection* connection,
				      const char* type,
				      const char* addrs,
				      const char* session,
				      const struct timeval* timestamp);
static void
spindump_main_textualmeasurement_json(spindump_analyze_event event,
				      struct spindump_connection* connection,
				      const char* type,
				      const char* addrs,
				      const char* session,
				      const struct timeval* timestamp);

//
// Actual code --------------------------------------------------------------------------------
//

//
// Interrupts (Ctrl-C) during program execution
// should cause the current probing process to end
// and results printed out.
//

static void
spindump_main_interrupt(int dummy) {
  interrupt = 1;
}

//
// Process command line arguments for the spindump command
//

static void
spindump_main_processargs(int argc,char** argv) {
  argc--; argv++;
  while (argc > 0) {

    if (strcmp(argv[0],"--version") == 0) {

      printf("version 0.11 January 22, 2019\n");
      exit(0);

    } else if (strcmp(argv[0],"--help") == 0) {

      help();
      exit(0);

    } else if (strcmp(argv[0],"--debug") == 0) {

      debug = 1;

    } else if (strcmp(argv[0],"--no-debug") == 0) {

      debug = 0;
      deepdebug = 0;

    } else if (strcmp(argv[0],"--deepdebug") == 0) {

      debug = 1;
      deepdebug = 1;

    } else if (strcmp(argv[0],"--no-deepdebug") == 0) {

      deepdebug = 0;

    } else if (strcmp(argv[0],"--stats") == 0) {

      showStats = 1;

    } else if (strcmp(argv[0],"--no-stats") == 0) {

      showStats = 0;

    } else if (strcmp(argv[0],"--names") == 0) {

      reverseDns = 1;

    } else if (strcmp(argv[0],"--addresses") == 0) {

      reverseDns = 0;

    } else if (strcmp(argv[0],"--report-spins") == 0) {

      reportSpins = 1;

    } else if (strcmp(argv[0],"--not-report-spins") == 0) {

      reportSpins = 0;

    } else if (strcmp(argv[0],"--report-spin-flips") == 0) {

      reportSpinFlips = 1;

    } else if (strcmp(argv[0],"--not-report-spin-flips") == 0) {

      reportSpinFlips = 0;

    } else if (strcmp(argv[0],"--anonymize") == 0) {

      anonymizeLeft = 1;
      anonymizeRight = 1;

    } else if (strcmp(argv[0],"--not-anonymize") == 0) {

      anonymizeLeft = 0;
      anonymizeRight = 0;

    } else if (strcmp(argv[0],"--anonymize-left") == 0) {

      anonymizeLeft = 1;

    } else if (strcmp(argv[0],"--not-anonymize-left") == 0) {

      anonymizeLeft = 0;

    } else if (strcmp(argv[0],"--anonymize-right") == 0) {

      anonymizeRight = 1;

    } else if (strcmp(argv[0],"--not-anonymize-right") == 0) {

      anonymizeRight = 0;

    } else if (strcmp(argv[0],"--silent") == 0) {

      toolmode = spindump_toolmode_silent;

    } else if (strcmp(argv[0],"--textual") == 0) {

      toolmode = spindump_toolmode_textual;

    } else if (strcmp(argv[0],"--visual") == 0) {

      toolmode = spindump_toolmode_visual;

    } else if (strcmp(argv[0],"--interface") == 0 && argc > 1) {

      interface = argv[1];
      argc--; argv++;

    } else if (strcmp(argv[0],"--format") == 0 && argc > 1) {

      format = spindump_main_parseformat(argv[1]);
      argc--; argv++;

    } else if (strcmp(argv[0],"--input-file") == 0 && argc > 1) {

      inputFile = argv[1];
      argc--; argv++;

    } else if (strcmp(argv[0],"--remote") == 0 && argc > 1) {

      if (nRemotes == SPINDUMP_REMOTE_CLIENT_MAX_CONNECTIONS) {
	spindump_fatalf("too many --remote connections");
	exit(1);
      }

      remotes[nRemotes++] = spindump_remote_client_init(argv[1]);
      argc--; argv++;

    } else if (strcmp(argv[0],"--max-receive") == 0 && argc > 1) {

      if (!isdigit(*(argv[1]))) {
	spindump_fatalf("expected a numeric argument for --max-receive, got %s", argv[1]);
	exit(1);
      }
      maxReceive = atoi(argv[1]);
      argc--; argv++;

    } else if (strcmp(argv[0],"--aggregate") == 0 && argc > 1) {

      //
      // Get the first of the two arguments
      //

      const char* side1string = argv[1];

      //
      // Determine whether the first argument is host or a network or a group
      //

      int side1ishost = (index(side1string,'/') == 0);
      int side1isgroup;

      //
      // Parse the first argument
      //

      spindump_address side1address;
      spindump_network side1network;

      if (side1ishost) {
	if (!spindump_address_fromstring(&side1address,side1string)) {
	  spindump_fatalf("expected an address as first argument for --aggregate, got %s", side1string);
	  exit(1);
	}
	side1isgroup = spindump_address_ismulticast(&side1address);
      } else {
	if (!spindump_network_fromstring(&side1network,side1string)) {
	  spindump_fatalf("expected a network as first argument bor --aggregate, got %s", side1string);
	  exit(1);
	}
	side1isgroup = spindump_network_ismulticast(&side1network);
      }

      spindump_deepdebugf("side1isgroup = %u side1ishost = %u", side1isgroup, side1ishost);

      //
      // Move past the first argument
      //

      argc--; argv++;

      //
      // Determine if we need a second argument (we don't if it is a
      // group). Get the second of the two arguments
      //

      int side2ishost = 0;
      spindump_address side2address;
      spindump_network side2network;

      if (!side1isgroup) {

	if (!(argc > 1)) {
	  spindump_fatalf("expected two addresses or networks as arguments to --aggregate, got just one (%s)",
			  side1string);
	  exit(1);
	}

	const char* side2string = argv[1];

	//
	// Determine whether the second argument is host or a network
	//

	side2ishost = (index(side2string,'/') == 0);

	//
	// Parse the second argument
	//

	if (side2ishost) {
	  if (!spindump_address_fromstring(&side2address,side2string)) {
	    spindump_fatalf("expected an address as second argument for --aggregate, got %s", side2string);
	    exit(1);
	  }
	} else {
	  if (!spindump_network_fromstring(&side2network,side2string)) {
	    spindump_fatalf("expected a network as second argument for --aggregate, got %s", side2string);
	    exit(1);
	  }
	}

	//
	// Move past the second argument
	//

	argc--; argv++;

      }

      //
      // Add the aggregste to the aggregate list, for the actual
      // aggregsate to be created later.
      //

      if (nAggregates >= spindump_main_maxnaggregates) {
	  spindump_fatalf("too many aggregates specified, can only support %u",
			  spindump_main_maxnaggregates);
	  exit(1);
      }

      struct spindump_main_aggregate* aggregate = &aggregates[nAggregates++];
      aggregate->ismulticastgroup = side1isgroup;
      aggregate->side1ishost = side1ishost;
      aggregate->side2ishost = side2ishost;
      aggregate->side1address = side1address;
      aggregate->side2address = side2address;
      aggregate->side1network = side1network;
      aggregate->side2network = side2network;

    } else if (argv[0][0] == '-') {

      spindump_fatalf("unrecognised option %s", argv[0]);

    } else {

      //
      // The extra arguments are all part of a filter. Collect all
      // components of the filter, and store them for later use in
      // PCAP.
      //

      if (filter == 0) {

	//
	// No filter components seen before. Allocate a fresh string.
	//

	spindump_deepdebugf("initial filter component...");
	filter = strdup(argv[0]);
	if (filter == 0) {
	  spindump_fatalf("Cannot allocate %u bytes", strlen(argv[0])+1);
	  exit(1);
	}

      } else {

	//
	// Additional components to a filter that has already begun in
	// previous arguments.
	//

	spindump_deepdebugf("additional filter components...");
	const char* prevfilter = filter;
	unsigned int n = strlen(prevfilter) + 1 + strlen(argv[0]) + 1;
	filter = malloc(n);

	if (filter == 0) {
	  spindump_fatalf("Cannot allocate %u bytes", n);
	  exit(1);
	} else {
	  strcpy(filter,prevfilter);
	  strcat(filter," ");
	  strcat(filter,argv[0]);
	  free((void*)prevfilter);
	}
      }

    }

    argc--; argv++;

  }

}

//
// Function that gets called whenever a new RTT data has come in for
// any connection.  This is activated when the --textual mode is on.
//

void
spindump_main_textualmeasurement(struct spindump_analyze* state,
				 void* handlerData,
				 void** handlerConnectionData,
				 spindump_analyze_event event,
				 struct spindump_packet* packet,
				 struct spindump_connection* connection) {

  if (toolmode != spindump_toolmode_textual) return;

  struct spindump_reverse_dns* querier = (struct spindump_reverse_dns*)handlerData;
  const char* type = spindump_connection_type_to_string(connection->type);
  const char* addrs = spindump_connection_addresses(connection,70,anonymizeLeft,anonymizeRight,querier);
  const char* session = spindump_connection_sessionstring(connection,70);

  switch (format) {
  case spindump_outputformat_text:
    spindump_main_textualmeasurement_text(event,connection,type,addrs,session,&packet->timestamp);
    break;
  case spindump_outputformat_json:
    spindump_main_textualmeasurement_json(event,connection,type,addrs,session,&packet->timestamp);
    break;
  default:
    spindump_fatalf("invalid output format in internal variable");
    exit(1);
  }
}

//
// Print out one --textual measurement event, when the format is set
// to --format text
//

static void
spindump_main_textualmeasurement_text(spindump_analyze_event event,
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

  printf("%s\n", buf);
}

//
// Print out one --textual measurement event, when the format is set
// to --format json
//

static void
spindump_main_textualmeasurement_json(spindump_analyze_event event,
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
    snprintf(what,sizeof(what)-1,"\"full_rtt_initiator\": %lu", connection->initToRespFullRTT.lastRTT);
    break;

  case spindump_analyze_event_newrespinitfullrttmeasurement:
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
    snprintf(what,sizeof(what)-1,"\"event\": ECN CE Initiator\"");
    break;

  case spindump_analyze_event_responderecnce:
    snprintf(what,sizeof(what)-1,"\"event\": ECN CE Responder\"");
    break;

  default:
    return;

  }

  //
  // With all the information collected, put that now in final text
  // format, hold it in "buf"
  //

  memset(buf,0,sizeof(buf));
  snprintf(buf,sizeof(buf)-1,"{ \"type\": \"%s\", \"addrs\": \"%s\", \"session\": \"%s\", \"ts\": %s,%s \"packets\": %u, \"ECT(0)\": %u, \"ECT(1)\": %u, \"CE\": %u }",
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

  printf("%s\n", buf);

}

//
// Spindump main operation
//

static void
spindump_main_operation() {

  //
  // Initialize the actual operation
  //

  if (interface == 0 && inputFile == 0) {
    interface = spindump_capture_defaultinterface();
    if (interface == 0) exit(1);
  }

  //
  // Initialize packet analyzer
  //

  struct spindump_analyze* analyzer = spindump_analyze_initialize();
  if (analyzer == 0) exit(1);

  //
  // Initialize aggregate collection, as specifie earlier
  //

  struct timeval startTime;
  spindump_getcurrenttime(&startTime);
  for (unsigned int i = 0; i < nAggregates; i++) {
    struct spindump_main_aggregate* aggregate = &aggregates[i];
    spindump_assert(spindump_isbool(aggregate->ismulticastgroup));
    spindump_assert(spindump_isbool(aggregate->side1ishost));
    spindump_assert(spindump_isbool(aggregate->side2ishost));
    struct spindump_connection* aggregateConnection = 0;
    if (aggregate->ismulticastgroup) {
      aggregateConnection = spindump_connections_newconnection_aggregate_multicastgroup(&aggregate->side1address,
											&startTime,
											1,
											analyzer->table);
    } else if (aggregate->side1ishost && aggregate->side2ishost) {
      aggregateConnection = spindump_connections_newconnection_aggregate_hostpair(&aggregate->side1address,
										  &aggregate->side2address,
										  &startTime,
										  1,
										  analyzer->table);
    } else if (aggregate->side1ishost && !aggregate->side2ishost) {
      aggregateConnection = spindump_connections_newconnection_aggregate_hostnetwork(&aggregate->side1address,
										     &aggregate->side2network,
										     &startTime,
										     1,
										     analyzer->table);
    } else if (!aggregate->side1ishost && aggregate->side2ishost) {
      aggregateConnection = spindump_connections_newconnection_aggregate_hostnetwork(&aggregate->side2address,
										     &aggregate->side1network,
										     &startTime,
										     1,
										     analyzer->table);
    } else if (!aggregate->side1ishost && !aggregate->side2ishost) {
      aggregateConnection = spindump_connections_newconnection_aggregate_networknetwork(&aggregate->side1network,
											&aggregate->side2network,
											&startTime,
											1,
											analyzer->table);
    }
    if (aggregateConnection != 0) {
      spindump_deepdebugf("created a manually configured aggregate connection %u", aggregateConnection->id);
    }
  }

  //
  // Initialize the capture interface
  //

  struct spindump_capture_state* capturer =
    (inputFile == 0 ?
     spindump_capture_initialize(interface,filter) :
     spindump_capture_initialize_file(inputFile,filter));

  if (capturer == 0) exit(1);

  //
  // Initialize the user interface
  //

  spindump_seterrordestination(debugfile);
  int averageMode = 0;
  int aggregateMode = 0;
  int closedMode = 1;
  int udpMode = 0;
  struct spindump_reverse_dns* querier =
    reverseDns ?
    spindump_reverse_dns_initialize_full() :
    spindump_reverse_dns_initialize_noop();
  struct spindump_report_state* reporter =
    (toolmode != spindump_toolmode_visual ?
     spindump_report_initialize_quiet() :
     spindump_report_initialize_terminal(querier));
  if (reporter == 0) exit(1);
  spindump_report_setanonymization(reporter,anonymizeLeft,anonymizeRight);

  //
  // Initialize the spindump server, if running silent
  //

  struct spindump_remote_server* server = 0;
  if (toolmode == spindump_toolmode_silent) {
    server = spindump_remote_server_init();
  }

  //
  // Draw screen once before waiting for packets
  //

  spindump_report_update(reporter,averageMode,
			 aggregateMode,
			 closedMode,
			 udpMode,
			 analyzer->table,
			 spindump_analyze_getstats(analyzer));

  //
  // If we are in the textual output mode, setup handlers to
  // track new RTT measurements.
  //

  if (toolmode == spindump_toolmode_textual) {
    spindump_analyze_registerhandler(analyzer,
				     spindump_analyze_event_alllegal,
				     spindump_main_textualmeasurement,
				     querier);
  }

  //
  // Main operation
  //

  struct timeval now;
  struct timeval previousPacketTimestamp;
  struct timeval previousupdate;
  spindump_zerotime(&previousPacketTimestamp);
  spindump_zerotime(&previousupdate);
  struct spindump_packet* packet = 0;
  int more = 1;

  while (!interrupt &&
	 more &&
	 (maxReceive == 0 ||
	  spindump_analyze_getstats(analyzer)->receivedFrames < maxReceive)) {

    //
    // Get a packet, if any. Analyze it.
    //

    spindump_capture_nextpacket(capturer,&packet,&more,spindump_analyze_getstats(analyzer));
    spindump_assert(spindump_isbool(more));

    if (packet != 0) {
      struct spindump_connection* connection = 0;
      spindump_analyze_process(analyzer,
			       spindump_capture_getlinktype(capturer),
			       packet,
			       &connection);
    }

    //
    // Get current time, ensure that different timer perceptions in
    // the system (on network card and in the CPUs) do not lead to
    // time ever going back
    //

    if (inputFile != 0) {
      if (packet != 0) {
	       now = previousPacketTimestamp = packet->timestamp;
      } else {
	       now = previousPacketTimestamp;
      }
    } else {
      spindump_getcurrenttime(&now);
    }

    spindump_assert(now.tv_sec > 0);
    spindump_assert(now.tv_usec <= 1000 * 1000);

    //
    // See if we need to do any periodic maintenance (timeouts etc) of
    // the set of connections we have.
    //

    if (spindump_connectionstable_periodiccheck(analyzer->table,
						&now,
						analyzer)) {
      if (server != 0) spindump_remote_server_update(server,analyzer->table);
      for (unsigned int i = 0; i < nRemotes; i++) {
	spindump_remote_client_update(remotes[i],analyzer->table);
      }
    }

    //
    // See if it is time to update the screen periodically
    //

    if (spindump_iszerotime(&previousupdate) ||
	spindump_timediffinusecs(&now,&previousupdate) >= updateperiod) {
      
      spindump_report_update(reporter,
			     averageMode,
			     aggregateMode,
			     closedMode,
			     udpMode,
			     analyzer->table,
			     spindump_analyze_getstats(analyzer));
      if (spindump_isearliertime(&now,&previousupdate)) previousupdate = now;
      
    }

    //
    // Check if we have any user input
    //

    double commandArgument;
    enum spindump_report_command command = spindump_report_checkinput(reporter,&commandArgument);
    switch (command) {
    case spindump_report_command_quit:
      interrupt = 1;
      break;
    case spindump_report_command_help:
      spindump_report_showhelp(reporter);
      break;
    case spindump_report_command_toggle_average:
      averageMode = !averageMode;
      break;
    case spindump_report_command_toggle_aggregate:
      aggregateMode = !aggregateMode;
      break;
    case spindump_report_command_toggle_closed:
      closedMode = !closedMode;
      break;
    case spindump_report_command_toggle_udp:
      udpMode = !udpMode;
      break;
    case spindump_report_command_update_interval:
      updateperiod = floor(commandArgument * 1000 * 1000);
      break;
    case spindump_report_command_none:
      break;
    default:
      spindump_errorf("invalid command");
      break;
    }
    if (command != spindump_report_command_none) {
      spindump_report_update(reporter,
			     averageMode,
			     aggregateMode,
			     closedMode,
			     udpMode,
			     analyzer->table,
			     spindump_analyze_getstats(analyzer));
    }
  }

  //
  // Done
  //

  if (showStats || debug) {
    spindump_stats_report(spindump_analyze_getstats(analyzer),stdout);
    spindump_connectionstable_report(analyzer->table,stdout,querier);
  }
  spindump_report_uninitialize(reporter);
  spindump_analyze_uninitialize(analyzer);
  spindump_capture_uninitialize(capturer);
  spindump_reverse_dns_uninitialize(querier);
}

//
// The main program
//

int main(int argc,char** argv) {

  //
  // Initialize
  //

  signal(SIGINT, spindump_main_interrupt);
  srand(time(0));
  debugfile = stderr;

  //
  // Process arguments
  //

  spindump_main_processargs(argc, argv);

  //
  // Check where debug printouts should go
  //

  if (toolmode != spindump_toolmode_silent && debug) {
    debugfile = fopen("spindump.debug","w");
    if (debugfile == 0) {
      spindump_fatalf("cannot open debug file");
      exit(1);
    }
    spindump_setdebugdestination(debugfile);
  }

  //
  // Main operation
  //

  spindump_main_operation();

  //
  // Done successfully, exit
  //

  exit(0);
}

//
// Print out help
//

static void
help() {

  printf("Usage:\n");
  printf("  \n");
  printf("    spindump [options] [filter]\n");
  printf("\n");
  printf("If no options or filter is specified, Spindump will look at all packets\n");
  printf("on the default interface. For the filter syntax, see pcap-filter(7).\n");
  printf("\n");
  printf("The options are as follows:\n");
  printf("\n");
  printf("    --silent              Sets the tool to be either silent, list RTT measurements\n");
  printf("    --textual             as they occur, or have a continuously updating visual\n");
  printf("    --visual              interface. The visual interface is the default.\n");
  printf("\n");
  printf("    --names               Use DNS names or addresses in the output. (The default is\n");
  printf("    --addresses           using names.)\n");
  printf("\n");
  printf("    --report-spins        Report individual spin bit changes in --textual mode.\n");
  printf("    --not-report-spins\n");
  printf("\n");
  printf("    --anonymize           Anonymization control.\n");
  printf("    --not-anonymize\n");
  printf("    --anonymize-left\n");
  printf("    --not-anonymize-left\n");
  printf("    --anonymize-right\n");
  printf("    --not-anonymize-right\n");
  printf("\n");
  printf("    --no-stats            Produces statistics at the end of the execution.\n");
  printf("    --stats\n");
  printf("\n");
  printf("    --max-receive n       Sets a limit of how many packets the tool accepts.\n");
  printf("\n");
  printf("    --interface i         Set the interface to listen on, or the capture\n");
  printf("    --input-file f        file to read from.\n");
  printf("    --remote h            Get connections information from spindump running at host h\n");
  printf("  \n");
  printf("    --debug               Sets the debugging output on/off.\n");
  printf("    --no-debug\n");
  printf("  \n");
  printf("    --deepdebug           Sets the extensive internal debugging output on/off.\n");
  printf("    --no-deepdebug\n");
  printf("\n");
  printf("    --help                Outputs information about the command usage and options.\n");
  printf("  \n");
  printf("    --version             Outputs the version number\n");
  printf("\n");
}

//
// Parse a request to use a particular output format. Call an error if
// the input is invalid.
//

static enum spindump_outputformat
spindump_main_parseformat(const char* string) {
  spindump_assert(string != 0);
  if (strcmp(string,"text") == 0) {
    return(spindump_outputformat_text);
  } else if (strcmp(string,"json") == 0) {
    return(spindump_outputformat_json);
  } else {
    spindump_fatalf("invalid output format (%s) specified, expected text or json", string);
    return(spindump_outputformat_text);
  }
}
