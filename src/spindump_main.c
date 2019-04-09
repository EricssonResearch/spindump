
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
#include <sys/types.h>
#include <unistd.h>
#include "spindump_util.h"
#include "spindump_capture.h"
#include "spindump_analyze.h"
#include "spindump_report.h"
#include "spindump_remote_client.h"
#include "spindump_remote_server.h"
#include "spindump_eventformatter.h"
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
static enum spindump_eventformatter_outputformat format = spindump_eventformatter_outputformat_text;
static unsigned int maxReceive = 0;
static int showStats = 0;
static int reverseDns = 0;
static int reportSpins = 0;
static int reportSpinFlips = 0;
static int anonymizeLeft = 0;
static int anonymizeRight = 0;
static unsigned long long updateperiod = 500 * 1000; // 0.5s
static unsigned int nAggregates = 0;
static struct spindump_main_aggregate aggregates[spindump_main_maxnaggregates];

//
// Other Variables ----------------------------------------------------------------------------
//

static int interrupt = 0;
static unsigned int nRemotes = 0;
static struct spindump_remote_client* remotes[SPINDUMP_REMOTE_CLIENT_MAX_CONNECTIONS];
static unsigned long remoteBlockSize = 16 * 1024;
static int collector = 0;
static spindump_port collectorPort = SPINDUMP_PORT_NUMBER;
static FILE* debugfile = 0;

//
// Function prototypes ------------------------------------------------------------------------
//

static void
help(void);
static void
spindump_main_processargs(int argc,char** argv);
static void
spindump_main_operation(void);
static void
spindump_main_packetloop(struct spindump_analyze* analyzer,
			 struct spindump_capture_state* capturer,
			 struct spindump_report_state* reporter,
			 struct spindump_eventformatter* formatter,
			 struct spindump_eventformatter* remoteFormatter,
			 struct spindump_remote_server* server,
			 int averageMode,
			 int aggregateMode,
			 int closedMode,
			 int udpMode);
static enum spindump_eventformatter_outputformat
spindump_main_parseformat(const char* string);
static void
spindump_main_initialize_aggregates(struct spindump_analyze* analyzer);

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

      printf("version 0.30 March 23, 2019\n");
      exit(0);

    } else if (strcmp(argv[0],"--help") == 0) {

      help();
      exit(0);

    } else if (strcmp(argv[0],"--debug") == 0) {

      spindump_debug = 1;

    } else if (strcmp(argv[0],"--no-debug") == 0) {

      spindump_debug = 0;
      spindump_deepdebug = 0;
      spindump_deepdeepdebug = 0;
      
    } else if (strcmp(argv[0],"--deepdebug") == 0) {

      spindump_debug = 1;
      spindump_deepdebug = 1;
      
    } else if (strcmp(argv[0],"--no-deepdebug") == 0) {
      
      spindump_deepdebug = 0;
      spindump_deepdeepdebug = 0;

    } else if (strcmp(argv[0],"--deepdeepdebug") == 0) {

      spindump_debug = 1;
      spindump_deepdebug = 1;
      spindump_deepdeepdebug = 1;
      
    } else if (strcmp(argv[0],"--no-deepdeepdebug") == 0) {
      
      spindump_deepdeepdebug = 0;
      
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
	spindump_errorf("too many --remote connections");
	exit(1);
      }

      remotes[nRemotes++] = spindump_remote_client_init(argv[1]);
      argc--; argv++;

    } else if (strcmp(argv[0],"--collector") == 0) {
      
      collector = 1;
      
    } else if (strcmp(argv[0],"--no-collector") == 0) {
      
      collector = 0;
      
    } else if (strcmp(argv[0],"--collector-port") == 0 && argc > 1) {

      if (!isdigit(*(argv[1]))) {
	spindump_errorf("expected a numeric argument for --collector-port, got %s", argv[1]);
	exit(1);
      }
      int input = atoi(argv[1]);
      if (input <= 1 || input > 65535) {
	spindump_errorf("expected argument for --collector-port to be between 1 and 65535, got %s", argv[1]);
	exit(1);
      }
      collectorPort = (spindump_port)input;
      argc--; argv++;
      
    } else if (strcmp(argv[0],"--remote-block-size") == 0 && argc > 1) {

      if (!isdigit(*(argv[1]))) {
	spindump_errorf("expected a numeric argument for --remote-block-size, got %s", argv[1]);
	exit(1);
      }
      remoteBlockSize = 1024 * (unsigned long)atoi(argv[1]);
      argc--; argv++;
      
    } else if (strcmp(argv[0],"--max-receive") == 0 && argc > 1) {

      if (!isdigit(*(argv[1]))) {
	spindump_errorf("expected a numeric argument for --max-receive, got %s", argv[1]);
	exit(1);
      }
      maxReceive = (unsigned int)atoi(argv[1]);
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

      memset(&side1address,0,sizeof(side1address));
      memset(&side1network,0,sizeof(side1network));
      
      if (side1ishost) {
	if (!spindump_address_fromstring(&side1address,side1string)) {
	  spindump_errorf("expected an address as first argument for --aggregate, got %s", side1string);
	  exit(1);
	}
	side1isgroup = spindump_address_ismulticast(&side1address);
      } else {
	if (!spindump_network_fromstring(&side1network,side1string)) {
	  spindump_errorf("expected a network as first argument bor --aggregate, got %s", side1string);
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

      memset(&side2address,0,sizeof(side2address));
      memset(&side2network,0,sizeof(side2network));
      
      if (!side1isgroup) {

	if (!(argc > 1)) {
	  spindump_errorf("expected two addresses or networks as arguments to --aggregate, got just one (%s)",
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
	    spindump_errorf("expected an address as second argument for --aggregate, got %s", side2string);
	    exit(1);
	  }
	} else {
	  if (!spindump_network_fromstring(&side2network,side2string)) {
	    spindump_errorf("expected a network as second argument for --aggregate, got %s", side2string);
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
	  spindump_errorf("too many aggregates specified, can only support %u",
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
	  spindump_errorf("Cannot allocate %u bytes", strlen(argv[0])+1);
	  exit(1);
	}

      } else {

	//
	// Additional components to a filter that has already begun in
	// previous arguments.
	//

	spindump_deepdebugf("additional filter components...");
	char* prevfilter = filter;
	unsigned long n = strlen(prevfilter) + 1 + strlen(argv[0]) + 1;
	filter = spindump_malloc(n);

	if (filter == 0) {
	  spindump_errorf("Cannot allocate %u bytes", n);
	  exit(1);
	} else {
	  spindump_strlcpy(filter,prevfilter,n);
	  spindump_strlcat(filter," ",n);
	  spindump_strlcat(filter,argv[0],n);
	  spindump_free(prevfilter);
	}
      }

    }

    argc--; argv++;

  }

}

//
// Spindump main operation
//

static void
spindump_main_operation(void) {

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

  spindump_main_initialize_aggregates(analyzer);
  
  //
  // Initialize the capture interface
  //

  struct spindump_capture_state* capturer = 0;

  if (inputFile != 0) {
    capturer = spindump_capture_initialize_file(inputFile,filter);
  } else if (collector) {
    capturer = spindump_capture_initialize_null();
  } else {
    capturer = spindump_capture_initialize_live(interface,filter);
  }
  
  if (capturer == 0) exit(1);
  
  //
  // Now is the time to drop privileges, as the capture interface has
  // been opened, so no longer need for root privileges (if we are
  // running root).
  //

  uid_t euid = geteuid();
  if (euid == 0) {

    uid_t uid = getuid();
    
    if (setgid(getgid()) != 0) {
      spindump_fatalf("Unable to drop group privileges");
    }
    
    if (setuid(getuid()) != 0) {
      spindump_fatalf("setuid: Unable to drop user privileges");
    }

    if (euid != uid) {

      //
      // Since we are paranoid... we will try to get our root privileges
      // back, which should fail. If it doesn't fail, we exit!
      //
      
      if (setuid(0) != -1) {
	spindump_fatalf("Managed to regain root privileges, this should not happen");
      }

    }
  }
  
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
  if (collector) {
    server = spindump_remote_server_init(collectorPort);
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

  struct spindump_eventformatter* formatter = 0;
  struct spindump_eventformatter* remoteFormatter = 0;
  if (toolmode == spindump_toolmode_textual) {
    formatter = spindump_eventformatter_initialize_file(analyzer,
							format,
							stdout,
							querier,
							reportSpins,
							reportSpinFlips,
							anonymizeLeft,
							anonymizeRight);
  }
  
  if (nRemotes > 0) {
    remoteFormatter = spindump_eventformatter_initialize_remote(analyzer,
								format,
								nRemotes,
								remotes,
								remoteBlockSize,
								querier,
								reportSpins,
								reportSpinFlips,
								anonymizeLeft,
								anonymizeRight);
  }

  //
  // Enter the main packet-waiting-loop
  //
  
  spindump_main_packetloop(analyzer,capturer,reporter,formatter,remoteFormatter,server,
			   averageMode,aggregateMode,closedMode,udpMode);
  
  //
  // Done
  //

  if (formatter != 0) {
    spindump_eventformatter_uninitialize(formatter);
  }
  
  if (remoteFormatter != 0) {
    spindump_eventformatter_uninitialize(remoteFormatter);
  }
  
  if (showStats) {
    spindump_stats_report(spindump_analyze_getstats(analyzer),
			  stdout);
    spindump_connectionstable_report(analyzer->table,
				     stdout,
				     anonymizeLeft,
				     querier);
  }
  spindump_report_uninitialize(reporter);
  spindump_analyze_uninitialize(analyzer);
  spindump_capture_uninitialize(capturer);
  spindump_reverse_dns_uninitialize(querier);
}

//
// Function to wait for packets in a loop and process them
//

static void
spindump_main_packetloop(struct spindump_analyze* analyzer,
			 struct spindump_capture_state* capturer,
			 struct spindump_report_state* reporter,
			 struct spindump_eventformatter* formatter,
			 struct spindump_eventformatter* remoteFormatter,
			 struct spindump_remote_server* server,
			 int averageMode,
			 int aggregateMode,
			 int closedMode,
			 int udpMode) {
  
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

  spindump_deepdebugf("main loop");
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
    // If we are in visual mode, keep the display up even if the
    // packets come from a PCAP file
    //
    
    if (!more && inputFile != 0 && toolmode == spindump_toolmode_visual) more = 1;

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
    // Check if there's any report from clients to our server, and
    // take those updates into account in our connection/analyzer
    // tables.
    //
    
    if (server != 0) {
      while (spindump_remote_server_getupdate(server)) {
      }
    }
    
    //
    // See if we need to do any periodic maintenance (timeouts etc) of
    // the set of connections we have.
    //

    if (spindump_connectionstable_periodiccheck(analyzer->table,
						&now,
						analyzer)) {
      if (remoteBlockSize > 0 && nRemotes > 0) {
	spindump_assert(remoteFormatter != 0);
	spindump_eventformatter_sendpooled(remoteFormatter);
      }
    }

    //
    // See if it is time to update the screen periodically
    //

    if (toolmode == spindump_toolmode_visual &&
	(spindump_iszerotime(&previousupdate) ||
	 spindump_timediffinusecs(&now,&previousupdate) >= updateperiod)) {
      
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
      {
	double result = floor(commandArgument * 1000 * 1000);
	updateperiod = (unsigned long long)result;
      }
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

}

//
// The main program
//

int main(int argc,char** argv) {

  //
  // Initialize
  //

  signal(SIGINT, spindump_main_interrupt);
  srand((unsigned int)time(0));
  debugfile = stderr;

  //
  // Process arguments
  //

  spindump_main_processargs(argc, argv);

  //
  // Check where debug printouts should go
  //

  if (toolmode != spindump_toolmode_silent && spindump_debug) {
    debugfile = fopen("spindump.debug","w");
    if (debugfile == 0) {
      spindump_errorf("cannot open debug file");
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
help(void) {

  printf("Usage:\n");
  printf("  \n");
  printf("    spindump [options] [filter]\n");
  printf("\n");
  printf("If no options or filter is specified, Spindump will look at all packets\n");
  printf("on the default interface. For the filter syntax, see pcap-filter(7).\n");
  printf("\n");
  printf("The options are as follows:\n");
  printf("\n");
  printf("    --silent                Sets the tool to be either silent, list RTT measurements\n");
  printf("    --textual               as they occur, or have a continuously updating visual\n");
  printf("    --visual                interface. The visual interface is the default.\n");
  printf("\n");
  printf("    --names                 Use DNS names or addresses in the output. (The default is\n");
  printf("    --addresses             using names.)\n");
  printf("\n");
  printf("    --report-spins          Report individual spin bit values in --textual mode.\n");
  printf("    --not-report-spins\n");
  printf("    --report-spin-flips     Report individual spin bit changes in --textual mode.\n");
  printf("    --not-report-spin-flips\n");
  printf("\n");
  printf("    --anonymize             Anonymization control.\n");
  printf("    --not-anonymize\n");
  printf("    --anonymize-left\n");
  printf("    --not-anonymize-left\n");
  printf("    --anonymize-right\n");
  printf("    --not-anonymize-right\n");
  printf("\n");
  printf("    --no-stats              Produces statistics at the end of the execution.\n");
  printf("    --stats\n");
  printf("\n");
  printf("    --aggregate p1 p2       Collect aggregate information for flows matching patterns\n");
  printf("                            p1 to p2. Pattern is either an address or a network prefix.\n");
  printf("\n");
  printf("    --max-receive n         Sets a limit of how many packets the tool accepts.\n");
  printf("\n");
  printf("    --interface i           Set the interface to listen on, or the capture\n");
  printf("    --input-file f          file to read from.\n");
  printf("    --remote u              Send connections information to spindump running elsewhere, at URL u\n");
  printf("    --remote-block-size n   When sending information, collect as much as n bytes of information\n");
  printf("                            in each batch\n");
  printf("    --collector-port p      Use the port p for listening for other spindump instances sending this\n");
  printf("                            instance information\n");
  printf("    --collector             Listen for other spindump instances for information.\n");
  printf("    --no-collector          Do not listen.\n");
  printf("  \n");
  printf("    --debug                 Sets the debugging output on/off.\n");
  printf("    --no-debug\n");
  printf("  \n");
  printf("    --deepdebug             Sets the extensive internal debugging output on/off.\n");
  printf("    --no-deepdebug\n");
  printf("\n");
  printf("    --help                  Outputs information about the command usage and options.\n");
  printf("  \n");
  printf("    --version               Outputs the version number\n");
  printf("\n");
}

//
// Parse a request to use a particular output format. Call an error if
// the input is invalid.
//

static enum spindump_eventformatter_outputformat
spindump_main_parseformat(const char* string) {
  spindump_assert(string != 0);
  if (strcmp(string,"text") == 0) {
    return(spindump_eventformatter_outputformat_text);
  } else if (strcmp(string,"json") == 0) {
    return(spindump_eventformatter_outputformat_json);
  } else {
    spindump_errorf("invalid output format (%s) specified, expected text or json", string);
    return(spindump_eventformatter_outputformat_text);
  }
}

static void
spindump_main_initialize_aggregates(struct spindump_analyze* analyzer) {
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
}
