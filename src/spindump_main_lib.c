
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

#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <unistd.h>
#include "spindump_util.h"
#include "spindump_tags.h"
#include "spindump_capture.h"
#include "spindump_analyze.h"
#include "spindump_report.h"
#include "spindump_remote_client.h"
#include "spindump_remote_server.h"
#include "spindump_eventformatter.h"
#include "spindump_main.h"
#include "spindump_main_lib.h"
#include "spindump_bandwidth.h"

//
// Types --------------------------------------------------------------------------------------
//

struct spindump_main_network_entry {
  struct spindump_main_network_entry *next;
  spindump_network network;
};

//
// Function prototypes ------------------------------------------------------------------------
//

static void
spindump_main_configuration_defaultvalues(struct spindump_main_configuration* config);
static enum spindump_eventformatter_outputformat
spindump_main_parseformat(const char* string);
static struct spindump_main_network_entry *
spindump_main_read_networks(const char *file);
static int
spindump_main_compare_aggrnetw(const void *p1, const void *p2);

//
// Actual code --------------------------------------------------------------------------------
//

//
// Create the main state object, and initialize configuration information
//

struct spindump_main_state*
spindump_main_initialize(void) {
  
  //
  // Calculate size and allocate state
  //

  spindump_deepdeepdebugf("spindump_main_initialize");
  unsigned int size = sizeof(struct spindump_main_state);
  struct spindump_main_state* state = (struct spindump_main_state*)spindump_malloc(size);
  if (state == 0) {
    spindump_errorf("cannot allocate main state of %u bytes", size);
    return(0);
  }

  //
  // Initialize state
  //

  memset(state,0,size);
  spindump_main_configuration_defaultvalues(&state->config);
  state->interrupt = 0;
  
  //
  // Done. Return state.
  //

  return(state);
}

//
// Destroy the main state object
//

void
spindump_main_uninitialize(struct spindump_main_state* state) {
  
  //
  // Checks
  //

  spindump_deepdeepdebugf("spindump_main_uninitialize");
  spindump_assert(state != 0);

  //
  // Free content fields
  //

  if (state->config.filter != 0) {
    spindump_free(state->config.filter);
  }
  spindump_tags_uninitialize(&state->config.defaultTags);
  
  //
  // Reset contents, just in case
  //

  memset(state,0,sizeof(*state));

  //
  // Actually free up the space
  //

  spindump_free(state);
}

//
// Put the default values in for the configuration object
//

static void
spindump_main_configuration_defaultvalues(struct spindump_main_configuration* config) {
  spindump_deepdeepdebugf("spindump_main_configuration_defaultvalues");
  memset(config,0,sizeof(*config));
  config->interface = 0;
  config->inputFile = 0;
  config->jsonInputFile = 0;
  config->filter = 0;
  config->snaplen = spindump_capture_snaplen;
  config->toolmode = spindump_toolmode_visual;
  config->format = spindump_eventformatter_outputformat_text;
  config->maxReceive = 0;
  config->showStats = 0;
  config->reverseDns = 0;
  config->reportSpins = 0;
  config->reportSpinFlips = 0;
  config->reportRtLoss = 0;
  config->reportQrLoss = 0;
  config->reportQlLoss = 0;
  config->reportPackets = 0;
  config->reportNotes = 1;
  config->anonymizeLeft = 0;
  config->anonymizeRight = 0;
  config->filterExceptionalValuesPercentage = 0; // no filtering of RTT values
  config->updatePeriod = 500 * 1000; // 0.5s
  config->bandwidthMeasurementPeriod = spindump_bandwidth_period_default;
  config->periodicReportPeriod = 0; // not enabled, values in seconds
  config->nAggregates = 0;
  config->remoteBlockSize = 16 * 1024;
  config->nRemotes = 0;
  config->collector = 0;
  config->collectorPort = SPINDUMP_PORT_NUMBER;
  spindump_tags_initialize(&config->defaultTags);
}

//
// Process command line arguments for the spindump command
//

void
spindump_main_processargs(int argc,
                          char** argv,
                          struct spindump_main_configuration* config) {
  
  spindump_deepdeepdebugf("spindump_main_processargs");
  argc--; argv++;
  while (argc > 0) {
    
    spindump_deepdeepdebugf("spindump_main_processarg %s", argv[0]);
    if (strcmp(argv[0],"--version") == 0) {

      printf("version 0.71 November 25, 2019\n");
      exit(0);

    } else if (strcmp(argv[0],"--help") == 0) {

      spindump_main_help();
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

      config->showStats = 1;

    } else if (strcmp(argv[0],"--no-stats") == 0) {

      config->showStats = 0;

    } else if (strcmp(argv[0],"--average-mode") == 0) {

      config->averageMode = 1;

    } else if (strcmp(argv[0],"--no-average-mode") == 0) {

      config->averageMode = 0;

    } else if (strcmp(argv[0],"--aggregate-mode") == 0) {

      config->aggregateMode = 1;

    } else if (strcmp(argv[0],"--no-aggregate-mode") == 0) {

      config->aggregateMode = 0;

    } else if (strcmp(argv[0],"--names") == 0) {

      config->reverseDns = 1;

    } else if (strcmp(argv[0],"--addresses") == 0) {

      config->reverseDns = 0;

    } else if (strcmp(argv[0],"--report-spins") == 0) {

      config->reportSpins = 1;

    } else if (strcmp(argv[0],"--not-report-spins") == 0) {

      config->reportSpins = 0;

    } else if (strcmp(argv[0],"--report-spin-flips") == 0) {

      config->reportSpinFlips = 1;

    } else if (strcmp(argv[0],"--not-report-spin-flips") == 0) {

      config->reportSpinFlips = 0;
    
    } else if (strcmp(argv[0],"--report-rt-loss") == 0) {

      config->reportRtLoss = 1;

    } else if (strcmp(argv[0],"--not-report-rt-loss") == 0) {

      config->reportRtLoss = 0;

    } else if (strcmp(argv[0],"--report-qr-loss") == 0) {

      config->reportQrLoss = 1;

    } else if (strcmp(argv[0],"--not-report-qr-loss") == 0) {

      config->reportQrLoss = 0;

    } else if (strcmp(argv[0],"--report-ql-loss") == 0) {

      config->reportQlLoss = 1;

    } else if (strcmp(argv[0],"--not-report-ql-loss") == 0) {

      config->reportQlLoss = 0;

    } else if (strcmp(argv[0],"--report-packets") == 0) {

      config->reportPackets = 1;

    } else if (strcmp(argv[0],"--not-report-packets") == 0) {

      config->reportPackets = 0;

    } else if (strcmp(argv[0],"--report-notes") == 0) {

      config->reportNotes = 1;

    } else if (strcmp(argv[0],"--not-report-notes") == 0) {

      config->reportNotes = 0;

    } else if (strcmp(argv[0],"--anonymize") == 0) {

      config->anonymizeLeft = 1;
      config->anonymizeRight = 1;

    } else if (strcmp(argv[0],"--not-anonymize") == 0) {

      config->anonymizeLeft = 0;
      config->anonymizeRight = 0;

    } else if (strcmp(argv[0],"--anonymize-left") == 0) {

      config->anonymizeLeft = 1;

    } else if (strcmp(argv[0],"--not-anonymize-left") == 0) {

      config->anonymizeLeft = 0;

    } else if (strcmp(argv[0],"--anonymize-right") == 0) {

      config->anonymizeRight = 1;

    } else if (strcmp(argv[0],"--not-anonymize-right") == 0) {

      config->anonymizeRight = 0;

    } else if (strcmp(argv[0],"--silent") == 0) {

      config->toolmode = spindump_toolmode_silent;

    } else if (strcmp(argv[0],"--textual") == 0) {

      config->toolmode = spindump_toolmode_textual;

    } else if (strcmp(argv[0],"--visual") == 0) {

      config->toolmode = spindump_toolmode_visual;

    } else if (strcmp(argv[0],"--tag") == 0 && argc > 1) {

      if (!spindump_tags_addtag(&config->defaultTags,argv[1])) {
        spindump_errorf("cannot add too many or too long tag values");
        exit(1);
      }
      argc--; argv++;
      
    } else if (strcmp(argv[0],"--interface") == 0 && argc > 1) {

      config->interface = argv[1];
      argc--; argv++;

    } else if (strcmp(argv[0],"--snaplen") == 0 && argc > 1) {

      if (!isdigit(argv[1][0])) {
        spindump_errorf("the --snaplen argument needs to be numeric");
        exit(1);
      }

      int arg = atoi(argv[1]);
      
      if (arg < 1) {
        spindump_errorf("the --snaplen argument needs to be bigger than zero");
        exit(1);
      }
      
      config->snaplen = (unsigned int)arg;
      
      argc--; argv++;

    } else if (strcmp(argv[0],"--filter-exceptional-values") == 0 && argc > 1) {

      if (!isdigit(argv[1][0])) {
        spindump_errorf("the --filter-exceptional-values argument needs to be numeric");
        exit(1);
      }

      int arg = atoi(argv[1]);
      
      if (arg < 1 || arg > 400) {
        spindump_errorf("the --filter-exceptional-values argument needs to be bigger than zero and less than or equal to 400");
        exit(1);
      }
      
      config->filterExceptionalValuesPercentage = (unsigned int)arg;
      
      argc--; argv++;

    } else if (strcmp(argv[0],"--format") == 0 && argc > 1) {

      config->format = spindump_main_parseformat(argv[1]);
      argc--; argv++;

    } else if (strcmp(argv[0],"--input-file") == 0 && argc > 1) {

      config->inputFile = argv[1];
      argc--; argv++;

    } else if (strcmp(argv[0],"--json-input-file") == 0 && argc > 1) {

      config->jsonInputFile = argv[1];
      argc--; argv++;

    } else if (strcmp(argv[0],"--remote") == 0 && argc > 1) {

      if (config->nRemotes == SPINDUMP_REMOTE_CLIENT_MAX_CONNECTIONS) {
        spindump_errorf("too many --remote connections");
        exit(1);
      }

      config->remotes[config->nRemotes++] = spindump_remote_client_init(argv[1]);
      argc--; argv++;

    } else if (strcmp(argv[0],"--collector") == 0) {
      
      config->collector = 1;
      
    } else if (strcmp(argv[0],"--no-collector") == 0) {
      
      config->collector = 0;
      
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
      config->collectorPort = (spindump_port)input;
      argc--; argv++;
      
    } else if (strcmp(argv[0],"--remote-block-size") == 0 && argc > 1) {

      if (!isdigit(*(argv[1]))) {
        spindump_errorf("expected a numeric argument for --remote-block-size, got %s", argv[1]);
        exit(1);
      }
      config->remoteBlockSize = 1024 * (unsigned long)atoi(argv[1]);
      argc--; argv++;
      
    } else if (strcmp(argv[0],"--max-receive") == 0 && argc > 1) {

      if (!isdigit(*(argv[1]))) {
        spindump_errorf("expected a numeric argument for --max-receive, got %s", argv[1]);
        exit(1);
      }
      config->maxReceive = (unsigned int)atoi(argv[1]);
      argc--; argv++;
      
    } else if (strcmp(argv[0],"--bandwidth-period") == 0 && argc > 1) {

      if (!isdigit(argv[1][0])) {
        spindump_errorf("the --bandwidth-period argument needs to be numeric");
        exit(1);
      }

      int arg = atoi(argv[1]);
      
      if (arg < 1) {
        spindump_errorf("the --bandwidth-period argument needs to be bigger than zero");
        exit(1);
      }
      
      config->bandwidthMeasurementPeriod = (unsigned long long)arg;
      
      argc--; argv++;
      
    } else if (strcmp(argv[0],"--report-only-periodically") == 0 && argc > 1) {

      if (!isdigit(argv[1][0])) {
        spindump_errorf("the --report-only-periodically argument needs to be numeric");
        exit(1);
      }

      int arg = atoi(argv[1]);
      
      if (arg < 0) {
        spindump_errorf("the --report-only-periodically argument can not be negative");
        exit(1);
      }
      
      config->periodicReportPeriod = (unsigned int)arg;
      
      argc--; argv++;
      
    } else if (strcmp(argv[0],"--aggregate") == 0 && argc > 1) {

      //
      // Get the tags, if any
      //

      spindump_tags tags;
      spindump_tags_initialize(&tags);
      while (strncmp(argv[1],"tag=",4) == 0 && argc > 2) {
        const char* tagvalue = argv[1]+4;
        if (strlen(tagvalue) == 0) {
          spindump_errorf("a tag value in --aggregate option cannot be empty");
          exit(1);
        }
        if (!spindump_tags_addtag(&tags,tagvalue)) {
          spindump_errorf("too long tag values in the --aggregate option");
          exit(1);
        }
        argv++;
        argc--;
      }

      //
      // Check if there's a "default" option
      //

      int defaultMatch = 0;
      if (strcmp(argv[1],"default") == 0 && argc > 2) {
        defaultMatch = 1;
        spindump_deepdeepdebugf("args processing, setting default match");
        argv++;
        argc--;
      }
      
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

      spindump_deepdeepdebugf("aggregate parsing side1 = %s, host = %u", side1string, side1ishost);
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

      spindump_deepdeepdebugf("aggregate parsing second arg %s", argv[0]);
      
      //
      // Determine if we need a second argument (we don't if it is a
      // group). Get the second of the two arguments
      //

      enum {network, host, multinet} side2type = network;
      spindump_address side2address;
      spindump_network side2network;
      struct spindump_main_network_entry *side2networks = NULL;

      memset(&side2address,0,sizeof(side2address));
      memset(&side2network,0,sizeof(side2network));
      
      spindump_deepdeepdebugf("aggregate parsing side1isgroup = %u side2type = %u", side1isgroup, side2type);
      
      if (!side1isgroup) {

        if (!(argc > 1)) {
          spindump_errorf("expected two addresses or networks as arguments to --aggregate, got just one (%s)",
                          side1string);
          exit(1);
        }

        const char* side2string = argv[1];

        //
        // Determine whether the second argument network, host or network file (multinet)
        //

        const char *multinet_prefix = "networkfile:";
        if (!strncmp(side2string, multinet_prefix, strlen(multinet_prefix))) {
          side2type = multinet;
          side2string += strlen(multinet_prefix);
        } else if (index(side2string,'/'))
          side2type = network;
        else
          side2type = host;

        //
        // Parse the second argument
        //

        if (side2type == host) {
          if (!spindump_address_fromstring(&side2address,side2string)) {
            spindump_errorf("expected an address as second argument for --aggregate, got %s", side2string);
            exit(1);
          }
        } else if (side2type == network) {
          if (!spindump_network_fromstring(&side2network,side2string)) {
            spindump_errorf("expected a network as second argument for --aggregate, got %s", side2string);
            exit(1);
          }
        } else if (side2type == multinet) {
          if (!(side2networks = spindump_main_read_networks(side2string)))
            exit(1);
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

      if (config->nAggregates >= spindump_main_maxnaggregates) {
          spindump_errorf("too many aggregates specified, can only support %u",
                          spindump_main_maxnaggregates);
          exit(1);
      }

      struct spindump_main_aggregate* aggregate = &config->aggregates[config->nAggregates++];
      aggregate->ismulticastgroup = side1isgroup;
      spindump_tags_copy(&aggregate->tags,&tags);
      spindump_tags_uninitialize(&tags);
      aggregate->defaultMatch = defaultMatch;
      spindump_deepdeepdebugf("args processing, final default match = %u", aggregate->defaultMatch);
      aggregate->side1ishost = side1ishost;
      aggregate->side2type = side2type;
      aggregate->side1address = side1address;
      aggregate->side2address = side2address;
      aggregate->side1network = side1network;
      aggregate->side2network = side2network;

      unsigned int maxAggrnetws = sizeof config->aggrnetws / sizeof config->aggrnetws[0];
      while (side2networks) {
        if (config->nAggrnetws >= maxAggrnetws) {
          spindump_errorf("too many aggregate networks specified, can only support %u",
                          maxAggrnetws);
          exit(1);
        }
        config->aggrnetws[config->nAggrnetws].aggregate = aggregate;
        config->aggrnetws[config->nAggrnetws].network = side2networks->network;
        side2networks = side2networks->next;
        config->nAggrnetws++;
      }

    } else if (argv[0][0] == '-') {

      spindump_fatalf("unrecognised option %s", argv[0]);

    } else {

      //
      // The extra arguments are all part of a filter. Collect all
      // components of the filter, and store them for later use in
      // PCAP.
      //

      if (config->filter == 0) {

        //
        // No filter components seen before. Allocate a fresh string.
        //

        spindump_deepdebugf("initial filter component...");
        config->filter = spindump_strdup(argv[0]);
        if (config->filter == 0) {
          spindump_errorf("Cannot allocate %lu bytes", strlen(argv[0])+1);
          exit(1);
        }

      } else {

        //
        // Additional components to a filter that has already begun in
        // previous arguments.
        //

        spindump_deepdebugf("additional filter components...");
        char* prevfilter = config->filter;
        unsigned long n = strlen(prevfilter) + 1 + strlen(argv[0]) + 1;
        config->filter = spindump_malloc(n);
        
        if (config->filter == 0) {
          spindump_errorf("Cannot allocate %lu bytes", n);
          exit(1);
        } else {
          spindump_strlcpy(config->filter,prevfilter,n);
          spindump_strlcat(config->filter," ",n);
          spindump_strlcat(config->filter,argv[0],n);
          spindump_free(prevfilter);
        }
      }

    }

    argc--; argv++;

  }

  qsort(config->aggrnetws, config->nAggrnetws, sizeof config->aggrnetws[0],
        spindump_main_compare_aggrnetw);
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

//
// Read CIDR format networks from file, one per line.
//

static struct spindump_main_network_entry *
spindump_main_read_networks(const char *file)
{
  struct spindump_main_network_entry *nwe = NULL;
  struct spindump_main_network_entry *nwlist = NULL;
  struct spindump_main_network_entry *result = NULL;
  FILE *f = NULL;
  char line[80], *cp;
  int linenr;

  if (!(f = fopen(file, "r"))) {
    spindump_errorf("fopen: %s: %s", file, strerror(errno));
    goto end;
  }

  line[sizeof line - 1] = '\0';
  for (linenr = 1; fgets(line, sizeof line, f); linenr++) {

    if (line[sizeof line - 1]) {
      spindump_errorf("%s:%d: line too long", file, linenr);
      goto end;
    }

    if ((cp = strchr(line, '\n')))
      *cp = '\0';

    if (!(nwe = spindump_malloc(sizeof *nwe))) {
      spindump_errorf("Cannot allocate %lu bytes", sizeof *nwe);
      goto end;
    }

    memset(nwe, 0, sizeof *nwe);
    if (!spindump_network_fromstring(&nwe->network, line)) {
      spindump_errorf("%s:%d: invalid network %s", file, linenr, line);
      goto end;
    }

    nwe->next = nwlist;
    nwlist = nwe;
    nwe = NULL;
  }

  if (ferror(f)) {
    spindump_errorf("fopen: %s: %s", file, strerror(errno));
    goto end;
  }

  result = nwlist;
  nwlist = NULL;

 end:
  if (nwe)
    spindump_free(nwe);
  while (nwlist) {
    nwe = nwlist->next;
    spindump_free(nwlist);
    nwlist = nwe;
  }
  if (f)
    fclose(f);
  return result;
}

//
// Compare too spindump_main_aggrnetw objects.
//

static int
spindump_main_compare_aggrnetw(const void *p1, const void *p2)
{
  const struct spindump_main_aggrnetw *anw1 = p1, *anw2 = p2;
  return spindump_address_compare(&anw1->network.address, &anw2->network.address);
}

//
// Print out help
//

void
spindump_main_help(void) {

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
  printf("    --report-rt-loss        Report roundtrip loss in --textual mode.\n");
  printf("    --not-report-rt-loss\n");
  printf("    --report-qr-loss        Report Telecom Italia QR loss in --textual mode.\n");
  printf("    --not-report-qr-loss\n");
  printf("    --report-ql-loss        Report Orange QL loss in --textual mode.\n");
  printf("    --not-report-ql-loss\n");
  printf("\n");
  printf("    --report-packets        Report update on every packet (default is not).\n");
  printf("    --not-report-packets    Do not report update on every packet.\n");
  printf("    --report-notes          Report additional textual notes in events (default is not).\n");
  printf("    --not-report-notes      Do not report additional textual notes.\n");
  printf("\n");
  printf("    --anonymize             Anonymization control.\n");
  printf("    --not-anonymize\n");
  printf("    --anonymize-left\n");
  printf("    --not-anonymize-left\n");
  printf("    --anonymize-right\n");
  printf("    --not-anonymize-right\n");
  printf("\n");
  printf("    --average-mode          Display (or report in output or HTTP-delivered update) average\n");
  printf("    --no-average-mode       values instead of specific instantaneous values. Default is not.\n");
  printf("    --aggregate-mode        Display (or report) aggregates only, not individal connections.\n");
  printf("    --no-aggregate-mode     Default is to report individual connections.\n");
  printf("\n");
  printf("    --filter-exceptional-values n\n");
  printf("                            Filter exceptional RTT values beyond given %% of standard deviation.\n");
  printf("\n");
  printf("    --no-stats              Produces statistics at the end of the execution.\n");
  printf("    --stats\n");
  printf("\n");
  printf("    --aggregate [t] [d] p q Collect aggregate information for flows matching patterns\n");
  printf("                            p to q. Pattern is either an address or a network prefix.\n");
  printf("                            Optionally, one may specify one or more tags of the form tag=value.\n");
  printf("                            One may also provide the keyword default before the pattern.\n");
  printf("    --tag t                 Specify a default tag value for all new connections created by\n");
  printf("                            Spindump.\n");
  printf("\n");
  printf("    --max-receive n         Sets a limit of how many packets the tool accepts.\n");
  printf("\n");
  printf("    --bandwidth-period n    Sets the length of bandwidth measurement period, in\n");
  printf("                            microseconds. The default is %llu or %.2f.\n",
         (unsigned long long)spindump_bandwidth_period_default,
         (spindump_bandwidth_period_default * 1.0) / 1000000.0);
  printf("    --report-only-periodically n\n");
  printf("                            Make only periodic reports every n seconds. The default is 0,\n");
   printf("                            which disables the periodic mode.\n");
  printf("\n");
  printf("    --interface i           Set the interface to listen on, or the capture\n");
  printf("    --snaplen n             How many bytes of the packet is captured (default is %u)\n", spindump_capture_snaplen);
  printf("    --input-file f          Give a PCAP file to read from.\n");
  printf("    --json-input-file f     Give a JSON file (produced by Spindump) to read from.\n");
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
  printf("  \n");
  printf("    --deepdeepdebug         Sets the even more extensive internal debugging output on/off.\n");
  printf("    --no-deepdeepdebug\n");
  printf("\n");
  printf("    --help                  Outputs information about the command usage and options.\n");
  printf("  \n");
  printf("    --version               Outputs the version number\n");
  printf("\n");
}
