
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
#include "spindump_remote_file.h"
#include "spindump_eventformatter.h"
#include "spindump_main.h"
#include "spindump_main_lib.h"
#include "spindump_main_loop.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static void
spindump_main_loop_initialize_aggregates(struct spindump_main_configuration* config,
                                         struct spindump_analyze* analyzer);
static void
spindump_main_loop_packetloop(struct spindump_main_state* state,
                              struct spindump_analyze* analyzer,
                              struct spindump_capture_state* capturer,
                              struct spindump_report_state* reporter,
                              struct spindump_eventformatter* formatter,
                              struct spindump_eventformatter* remoteFormatter,
                              struct spindump_remote_server* server,
                              struct spindump_remote_file* jsonFileReader,
                              struct spindump_reverse_dns* querier,
                              int averageMode,
                              int aggregateMode,
                              int closedMode,
                              int udpMode,
                              int reverseDnsMode);

//
// Actual code --------------------------------------------------------------------------------
//

//
// Spindump main operation
//

void
spindump_main_loop_operation(struct spindump_main_state* state) {

  //
  // Checks and debugs
  //

  spindump_assert(state != 0);
  spindump_deepdeepdebugf("main loop operation");
  
  //
  // Initialize the actual operation
  //
  int interface_allocated = 0;
  struct spindump_main_configuration* config = &state->config;
  if (config->interface == 0 && config->inputFile == 0 && config->jsonInputFile == 0) {
    config->interface = spindump_capture_defaultinterface();
    if (config->interface == 0) exit(1);
    interface_allocated = 1;
  }

  //
  // Initialize packet analyzer
  //

  spindump_deepdeepdebugf("main loop, analyzer initialization");
  if (config->toolmode == spindump_toolmode_visual) config->periodicReportPeriod = 0;
  struct spindump_analyze* analyzer = spindump_analyze_initialize(config-> filterExceptionalValuesPercentage,
                                                                  config->bandwidthMeasurementPeriod,
                                                                  config->periodicReportPeriod,
                                                                  &config->defaultTags);
  if (analyzer == 0) exit(1);

  //
  // Initialize the capture interface
  //

  struct spindump_capture_state* capturer = 0;

  spindump_deepdeepdebugf("main loop, capturer initialization");
  if (config->inputFile != 0) {
    capturer = spindump_capture_initialize_file(config->inputFile,config->filter);
  } else if (config->jsonInputFile) {
    capturer = spindump_capture_initialize_null();
  } else if (config->collector) {
    capturer = spindump_capture_initialize_null();
  } else {
    capturer = spindump_capture_initialize_live(config->interface,config->filter,config->snaplen);
  }
  
  if (capturer == 0) exit(1);
  
  //
  // Now is the time to drop privileges, as the capture interface has
  // been opened, so no longer need for root privileges (if we are
  // running root).
  //
  
  spindump_deepdeepdebugf("main loop, privilege demotion");
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

  spindump_deepdeepdebugf("main loop, UI initialization");
  int averageMode = state->config.averageMode;
  int aggregateMode = state->config.aggregateMode;
  int closedMode = 1;
  int udpMode = 0;
  int reverseDnsMode = state->config.reverseDns;

  struct spindump_reverse_dns* querier =
    spindump_reverse_dns_initialize_full(config->reverseDns);

  struct spindump_report_state* reporter =
    (config->toolmode != spindump_toolmode_visual ?
     spindump_report_initialize_quiet() :
     spindump_report_initialize_terminal(querier));
  if (reporter == 0) exit(1);
  spindump_report_setanonymization(reporter,
                                   config->anonymizeLeft,
                                   config->anonymizeRight);

  //
  // Initialize the spindump server, if running silent
  //

  spindump_deepdeepdebugf("main loop operation, server init");
  struct spindump_remote_server* server = 0;
  if (config->collector) {
    server = spindump_remote_server_init(config->collectorPort);
    if (server == 0) {
      exit(1);
    }
  }
  spindump_deepdeepdebugf("main loop operation, server init done");

  //
  // Initialize the file reader, if reading events from a JSON file
  //

  struct spindump_remote_file* jsonFileReader = 0;
  if (config->jsonInputFile != 0) {
    jsonFileReader = spindump_remote_file_init(config->jsonInputFile);
    if (jsonFileReader == 0) {
      exit(1);
    }
  }
  
  //
  // Draw screen once before waiting for packets
  //

  spindump_deepdeepdebugf("main loop, entering first report update");
  spindump_report_update(reporter,
                         averageMode,
                         aggregateMode,
                         closedMode,
                         udpMode,
                         reverseDnsMode,
                         analyzer->table,
                         spindump_analyze_getstats(analyzer));

  //
  // If we are in the textual output mode, setup handlers to
  // track new RTT measurements.
  //

  spindump_deepdeepdebugf("main loop, entering eventformatter initialization");
  struct spindump_eventformatter* formatter = 0;
  struct spindump_eventformatter* remoteFormatter = 0;
  if (config->toolmode == spindump_toolmode_textual) {
    formatter = spindump_eventformatter_initialize_file(analyzer,
                                                        config->format,
                                                        stdout,
                                                        querier,
                                                        config->reportSpins,
                                                        config->reportSpinFlips,
                                                        config->reportRtLoss,
                                                        config->reportQrLoss,
                                                        config->reportQlLoss,
                                                        config->reportPackets,
                                                        config->reportNotes,
                                                        config->anonymizeLeft,
                                                        config->anonymizeRight,
                                                        config->aggregateMode,
                                                        config->averageMode,
                                                        config->filterExceptionalValuesPercentage);
  }
  
  if (config->nRemotes > 0) {
    remoteFormatter = spindump_eventformatter_initialize_remote(analyzer,
                                                                config->format,
                                                                config->nRemotes,
                                                                config->remotes,
                                                                config->remoteBlockSize,
                                                                querier,
                                                                config->reportSpins,
                                                                config->reportSpinFlips,
                                                                config->reportRtLoss,
                                                                config->reportQrLoss,
                                                                config->reportQlLoss,
                                                                config->reportPackets,
                                                                config->reportNotes,
                                                                config->anonymizeLeft,
                                                                config->anonymizeRight,
                                                                config->aggregateMode,
                                                                config->averageMode,
                                                                config->filterExceptionalValuesPercentage);
  }

  //
  // Initialize aggregate collection, as specified earlier
  //

  spindump_deepdeepdebugf("main loop operation, entering aggregate creation");
  spindump_main_loop_initialize_aggregates(config,analyzer);
  
  //
  // Enter the main packet-waiting-loop
  //
  
  spindump_deepdeepdebugf("main loop operation, entering packetloop");
  spindump_main_loop_packetloop(state,
                                analyzer,
                                capturer,
                                reporter,
                                formatter,
                                remoteFormatter,
                                server,
                                jsonFileReader,
                                querier,
                                averageMode,
                                aggregateMode,
                                closedMode,
                                udpMode,
                                reverseDnsMode);
  
  //
  // Done
  //

  if (formatter != 0) {
    spindump_eventformatter_uninitialize(formatter);
  }
  
  if (remoteFormatter != 0) {
    spindump_eventformatter_uninitialize(remoteFormatter);
  }
  
  if (config->showStats) {
    spindump_stats_report(spindump_analyze_getstats(analyzer),
                          stdout);
    spindump_connectionstable_report(analyzer->table,
                                     stdout,
                                     config->anonymizeLeft,
                                     querier);
  }
  // Only free interface string if it was allocated by us
  if (interface_allocated) {
    spindump_free(config->interface);
  }
  spindump_report_uninitialize(reporter);
  spindump_analyze_uninitialize(analyzer);
  spindump_capture_uninitialize(capturer);
  spindump_reverse_dns_uninitialize(querier);
  if (server != 0) spindump_remote_server_close(server);
  if (jsonFileReader != 0) spindump_remote_file_close(jsonFileReader);
}

//
// Function to wait for packets in a loop and process them
//

static void
spindump_main_loop_packetloop(struct spindump_main_state* state,
                              struct spindump_analyze* analyzer,
                              struct spindump_capture_state* capturer,
                              struct spindump_report_state* reporter,
                              struct spindump_eventformatter* formatter,
                              struct spindump_eventformatter* remoteFormatter,
                              struct spindump_remote_server* server,
                              struct spindump_remote_file* jsonFileReader,
                              struct spindump_reverse_dns* querier,
                              int averageMode,
                              int aggregateMode,
                              int closedMode,
                              int udpMode,
                              int reverseDnsMode) {
  
  //
  // Main operation
  //
  
  struct timeval now;
  struct timeval previousPacketTimestamp;
  struct timeval previousupdate;
  spindump_zerotime(&previousPacketTimestamp);
  spindump_zerotime(&previousupdate);
  struct spindump_packet* packet = 0;
  struct spindump_main_configuration* config = &state->config;
  int more = 1;
  int seenEof = 0;
  int firstEof = 1;
  
  spindump_deepdebugf("main packet loop");
  while (!state->interrupt &&
         more &&
         (config->maxReceive == 0 ||
          spindump_analyze_getstats(analyzer)->receivedFrames < config->maxReceive)) {
    
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
    // packets came from a PCAP file and we run out of more packets
    // to read from the file
    //

    if (!more && !seenEof) {
      seenEof = 1;
    }
    
    if (!more &&
        (config->inputFile != 0 || config->jsonInputFile != 0) &&
        config->toolmode == spindump_toolmode_visual) more = 1;
    
    //
    // Get current time, ensure that different timer perceptions in
    // the system (on network card and in the CPUs) do not lead to
    // time ever going back
    //

    if (config->inputFile != 0) {
      if (packet != 0) {
        now = previousPacketTimestamp = packet->timestamp;
      } else {
        now = previousPacketTimestamp;
      }
    } else if (config->jsonInputFile != 0) {
      if (!spindump_iszerotime(&previousPacketTimestamp)) {
        spindump_deepdeepdebugf("time set 1");
        now = previousPacketTimestamp;
      } else {
        spindump_deepdeepdebugf("time set 2");
        spindump_getcurrenttime(&now);
      }
    } else {
      spindump_getcurrenttime(&now);
    }
    
    spindump_deepdeepdebugf("time check %u.%u %u", now.tv_sec, now.tv_usec, seenEof);
    spindump_assert(now.tv_sec > 0 || seenEof);
    spindump_assert(now.tv_usec <= 1000 * 1000);

    //
    // Check if there's any report from clients to our server, and
    // take those updates into account in our connection/analyzer
    // tables.
    //

    if (server != 0) {
      while (spindump_remote_server_getupdate(server,analyzer)) {
      }
    }
    
    //
    // Check if there's any events from a JSON file to react to,
    // take those updates into account in our connection/analyzer
    // tables.
    //
    
    if (jsonFileReader != 0) {
      while (spindump_remote_file_getupdate(jsonFileReader,analyzer,&previousPacketTimestamp)) {
      }
      more = 0;
    }
    
    //
    // See if we need to do any periodic maintenance (timeouts etc) of
    // the set of connections we have.
    //
    
    if (now.tv_sec > 0 &&
        spindump_connectionstable_periodiccheck(analyzer->table,
                                                &now,
                                                analyzer)) {
      if (config->remoteBlockSize > 0 && config->nRemotes > 0) {
        spindump_assert(remoteFormatter != 0);
        spindump_eventformatter_sendpooled(remoteFormatter);
      }
    }

    //
    // See if it is time to update the screen periodically
    //

    if (config->toolmode == spindump_toolmode_visual &&
        (spindump_iszerotime(&previousupdate) ||
         spindump_timediffinusecs(&now,&previousupdate) >= config->updatePeriod ||
         (seenEof && firstEof))) {
      
      spindump_report_update(reporter,
                             averageMode,
                             aggregateMode,
                             closedMode,
                             udpMode,
                             reverseDnsMode,
                             analyzer->table,
                             spindump_analyze_getstats(analyzer));
      if (spindump_isearliertime(&now,&previousupdate)) previousupdate = now;
      if (seenEof) firstEof = 0;
      
    }

    //
    // Check if we have any user input
    //

    double commandArgument;
    enum spindump_report_command command = spindump_report_checkinput(reporter,&commandArgument);
    
    switch (command) {
      
    case spindump_report_command_quit:
      state->interrupt = 1;
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
        config->updatePeriod = (unsigned long long)result;
      }
      break;
      
    case spindump_report_command_toggle_reverse_dns:
      reverseDnsMode = !reverseDnsMode;
      spindump_reverse_dns_toggle(querier,reverseDnsMode);
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
                             reverseDnsMode,
                             analyzer->table,
                             spindump_analyze_getstats(analyzer));
    }
  }

}

//
// Helper function to initialize an aggregate connection object for
// the analyzer
//

static void
spindump_main_loop_initialize_aggregates(struct spindump_main_configuration* config,
                                         struct spindump_analyze* analyzer) {
  struct timeval startTime;
  struct spindump_connectionstable* table = analyzer->table;
  spindump_getcurrenttime(&startTime);
  spindump_deepdeepdebugf("spindump_main_loop_initialize_aggregate network %u", config->nAggrnetws);
  if (config->nAggrnetws <= 0)
    table->networks = 0;
  else if (!(table->networks = spindump_malloc(config->nAggrnetws * sizeof table->networks[0])))
    spindump_errorf("cannot allocate aggregate networks");
  else {
    memset(table->networks, 0, config->nAggrnetws * sizeof table->networks);
    for (unsigned int i = 0; i < config->nAggrnetws; i++) {
      table->networks[i].side2Network = config->aggrnetws[i].network;
      table->networks[i].connection = 0;
    }
    table->nNetworks = config->nAggrnetws;
  }
  spindump_deepdeepdebugf("spindump_main_loop_initialize_aggregate %u", config->nAggregates);
  for (unsigned int i = 0; i < config->nAggregates; i++) {
    struct spindump_main_aggregate* aggregate = &config->aggregates[i];
    spindump_assert(spindump_isbool(aggregate->ismulticastgroup));
    spindump_assert(spindump_isbool(aggregate->side1ishost));
    spindump_assert(aggregate->side2type == network ||
                    aggregate->side2type == host ||
                    aggregate->side2type == multinet);
    spindump_deepdeepdebugf("spindump_main_loop_initialize_aggregate no %u", i);
    struct spindump_connection* aggregateConnection = 0;
    if (aggregate->ismulticastgroup) {
      aggregateConnection = spindump_connections_newconnection_aggregate_multicastgroup(&aggregate->side1address,
                                                                                        &startTime,
                                                                                        1,
                                                                                        analyzer->table);
    } else if (aggregate->side1ishost && aggregate->side2type == host) {
      aggregateConnection = spindump_connections_newconnection_aggregate_hostpair(&aggregate->side1address,
                                                                                  &aggregate->side2address,
                                                                                  &startTime,
                                                                                  1,
                                                                                  analyzer->table);
    } else if (aggregate->side1ishost && aggregate->side2type == network) {
      aggregateConnection = spindump_connections_newconnection_aggregate_hostnetwork(&aggregate->side1address,
                                                                                     &aggregate->side2network,
                                                                                     &startTime,
                                                                                     1,
                                                                                     analyzer->table);
    } else if (aggregate->side1ishost && aggregate->side2type == multinet) {
      aggregateConnection = spindump_connections_newconnection_aggregate_hostmultinet(&aggregate->side1address,
                                                                                      &startTime,
                                                                                      1,
                                                                                      analyzer->table);
    } else if (!aggregate->side1ishost && aggregate->side2type == host) {
      aggregateConnection = spindump_connections_newconnection_aggregate_hostnetwork(&aggregate->side2address,
                                                                                     &aggregate->side1network,
                                                                                     &startTime,
                                                                                     1,
                                                                                     analyzer->table);
    } else if (!aggregate->side1ishost && aggregate->side2type == network) {
      spindump_deepdeepdebugf("creating an aggragate with default match %u", aggregate->defaultMatch);
      aggregateConnection = spindump_connections_newconnection_aggregate_networknetwork(aggregate->defaultMatch,
                                                                                        &aggregate->side1network,
                                                                                        &aggregate->side2network,
                                                                                        &startTime,
                                                                                        1,
                                                                                        analyzer->table);
    } else if (!aggregate->side1ishost && aggregate->side2type == multinet) {
      aggregateConnection = spindump_connections_newconnection_aggregate_networkmultinet(&aggregate->side1network,
                                                                                         &startTime,
                                                                                         1,
                                                                                         analyzer->table);
    }
    if (aggregateConnection != 0) {
      spindump_tags_copy(&aggregateConnection->tags,&aggregate->tags);
      spindump_deepdebugf("created a manually configured aggregate connection %u tags = %s",
                          aggregateConnection->id,
                          aggregateConnection->tags.string);
      struct timeval now;
      spindump_getcurrenttime(&now);
      spindump_analyze_process_handlers(analyzer,
                                        spindump_analyze_event_newconnection,
                                        &now,
                                        0, // fromResponder not known
                                        0, // ipPacketLength not known
                                        0, // no connection
                                        aggregateConnection);
    }
    for (unsigned int i = 0; i < config->nAggrnetws; i++) {
      if (config->aggrnetws[i].aggregate == aggregate)
        table->networks[i].connection = aggregateConnection;
    }
  }
}
