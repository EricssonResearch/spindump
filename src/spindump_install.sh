###
###
###  ######################################################################
###  #######                                                      #########
###  ####      SSS   PPPP   I  N    N  DDDD   U   U  M   M  PPPP       ####
###  #        S      P   P  I  NN   N  D   D  U   U  MM MM  P   P         #
###  #         SSS   PPPP   I  N NN N  D   D  U   U  M M M  PPPP          #
###  #            S  P      I  N   NN  D   D  U   U  M   M  P             #
###  ####      SSS   P      I  N    N  DDDD    UUU   M   M  P          ####
###  #######                                                      #########
###  ######################################################################
###
###  SPINDUMP (C) 2018-2019 BY ERICSSON RESEARCH
###  AUTHOR: JARI ARKKO
###
###

execute_process(COMMAND cp -f src/spindump /usr/local/bin/spindump
)
execute_process(COMMAND sh src/spindump_install_setrights.sh /usr/local/bin/spindump
)
execute_process(COMMAND mkdir -p /usr/local/include/spindump
)
execute_process(COMMAND chmod a+rx /usr/local/include/spindump
)
execute_process(COMMAND chmod og-w /usr/local/include/spindump
)
execute_process(COMMAND cp -f src/spindump_util.h src/spindump_packet.h src/spindump_protocols.h src/spindump_capture.h src/spindump_connections_structs.h src/spindump_connections.h src/spindump_connections_set.h src/spindump_connections_set_iterator.h src/spindump_table_structs.h src/spindump_table.h src/spindump_test.h src/spindump_analyze.h src/spindump_analyze_icmp.h src/spindump_analyze_tcp.h src/spindump_analyze_udp.h src/spindump_analyze_dns.h src/spindump_analyze_coap.h src/spindump_analyze_tls_parser.h src/spindump_analyze_quic.h src/spindump_analyze_quic_parser.h src/spindump_analyze_aggregate.h src/spindump_reversedns.h src/spindump_rtt.h src/spindump_mid.h src/spindump_seq.h src/spindump_spin.h src/spindump_spin_structs.h src/spindump_stats.h src/spindump_remote_client.h src/spindump_remote_server.h src/spindump_report.h src/spindump_main.h /usr/local/include/spindump/
)
execute_process(COMMAND cp -f src/libspindumplib.a /usr/local/lib/libspindump.a
)
