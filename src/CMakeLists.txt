# for libpcap installed on on MacOS via homebrew
list(APPEND CMAKE_PREFIX_PATH "/usr/local/opt/libpcap")

find_package(PkgConfig)
find_package(Curses)
pkg_check_modules(PCAP REQUIRED libpcap)

add_library(libspindump
  spindump_analyze.c
  spindump_analyze_aggregate.c
  spindump_analyze_coap.c
  spindump_analyze_dns.c
  spindump_analyze_icmp.c
  spindump_analyze_quic.c
  spindump_analyze_quic_parser.c
  spindump_analyze_tcp.c
  spindump_analyze_tls_parser.c
  spindump_analyze_udp.c
  spindump_capture.c
  spindump_connections.c
  spindump_connections_new.c
  spindump_connections_print.c
  spindump_connections_search.c
  spindump_connections_set.c
  spindump_connections_set_iterator.c
  spindump_mid.c
  spindump_packet.c
  spindump_protocols.c
  spindump_remote.c
  spindump_report.c
  spindump_reversedns.c
  spindump_rtt.c
  spindump_seq.c
  spindump_spin.c
  spindump_stats.c
  spindump_table.c
  spindump_util.c
)

target_include_directories(libspindump
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(libspindump
  PRIVATE
    ${PCAP_LIBRARIES}
    ${CURSES_LIBRARIES}
)

add_executable(spindump spindump_main.c)
target_link_libraries(spindump libspindump)

add_executable(spindump_test spindump_test.c)
target_link_libraries(spindump_test libspindump)
