
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
###  AUTHOR: JARI ARKKO AND LARS EGGERT
###
###

#
# Libraries used
#

# for libpcap installed on on MacOS via homebrew
if(EXISTS "/usr/local/opt/libpcap")
  list(APPEND CMAKE_PREFIX_PATH "/usr/local/opt/libpcap")
endif()

find_package(Curses)
find_package(Threads)
#find_package(Microhttpd)

find_path(PCAP_INCLUDE_DIR NAMES pcap/pcap.h pcap.h)
find_library(PCAP_LIBRARY NAMES pcap)
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCAP DEFAULT_MSG PCAP_INCLUDE_DIR PCAP_LIBRARY)

find_path(CURL_INCLUDE_DIR NAMES curl/curl.h curl.h)
find_library(CURL_LIBRARY NAMES curl)
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(CURL DEFAULT_MSG CURL_INCLUDE_DIR CURL_LIBRARY)

find_path(MICROHTTPD_INCLUDE_DIR NAMES microhttpd.h)
find_library(MICROHTTPD_LIBRARY NAMES microhttpd)
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MICROHTTPD DEFAULT_MSG MICROHTTPD_INCLUDE_DIR MICROHTTPD_LIBRARY)

#
# Main spindump library that we create
#

add_library(spindumplib
  spindump_analyze.c 
  spindump_analyze_event.c 
  spindump_analyze_aggregate.c
  spindump_analyze_coap.c
  spindump_analyze_dns.c
  spindump_analyze_ip.c 
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
  spindump_eventformatter.c 
  spindump_eventformatter_text.c 
  spindump_eventformatter_json.c 
  spindump_event.c
  spindump_event_parser_json.c
  spindump_event_parser_text.c
  spindump_json.c 
  spindump_json_value.c 
  spindump_memdebug.c
  spindump_mid.c
  spindump_packet.c
  spindump_protocols.c
  spindump_remote_client.c
  spindump_remote_server.c
  spindump_report.c
  spindump_reversedns.c
  spindump_reversedns_full.c
  spindump_rtt.c
  spindump_seq.c
  spindump_spin.c
  spindump_stats.c
  spindump_table.c
  spindump_util.c 
  spindump_utildebug.c 
  spindump_utilerror.c 
)

target_include_directories(spindumplib
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(spindumplib
  PRIVATE
    ${MICROHTTPD_LIBRARY}
    ${CURL_LIBRARY}
    ${PCAP_LIBRARY}
    ${CURSES_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
    m
# uncomment the following line if you're doing profiling with google-proftools (gproftools)
    # -L/opt/local/lib profiler
# uncomment the following line if you're doing profiling with GNU performance tools (gperf)
    # -pg
)

#
# Main program of the spindump tool
#

add_executable(spindump spindump_main.c spindump_main_lib.c spindump_main_loop.c)
target_link_libraries(spindump spindumplib)

#
# Testing
#

add_custom_command(
  OUTPUT spindump_test0.out
  COMMAND bash spindump_checksource.sh
  ARGS  2> spindump_test0.out
  DEPENDS spindump_checksource.sh
)

add_custom_command(
  OUTPUT spindump_test1.out
  COMMAND spindump_test
  ARGS  > spindump_test1.out
  DEPENDS spindump_test
)

add_custom_command(
  OUTPUT spindump_test2.out
  COMMAND bash spindump_testtraces.sh
  ARGS  2> spindump_test2.out
  DEPENDS spindump_testtraces.sh
  WORKING_DIRECTORY .
)

set_property(SOURCE spindump_main.c APPEND PROPERTY OBJECT_DEPENDS src/spindump_test0.out src/spindump_test1.out)

add_executable(spindump_test spindump_test.c)
target_link_libraries(spindump_test spindumplib)

include( CTest )

add_test( spindump_checksource spindump_checksource.sh )  
add_test( spindump_test spindump_test )  
add_test( spindump_testtraces spindump_testtraces.sh )

#
# Tar file
#

add_custom_command(OUTPUT ${PROJECT_SOURCE_DIR}/spindump.tar.gz
                   COMMAND rm ARGS -f ${PROJECT_SOURCE_DIR}/spindump.tar.gz
                   COMMAND tar
                   ARGS czf spindump.tar.gz CMakeLists.txt src/CMakeLists.txt README.md .gitignore LICENSE.txt images/*.png images/*.jpg src/*.h src/*.c src/*.sh test/*.txt test/*.pcap test/*.expected test/*.options
                   WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
)

set_property(SOURCE spindump_main.c APPEND PROPERTY OBJECT_DEPENDS ${PROJECT_SOURCE_DIR}/spindump.tar.gz)

#
# Installations
#


install(SCRIPT spindump_install.sh)

add_custom_target(uninstall
                  COMMAND sh spindump_uninstall.sh
)
                  
#
# Word counts
#

add_custom_target(wc
                  COMMAND sh spindump_wc.sh
)
