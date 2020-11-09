
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
# CMAKE version
#

cmake_minimum_required(VERSION 3.1)

#
# Languages and compilers
#

project(spindump VERSION 0.2.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

find_program(CLANGTIDY NAMES clang-tidy)
if(CLANGTIDY)
  message(STATUS "Found clang-tidy: ${CLANGTIDY}")
  set(CMAKE_C_CLANG_TIDY ${CLANGTIDY} -system-headers -checks=*)
endif()

find_program(IWYU NAMES include-what-you-use iwyu)
if(IWYU)
  message(STATUS "Found include-what-you-use: ${IWYU}")
  set(CMAKE_C_INCLUDE_WHAT_YOU_USE ${IWYU})
endif()

find_program(CPPCHECK NAMES cppcheck)
if(CPPCHECK)
  message(STATUS "Found cppcheck: ${CPPCHECK}")
  set(CMAKE_C_CPPCHECK ${CPPCHECK} -q --inline-suppr --enable=all)
endif()

include(CheckCCompilerFlag)
foreach(FLAG
    -pipe
    -I/opt/local/include
    -Wall -Wextra -Wpedantic -Weverything -Werror
    -Wno-unknown-warning-option
    -fno-diagnostics-color
    -fno-omit-frame-pointer
    -fno-optimize-sibling-calls -fno-common
    -Wno-covered-switch-default
    -Wno-unused-parameter 
    -Wno-disabled-macro-expansion
    # need to include the following to make PCAP compile
    -Wno-padded
    # need to the include the following to make Libmicrohttpd compile
    -Wno-documentation-deprecated-sync
    -Wno-reserved-id-macro
    -Wno-documentation
# comment in/out one of the two following lines out to switch between optimized and debug versions
    -g -DSPINDUMP_DEBUG -DSPINDUMP_MEMDEBUG -DSPINDUMP_MEMDEBUG_TRASHMEM -Wno-cast-align
    # -O3 -Wno-unused-variable
# uncomment the following line if you're doing profiling with GNU performance tools (gperf)
    # -pg
  )
  string(REGEX REPLACE "[-=+]" "_" F ${FLAG})
  check_c_compiler_flag(${FLAG} ${F})
  if(${F})
    add_compile_options(${FLAG})
  endif()
endforeach()

#
# Directories
#

add_subdirectory(src)

#
# Testing
#

include( CTest )
