
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

#ifndef SPINDUMP_CAPTURE_H
#define SPINDUMP_CAPTURE_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <pcap.h>
#include "spindump_protocols.h"
#include "spindump_packet.h"
#include "spindump_stats.h"

//
// Capture parameters -------------------------------------------------------------------------
//

#define spindump_capture_snaplen        128   // bytes
#define spindump_capture_wait           1     // ms
#define spindump_capture_wait_select    5000  // usec

//
// Capture data structures --------------------------------------------------------------------
//

enum spindump_capture_linktype {
  spindump_capture_linktype_ethernet,
  spindump_capture_linktype_null
};

struct spindump_capture_state {
  pcap_t *handle;
  int waitable;
  int handleFD;
  fd_set handleSet;
  enum spindump_capture_linktype linktype;
  uint32_t ourNetmask;
  uint32_t ourAddress;
  uint32_t ourLocalBroadcastAddress;
  struct bpf_program compiledFilter;
  struct spindump_packet currentPacket;
};

//
// Capture module API interface ---------------------------------------------------------------
//

char*
spindump_capture_defaultinterface(void);
struct spindump_capture_state*
spindump_capture_initialize_live(const char* interface,
                                 const char* filter,
                                 unsigned int snaplen);
struct spindump_capture_state*
spindump_capture_initialize_file(const char* file,
                                 const char* filter);
struct spindump_capture_state*
spindump_capture_initialize_null(void);
enum spindump_capture_linktype
spindump_capture_getlinktype(struct spindump_capture_state* state);
void
spindump_capture_nextpacket(struct spindump_capture_state* state,
                            struct spindump_packet** p_packet,
                            int* p_more,
                            struct spindump_stats* stats);
void
spindump_capture_uninitialize(struct spindump_capture_state* state);

#endif // SPINDUMP_CAPTURE_H
