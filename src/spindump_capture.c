
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
//  SPINDUMP (C) 2018-2020 BY ERICSSON RESEARCH
//  AUTHOR: JARI ARKKO
//
// 

//
// Includes -----------------------------------------------------------------------------------
//

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include "spindump_util.h"
#include "spindump_protocols.h"
#include "spindump_capture.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static struct spindump_capture_state*
spindump_capture_initialize_aux(const char* interface,
                                const char* file,
                                const char* filter,
                                unsigned int snaplen);

//
// Actual code --------------------------------------------------------------------------------
//

//
// Return the name of the default interface in this system.
//

char*
spindump_capture_defaultinterface(void) {

  //
  // Look up default device from PCAP
  // 
  
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t* alldevs = 0;
  
  memset(errbuf,0,sizeof(errbuf));
  if (pcap_findalldevs(&alldevs,errbuf) != 0) {
    spindump_errorf("couldn't find default device: %s", errbuf);
    return(0);
  }

  //
  // Get the interface name and substitute our own allocated string for it
  // 
  
  char* result = spindump_strdup(alldevs->name);
  pcap_freealldevs(alldevs);
  if (result == 0) {
    spindump_errorf("cannot allocate memory for string representing a device");
    return(0);
  }

  //
  // Done. Return the string.
  // 
  
  return(result);
}

//
// A helper function for initialization of the spindump_capture
// object. This is the function that does almost everything, including
// setting up filters, etc.
//

static struct spindump_capture_state*
spindump_capture_initialize_aux(const char* interface,
                                const char* file,
                                const char* filter,
                                unsigned int snaplen) {
  //
  // Debugs
  // 
  
  if (filter != 0) spindump_debugf("configured filter = %s...", filter);
  
  //
  // Allocate
  // 
  
  unsigned int size = sizeof(struct spindump_capture_state);
  struct spindump_capture_state* state = (struct spindump_capture_state*)spindump_malloc(size);
  if (state == 0) {
    spindump_errorf("cannot allocate capture state for %u bytes", size);
    return(0);
  }
  
  //
  // Initialize the state
  // 

  memset(state,0,sizeof(*state));

  //
  // Determine what if anything we need to listen on
  //
  
  char errbuf[PCAP_ERRBUF_SIZE];
  int promisc = 0;
  if (interface == 0 && file == 0) {
    
    //
    // If this is a null capture that never returns packets, then just
    // set the contents of the object to indicate that, and return.
    //
    
    state->handle = 0;
    state->linktype = spindump_capture_linktype_null;
    state->ourAddress = 0x7f000001;
    state->ourNetmask = 0xff000000;
    state->ourLocalBroadcastAddress = 0x7fffffff;
    state->waitable = 0;
    return(state);
    
  } else if (interface != 0) {

    if (((int)snaplen) < 0) {
      spindump_errorf("snaplen %u is too high", snaplen);
      spindump_free(state);
      return(0);
    }
    
    //
    // Open the PCAP interface
    // 
    
    state->handle = pcap_open_live(interface, (int)snaplen, promisc, spindump_capture_wait, errbuf);
    if (state->handle == 0) {
      spindump_errorf("couldn't open device %s: %s", interface, errbuf);
      spindump_free(state);
      return(0);
    }

    //
    // Set "non-blocking" mode to enhance interface responsiveness. Using a timeout
    // on packet buffer does not guarantee non-blocking behaviour of pcap_next_ex().
    //

    if (pcap_setnonblock(state->handle, 1, errbuf) == PCAP_ERROR) {
      spindump_errorf("couldn't enable non_blocking mode: %s", errbuf);
      spindump_free(state);
      return(0);
    }

    //
    // Initialize the file descriptor set to handle timeout on packet capture.
    //

    state->handleFD = pcap_get_selectable_fd(state->handle);
    if (state->handleFD == PCAP_ERROR) {
      spindump_errorf("couldn't get pcap handle file descriptor");
      spindump_free(state);
      return(0);
    }
    FD_ZERO(&state->handleSet);
    FD_SET(state->handleFD, &state->handleSet);
    state->waitable = 1;
    
  } else if (file != 0) {
    
    state->handle = pcap_open_offline(file, errbuf);
    if (state->handle == 0) {
      spindump_errorf("couldn't open file %s: %s", file, errbuf);
      spindump_free(state);
      return(0);
    }

    state->waitable = 0;
    
  }
  
  int linktype = pcap_datalink(state->handle);
  switch (linktype) {
  case DLT_NULL:
    state->linktype = spindump_capture_linktype_null;
    break;
  case DLT_EN10MB:
    state->linktype = spindump_capture_linktype_ethernet;
    break;
  case DLT_LINUX_SLL:
    state->linktype = spindump_capture_linktype_linux_sll;
    break;
  default:
    spindump_errorf("device %s doesn't provide Ethernet headers - value %u not supported",
                    interface, linktype);
    pcap_close(state->handle);
    spindump_free(state);
    return(0);
  }
  
  //
  // Find the properties for the device
  // 

  if (interface != 0) {
    
    if (pcap_lookupnet(interface, &state->ourAddress, &state->ourNetmask, errbuf) == -1) {
      spindump_warnf("couldn't get netmask for device %s: %s", interface, errbuf);
      state->ourAddress = 0x7f000001;
      state->ourNetmask = 0xff000000;
    }
  } else {
    state->ourAddress = 0x7f000001;
    state->ourNetmask = 0xff000000;
  }
  state->ourLocalBroadcastAddress = (state->ourAddress & state->ourNetmask) | (~(state->ourNetmask));
  spindump_deepdebugf("our local address %08x netmask %08x broadcast %08x",
                      state->ourAddress,
                      state->ourNetmask,
                      state->ourLocalBroadcastAddress);
  
  //
  // Compile and apply the filter, if any
  // 

  if (filter != 0) {

    spindump_deepdebugf("compiling filter %...", filter);
    
    if (pcap_compile(state->handle, &state->compiledFilter, filter, 0, state->ourAddress) == -1) {
      spindump_errorf("couldn't parse filter %s: %s", filter, pcap_geterr(state->handle));
      pcap_close(state->handle);
      spindump_free(state);
      return(0);
    }
    
    spindump_deepdebugf("installing filter...");
    
    if (pcap_setfilter(state->handle, &state->compiledFilter) == -1) {
      spindump_errorf("couldn't install filter %s: %s", filter, pcap_geterr(state->handle));
      pcap_close(state->handle);
      spindump_free(state);
      return(0);
    }

  }
  
  spindump_debugf("PCAP initialized, own address %08x", state->ourAddress);
  
  //
  // Done.
  // 
  
  return(state);
}

//
// Initialize a capture object to read packets from a PCAP file
//

struct spindump_capture_state*
spindump_capture_initialize_file(const char* file,
                                 const char* filter) {
  spindump_debugf("opening capture file %s...", file);
  return(spindump_capture_initialize_aux(0,file,filter,0));
}

//
// Initialize a capture object to capture packets from a live
// interface
//

struct spindump_capture_state*
spindump_capture_initialize_live(const char* interface,
                                 const char* filter,
                                 unsigned int snaplen) {

  spindump_debugf("opening capture on interface %s...", interface);
  return(spindump_capture_initialize_aux(interface,0,filter,snaplen));
  
}

//
// Initialize a capture object to capture nothing
//

struct spindump_capture_state*
spindump_capture_initialize_null(void) {
  spindump_debugf("opening null capture...");
  return(spindump_capture_initialize_aux(0,0,"",0));
  
}

//
// Retrieve the next packet from the capture interface or file.
//

void
spindump_capture_nextpacket(struct spindump_capture_state* state,
                            struct spindump_packet** p_packet,
                            int* p_more,
                            struct spindump_stats* stats) {
  
  //
  // Check
  // 
  
  spindump_assert(state != 0);
  spindump_assert(p_packet != 0);
  spindump_assert(p_more != 0);
  spindump_assert(stats != 0);

  //
  // Check if we have a capture object created by
  // spindump_capture_initialize_null, in that case we're not supposed
  // to return any packets.
  //

  if (state->handle == 0) {
    *p_packet = 0;
    *p_more = 1;
    return;
  }
  
  //
  // Otherwise, wait for the next packet
  //
  
  if (state->waitable) {
    fd_set set = state->handleSet;
    struct timeval timeout = { .tv_sec = 0, .tv_usec = spindump_capture_wait_select };
    select(state->handleFD + 1, &set, NULL, NULL, &timeout);
  }
  
  struct spindump_packet* packet = &state->currentPacket;
  memset(packet,0,sizeof(*packet));

  struct pcap_pkthdr* header = 0;
  int ret = pcap_next_ex(state->handle, &header, &packet->contents);
  
  switch (ret) {
    
  case 1:
    
    //
    // Received a packet. Parse it.
    // 
    
    *p_packet = packet;
    packet->timestamp = header->ts;
    packet->etherlen = header->len;
    packet->caplen = header->caplen;
    stats->receivedFrames++;
    *p_more = 1;
    break;
    
  case 0:
    
    //
    // No packet within the specified wait time. Continue, nothing to do.
    // 
    
    *p_packet = 0;
    *p_more = 1;
    break;

  case -1:
  case -2:
  default:
    
    //
    // End of file or read error
    // 
    
    *p_packet = 0;
    *p_more = 0;
    break;

  }
}

//
// Return the currently used data link layer type
//

enum spindump_capture_linktype
spindump_capture_getlinktype(struct spindump_capture_state* state) {
  return(state->linktype);
}

//
// Delete the object, close the PCAP interface
//

void
spindump_capture_uninitialize(struct spindump_capture_state* state) {

  //
  // Check
  // 
  
  spindump_assert(state != 0);
  
  //
  // Close and cleanup
  // 

  if (state->handle != 0) {
    pcap_close(state->handle);
  }
  memset(state,0,sizeof(*state));
  
  //
  // Deallocate the state
  // 
  
  spindump_free(state);
}

