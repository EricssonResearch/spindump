
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

#include <string.h>
#include "spindump_util.h"
#include "spindump_protocols.h"

//
// Actual code --------------------------------------------------------------------------------
//

//
// This helper function converts a TCP flags field to a set of
// printable option names, useful for debugs etc.
// 
// Note: This function is not thread safe.
//

const char*
spindump_protocols_tcp_flagstostring(uint8_t flags) {
  
  static char buf[50];
  buf[0] = 0;
  
# define spindump_checkflag(flag,string,val)                    \
  if (((val) & flag) != 0) {                                    \
    if (buf[0] != 0) spindump_strlcat(buf," ",sizeof(buf));	\
    spindump_strlcat(buf,string,sizeof(buf));			\
   }
  
  spindump_checkflag(SPINDUMP_TH_FIN,"FIN",flags);
  spindump_checkflag(SPINDUMP_TH_SYN,"SYN",flags);
  spindump_checkflag(SPINDUMP_TH_RST,"RST",flags);
  spindump_checkflag(SPINDUMP_TH_PUSH,"PUSH",flags);
  spindump_checkflag(SPINDUMP_TH_ACK,"ACK",flags);
  spindump_checkflag(SPINDUMP_TH_URG,"URG",flags);
  spindump_checkflag(SPINDUMP_TH_ECE,"ECE",flags);
  spindump_checkflag(SPINDUMP_TH_CWR,"CWR",flags);
  
  return(buf);
}
