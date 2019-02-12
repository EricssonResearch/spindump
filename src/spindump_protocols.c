
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

//
// Decode a UDP header from the packet bytes starting from the pointer
// "header". It is assumed to be long enough for the DNS header, i.e.,
// the caller must have checked this.  The header as parsed and as
// converted to host byte order where applicable, is placed in the
// output parameter "decoded".
//

void
spindump_protocols_udp_header_decode(const unsigned char* header,
				     struct spindump_udp* decoded) {

  //
  // Sanity checks
  //

  spindump_assert(header != 0);
  spindump_assert(decoded != 0);

  // 
  // Parse the UDP header. The structure is defined in RFC 768:
  //
  // 0      7 8     15 16    23 24    31
  // +--------+--------+--------+--------+
  // |     Source      |   Destination   |
  // |      Port       |      Port       |
  // +--------+--------+--------+--------+
  // |                 |                 |
  // |     Length      |    Checksum     |
  // +--------+--------+--------+--------+
  //

  unsigned int pos = 0;
  
  spindump_decode2byteint(decoded->uh_sport,header,pos);       // source port
  spindump_decode2byteint(decoded->uh_dport,header,pos);       // destination port
  spindump_decode2byteint(decoded->uh_len,header,pos);         // UDP header and payload length
  spindump_decode2byteint(decoded->uh_csum,header,pos);        // checksum
}

//
// Decode a DNS header from the packet bytes starting from the pointer
// "header". It is assumed to be long enough for the DNS header, i.e.,
// the caller must have checked this.  The header as parsed and as
// converted to host byte order where applicable, is placed in the
// output parameter "decoded".
//

void
spindump_protocols_dns_header_decode(const unsigned char* header,
				     struct spindump_dns* decoded) {

  //
  // Sanity checks
  //

  spindump_assert(header != 0);
  spindump_assert(decoded != 0);

  // 
  // Parse the DNS header. The structure is from RFC 1035, Section
  // 4.1.1:
  //
  //                                    1  1  1  1  1  1
  //      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
  //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //    |                      ID                       |
  //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
  //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //    |                    QDCOUNT                    |
  //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //    |                    ANCOUNT                    |
  //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //    |                    NSCOUNT                    |
  //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //    |                    ARCOUNT                    |
  //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //
  
  unsigned int pos = 0;
  
  spindump_decode2byteint(decoded->id,header,pos);       // message identifier
  spindump_decodebyte(decoded->flagsOpcode,header,pos);  // QR, Opcode, AA, TC, and RD fields
  spindump_decodebyte(decoded->flagsRcode,header,pos);   // RA, Z, and RCODE fields
  spindump_decode2byteint(decoded->QDCount,header,pos);  // QDCOUNT
  spindump_decode2byteint(decoded->ANCount,header,pos);  // ANCOUNT
  spindump_decode2byteint(decoded->NSCount,header,pos);  // NSCOUNT
  spindump_decode2byteint(decoded->ARCount,header,pos);  // ARCOUNT
}
