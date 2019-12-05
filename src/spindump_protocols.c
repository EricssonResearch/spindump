
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
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
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
  do {                                                          \
    if (((val) & flag) != 0) {                                  \
      if (buf[0] != 0) spindump_strlcat(buf," ",sizeof(buf));     \
      spindump_strlcat(buf,string,sizeof(buf));                             \
    }                                                           \
  } while(0)
  
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
// Decode an Ethernet header from the packet bytes starting from the
// pointer "header". It is assumed to be long enough for the DNS
// header, i.e., the caller must have checked this.  The header as
// parsed and as converted to host byte order where applicable, is
// placed in the output parameter "decoded".
//

void
spindump_protocols_ethernet_header_decode(const unsigned char* header,
                                          struct spindump_ethernet* decoded) {
  
  //
  // Sanity checks
  //
  
  spindump_assert(header != 0);
  spindump_assert(decoded != 0);
  
  //
  // Parse the Ethernet header.
  //
  
  unsigned int pos = 0;
  spindump_decodebytes(decoded->ether_dest,header,spindump_ethernet_address_length,pos); // destination
  spindump_decodebytes(decoded->ether_src,header,spindump_ethernet_address_length,pos);  // source
  spindump_decode2byteint(decoded->ether_type,header,pos);                               // type
}

//
// Decode a IPv4 header from the packet bytes starting from the pointer
// "header". It is assumed to be long enough for the DNS header, i.e.,
// the caller must have checked this.  The header as parsed and as
// converted to host byte order where applicable, is placed in the
// output parameter "decoded".
//

void
spindump_protocols_ip_header_decode(const unsigned char* header,
                                    struct spindump_ip* decoded) {
  
  //
  // Sanity checks
  //
  
  spindump_assert(header != 0);
  spindump_assert(decoded != 0);
  
  //
  // Parse the IP header. The header is defined in RFC 760:
  //
  //   0                   1                   2                   3   
  //   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |Version|  IHL  |Type of Service|          Total Length         |
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |         Identification        |Flags|      Fragment Offset    |
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |  Time to Live |    Protocol   |         Header Checksum       |
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                       Source Address                          |
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                    Destination Address                        |
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                    Options                    |    Padding    |
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //
  
  unsigned int pos = 0;
  spindump_decodebyte(decoded->ip_vhl,header,pos);       // version & header length
  spindump_decodebyte(decoded->ip_tos,header,pos);       // type of service
  spindump_decode2byteint(decoded->ip_len,header,pos);   // total length
  spindump_decode2byteint(decoded->ip_id,header,pos);    // identification
  spindump_decode2byteint(decoded->ip_off,header,pos);   // fragment offset field
  spindump_decodebyte(decoded->ip_ttl,header,pos);       // time to live
  spindump_decodebyte(decoded->ip_proto,header,pos);     // protocol
  spindump_decode2byteint(decoded->ip_sum,header,pos);   // checksum
  spindump_decodebytes(decoded->ip_src,header,4,pos);    // source address
  spindump_deepdebugf("IPv4 source set from %u.%u.%u.%u to %08x",
                      header[pos - 4], header[pos - 3], header[pos - 2], header[pos - 1],
                      decoded->ip_src);
  spindump_decodebytes(decoded->ip_dst,header,4,pos);    // destination address
  spindump_deepdebugf("IPv4 destination set from %u.%u.%u.%u to %08x",
                      header[pos - 4], header[pos - 3], header[pos - 2], header[pos - 1],
                      decoded->ip_dst);
}

//
// Decode a IPv6 header from the packet bytes starting from the pointer
// "header". It is assumed to be long enough for the DNS header, i.e.,
// the caller must have checked this.  The header as parsed and as
// converted to host byte order where applicable, is placed in the
// output parameter "decoded".
//

void
spindump_protocols_ip6_header_decode(const unsigned char* header,
                                     struct spindump_ip6* decoded) {
  
  //
  // Sanity checks
  //
  
  spindump_assert(header != 0);
  spindump_assert(decoded != 0);
  
  //
  // Parse the IPv6 header. The header is defined in RFC 2460:
  //
  //
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |Version| Traffic Class |           Flow Label                  |
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |         Payload Length        |  Next Header  |   Hop Limit   |
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                                                               |
  //   +                                                               +
  //   |                                                               |
  //   +                         Source Address                        +
  //   |                                                               |
  //   +                                                               +
  //   |                                                               |
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                                                               |
  //   +                                                               +
  //   |                                                               |
  //   +                      Destination Address                      +
  //   |                                                               |
  //   +                                                               +
  //   |                                                               |
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //
  
  unsigned int pos = 0;
  spindump_decodebyte(decoded->ip6_vtc,header,pos);             // version & traffic class
  spindump_decodebyte(decoded->ip6_tcfl,header,pos);            // traffic class & flow label
  spindump_decodebytes(decoded->ip6_flowlabel,header,2,pos);    // flow label
  spindump_decode2byteint(decoded->ip6_payloadlen,header,pos);  // length
  spindump_decodebyte(decoded->ip6_nextheader,header,pos);      // protocol
  spindump_decodebyte(decoded->ip6_hoplimit,header,pos);        // hop limit
  spindump_decodebytes(decoded->ip6_source,header,16,pos);      // source address
  spindump_decodebytes(decoded->ip6_destination,header,16,pos); // destination address
}

//
// Decode an IPv6 Fragment Header (FH) from the packet bytes starting
// from the pointer "header". It is assumed to be long enough for the
// DNS header, i.e., the caller must have checked this.  The header as
// parsed and as converted to host byte order where applicable, is
// placed in the output parameter "decoded".
//

void
spindump_protocols_ip6_fh_header_decode(const unsigned char* header,
                                        struct spindump_ip6_fh* decoded) {
  
  //
  // Sanity checks
  //
  
  spindump_assert(header != 0);
  spindump_assert(decoded != 0);

  //
  // Parse the FH header. The header is as defined in RFC 2460:
  //
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |  Next Header  |   Reserved    |      Fragment Offset    |Res|M|
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                         Identification                        |
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //
  
  unsigned int pos = 0;
  spindump_decodebyte(decoded->fh_nextheader,header,pos);         // next header
  spindump_decodebyte(decoded->fh_reserved,header,pos);           // reserved
  spindump_decode2byteint(decoded->fh_off,header,pos);            // offset, reserved, and more flag
  spindump_decode4byteint(decoded->fh_identification,header,pos); // identification
}

//
// Decode a ICMP header from the packet bytes starting from the pointer
// "header". It is assumed to be long enough for the DNS header, i.e.,
// the caller must have checked this.  The header as parsed and as
// converted to host byte order where applicable, is placed in the
// output parameter "decoded".
//

void
spindump_protocols_icmp_header_decode(const unsigned char* header,
                                      struct spindump_icmp* decoded) {
  
  //
  // Sanity checks
  //
  
  spindump_assert(header != 0);
  spindump_assert(decoded != 0);
  
  //
  // Parse the ICMPv6 header. The header is defined in RFC 792:
  //
  //    0                   1                   2                   3
  //    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |     Type      |     Code      |          Checksum             |
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |           Identifier          |        Sequence Number        |
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |     Data ...
  //   +-+-+-+-+-
  //
  
  unsigned int pos = 0;
  spindump_decodebyte(decoded->ih_type,header,pos);       // type
  spindump_decodebyte(decoded->ih_code,header,pos);       // code
  spindump_decode2byteint(decoded->ih_csum,header,pos);   // csum
  if (decoded->ih_type == ICMP_ECHO || decoded->ih_type == ICMP_ECHOREPLY) {
    spindump_decode2byteint(decoded->ih_u.ih_echo.ih_id,header,pos);   // identifier
    spindump_decode2byteint(decoded->ih_u.ih_echo.ih_seq,header,pos);  // sequence number
  }
}

//
// Decode a ICMPv6 header from the packet bytes starting from the pointer
// "header". It is assumed to be long enough for the DNS header, i.e.,
// the caller must have checked this.  The header as parsed and as
// converted to host byte order where applicable, is placed in the
// output parameter "decoded".
//

void
spindump_protocols_icmp6_header_decode(const unsigned char* header,
                                       struct spindump_icmpv6* decoded) {

  //
  // Sanity checks
  //

  spindump_assert(header != 0);
  spindump_assert(decoded != 0);

  //
  // Parse the ICMPv6 header. The header is defined in RFC 2463:
  //
  //     0                   1                   2                   3
  //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //    |     Type      |     Code      |          Checksum             |
  //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //    |           Identifier          |        Sequence Number        |
  //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //    |     Data ...
  //    +-+-+-+-+-
  //
  
  unsigned int pos = 0;
  spindump_decodebyte(decoded->ih6_type,header,pos);       // type
  spindump_decodebyte(decoded->ih6_code,header,pos);       // code
  spindump_decode2byteint(decoded->ih6_csum,header,pos);   // csum
  if (decoded->ih6_type == ICMP6_ECHO_REQUEST || decoded->ih6_type == ICMP6_ECHO_REPLY) {
    spindump_decode2byteint(decoded->ih6_u.ih6_echo.ih6_id,header,pos);   // identifier
    spindump_decode2byteint(decoded->ih6_u.ih6_echo.ih6_seq,header,pos);  // sequence number
  }
  
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

//
// Decode a COAP header from the packet bytes starting from the pointer
// "header". It is assumed to be long enough for the DNS header, i.e.,
// the caller must have checked this.  The header as parsed and as
// converted to host byte order where applicable, is placed in the
// output parameter "decoded".
//

void
spindump_protocols_coap_header_decode(const unsigned char* header,
                                     struct spindump_coap* decoded) {

  //
  // Sanity checks
  //

  spindump_assert(header != 0);
  spindump_assert(decoded != 0);

  // 
  // Parse the COAP header. The structure is from RFC 7252, Figure 7:
  //
  //  0                   1                   2                   3
  //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |Ver| T |  TKL  |      Code     |          Message ID           |
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |   Token (if any, TKL bytes) ...
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |   Options (if any) ...
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |1 1 1 1 1 1 1 1|    Payload (if any) ...
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //
  //
  
  unsigned int pos = 0;
  
  spindump_decodebyte(decoded->verttkl,header,pos);       // version, T, and TKL fields
  spindump_decodebyte(decoded->code,header,pos);          // code
  spindump_decode2byteint(decoded->id,header,pos);        // message identifier
}

//
// Decode a TCP header from the packet bytes starting from the pointer
// "header". It is assumed to be long enough for the DNS header, i.e.,
// the caller must have checked this.  The header as parsed and as
// converted to host byte order where applicable, is placed in the
// output parameter "decoded".
//

void
spindump_protocols_tcp_header_decode(const unsigned char* header,
                                     struct spindump_tcp* decoded) {

  //
  // Sanity checks
  //

  spindump_assert(header != 0);
  spindump_assert(decoded != 0);

  // 
  // Parse the TCP header. The structure is from RFC 793:
  //
  //  0                   1                   2                   3
  //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |          Source Port          |       Destination Port        |
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                        Sequence Number                        |
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                    Acknowledgment Number                      |
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |  Data |           |U|A|P|R|S|F|                               |
  //  | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
  //  |       |           |G|K|H|T|N|N|                               |
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |           Checksum            |         Urgent Pointer        |
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                    Options                    |    Padding    |
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                             data                              |
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //
  //
  
  unsigned int pos = 0;
  
  spindump_decode2byteint(decoded->th_sport,header,pos);       // source port
  spindump_decode2byteint(decoded->th_dport,header,pos);       // destination port
  spindump_decode4byteint(decoded->th_seq,header,pos);         // sequence number
  spindump_decode4byteint(decoded->th_ack,header,pos);         // acknowledgement number
  spindump_decodebyte(decoded->th_offx2,header,pos);           // data offset, rsvd
  spindump_decodebyte(decoded->th_flags,header,pos);           // flags
  spindump_decode2byteint(decoded->th_win,header,pos);         // window
  spindump_decode2byteint(decoded->th_sum,header,pos);         // checksum
  spindump_decode2byteint(decoded->th_urp,header,pos);         // urgent pointer
}

//
// Decode a SCTP header from the packet bytes starting from the pointer
// "header". It is assumed to be long enough for the SCTP header, i.e.,
// the caller must have checked this.  The header as parsed and as
// converted to host byte order where applicable, is placed in the
// output parameter "decoded".
//

void
spindump_protocols_sctp_header_decode(const unsigned char* header,
                                     struct spindump_sctp* decoded) {

  //
  // Sanity checks
  //

  spindump_assert(header != 0);
  spindump_assert(decoded != 0);

  //
  // SCTP header from RFC 4960:
  //
  // 0                   1                   2                   3
  // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |     Source Port Number        |     Destination Port Number   |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                      Verification Tag                         |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                           Checksum                            |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //
  unsigned int pos = 0;
  spindump_decode2byteint(decoded->sh_sport,header,pos);     // source port
  spindump_decode2byteint(decoded->sh_dport,header,pos);     // destination port
  spindump_decode4byteint(decoded->sh_vtag,header,pos);      // Verification Tag
  spindump_decode4byteint(decoded->sh_checksum,header,pos);  // Cheksum
}

//
// Decode a QUIC header from the packet bytes starting from the pointer
// "header". It is assumed to be long enough for the DNS header, i.e.,
// the caller must have checked this.  The header as parsed and as
// converted to host byte order where applicable, is placed in the
// output parameter "decoded".
//

void
spindump_protocols_quic_header_decode(const unsigned char* header,
                                      unsigned char* decoded) {
  
  //
  // Sanity checks
  //

  spindump_assert(header != 0);
  spindump_assert(decoded != 0);

  // 
  // Parse the QUIC header. The structure is from
  // draft-ietf-quic-transport; to begin with we can just take the
  // first byte which will tell us whether this is a short or long
  // form, etc.
  //
  // Draft 17 short header:
  //
  //   +-+-+-+-+-+-+-+-+
  //   |0|1|S|R|R|K|P P|
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                Destination Connection ID (0..144)           ...
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                     Packet Number (8/16/24/32)              ...
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                     Protected Payload (*)                   ...
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //
  //
  // Draft 16 short header:
  //
  //   +-+-+-+-+-+-+-+-+
  //   |0|K|1|1|0|R R R|
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                Destination Connection ID (0..144)           ...
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                      Packet Number (8/16/32)                ...
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                     Protected Payload (*)                   ...
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //

  *decoded = *header;
}

//
// Decode a QUIC header from the packet bytes starting from the pointer
// "header". It is assumed to be long enough for the DNS header, i.e.,
// the caller must have checked this.  The header as parsed and as
// converted to host byte order where applicable, is placed in the
// output parameter "decoded".
//

void
spindump_protocols_quic_longheader_decode(const unsigned char* header,
                                          struct spindump_quic* decoded) {
  
  //
  // Sanity checks
  //

  spindump_assert(header != 0);
  spindump_assert(decoded != 0);

  // 
  // Parse the QUIC header. The structure is from draft-ietf-quic-transport:
  //
  //
  // Draft 17 long header:
  //
  //   +-+-+-+-+-+-+-+-+
  //   |1|1|T T|R R|P P|
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                         Version (32)                          |
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |DCIL(4)|SCIL(4)|
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |               Destination Connection ID (0/32..144)         ...
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                 Source Connection ID (0/32..144)            ...
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                           Length (i)                        ...
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                    Packet Number (8/16/24/32)               ...
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                          Payload (*)                        ...
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //
  //
  // Draft 16 long header:
  //
  //   +-+-+-+-+-+-+-+-+
  //   |1|   Type (7)  |
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                         Version (32)                          |
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |DCIL(4)|SCIL(4)|
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |               Destination Connection ID (0/32..144)         ...
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                 Source Connection ID (0/32..144)            ...
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                           Length (i)                        ...
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                     Packet Number (8/16/32)                   |
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                          Payload (*)                        ...
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //
  //
  // Version negotiation:
  //
  //   +-+-+-+-+-+-+-+-+
  //   |1|  Unused (7) |
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                          Version (32)                         |
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |DCIL(4)|SCIL(4)|
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |               Destination Connection ID (0/32..144)         ...
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                 Source Connection ID (0/32..144)            ...
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                    Supported Version 1 (32)                 ...
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                   [Supported Version 2 (32)]                ...
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //                                ...
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                   [Supported Version N (32)]                ...
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //
  //
  
  unsigned int pos = 0;
  
  spindump_decodebyte(decoded->u.longheader.qh_byte,header,pos);        // header byte
  spindump_decodebytes(decoded->u.longheader.qh_version,header,4,pos);  // version
  spindump_decodebyte(decoded->u.longheader.qh_cidLengths,header,pos);  // CID length nibbles
}

//
// Decode a TLS record layer header from the packet bytes starting
// from the pointer "header". It is assumed to be long enough for the
// DNS header, i.e., the caller must have checked this.  The header as
// parsed and as converted to host byte order where applicable, is
// placed in the output parameter "decoded".
//

void
spindump_protocols_tls_recordlayerheader_decode(const unsigned char* header,
                                                struct spindump_tls_recordlayer* decoded) {
  
  //
  // Sanity checks
  //

  spindump_assert(header != 0);
  spindump_assert(decoded != 0);

  //
  // Parse the header, as specified in RFC 8446
  //

  unsigned int pos = 0;
  spindump_decodebyte(decoded->type,header,pos);        // type
  spindump_decodebytes(decoded->version,header,2,pos);  // version
  spindump_decodebytes(decoded->length,header,2,pos);   // length
}

//
// Decode a DTLS record layer header from the packet bytes starting
// from the pointer "header". It is assumed to be long enough for the
// DNS header, i.e., the caller must have checked this.  The header as
// parsed and as converted to host byte order where applicable, is
// placed in the output parameter "decoded".
//

void
spindump_protocols_dtls_recordlayerheader_decode(const unsigned char* header,
                                                 struct spindump_dtls_recordlayer* decoded) {
  
  //
  // Sanity checks
  //

  spindump_assert(header != 0);
  spindump_assert(decoded != 0);

  //
  // Parse the header, as specified in RFC 6347
  //

  unsigned int pos = 0;
  spindump_decodebyte(decoded->type,header,pos);              // type
  spindump_decodebytes(decoded->version,header,2,pos);        // version
  spindump_decodebytes(decoded->epoch,header,2,pos);          // epoch
  spindump_decodebytes(decoded->sequenceNumber,header,2,pos); // sequence number
  spindump_decodebytes(decoded->length,header,2,pos);         // length
}

//
// Decode a DTLS handshake header from the packet bytes starting
// from the pointer "header". It is assumed to be long enough for the
// DNS header, i.e., the caller must have checked this.  The header as
// parsed and as converted to host byte order where applicable, is
// placed in the output parameter "decoded".
//

void
spindump_protocols_tls_handshakeheader_decode(const unsigned char* header,
                                              struct spindump_tls_handshake* decoded) {
  //
  // Sanity checks
  //

  spindump_assert(header != 0);
  spindump_assert(decoded != 0);

  //
  // Parse the header, as specified in RFC 8446
  //

  unsigned int pos = 0;
  spindump_decodebyte(decoded->handshakeType,header,pos);       // type
  spindump_decodebytes(decoded->length,header,3,pos);           // length
}

//
// Decode a DTLS handshake header from the packet bytes starting
// from the pointer "header". It is assumed to be long enough for the
// DNS header, i.e., the caller must have checked this.  The header as
// parsed and as converted to host byte order where applicable, is
// placed in the output parameter "decoded".
//

void
spindump_protocols_dtls_handshakeheader_decode(const unsigned char* header,
                                               struct spindump_dtls_handshake* decoded) {
  //
  // Sanity checks
  //

  spindump_assert(header != 0);
  spindump_assert(decoded != 0);

  //
  // Parse the header, as specified in RFC 6347
  //
  
  unsigned int pos = 0;
  spindump_decodebyte(decoded->handshakeType,header,pos);       // type
  spindump_decodebytes(decoded->length,header,3,pos);           // length
  spindump_decodebytes(decoded->messageSeq,header,2,pos);       // sequence number
  spindump_decodebytes(decoded->fragmentOffset,header,3,pos);   // fragment offset
  spindump_decodebytes(decoded->fragmentLength,header,3,pos);   // fragment length
}
