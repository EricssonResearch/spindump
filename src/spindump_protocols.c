
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
