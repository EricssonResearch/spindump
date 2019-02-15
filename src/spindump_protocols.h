
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

#ifndef SPINDUMP_PROTOCOLS_H
#define SPINDUMP_PROTOCOLS_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <stdlib.h>

//
// Packet header definitions ------------------------------------------------------------------
//

#define spindump_ethernet_address_length	6
#define spindump_ethernet_header_size		(spindump_ethernet_address_length*2 + 2)
#define spindump_null_header_size		4

typedef uint16_t spindump_port;

struct spindump_ethernet {
  unsigned char ether_dest[spindump_ethernet_address_length];
  unsigned char ether_src[spindump_ethernet_address_length];
  uint16_t ether_type;
# define spindump_ethertype_ip  0x0800
# define spindump_ethertype_ip6 0x86dd
};

struct spindump_ip {
  unsigned char ip_vhl;		    // version << 4 | header length >> 2
  unsigned char ip_tos;		    // type of service
  uint16_t ip_len;		    // total length
  uint16_t ip_id;		    // identification
  uint16_t ip_off;		    // fragment offset field
#define SPINDUMP_IP_RF 0x8000	    // reserved fragment flag
#define SPINDUMP_IP_DF 0x4000	    // dont fragment flag
#define SPINDUMP_IP_MF 0x2000	    // more fragments flag
#define SPINDUMP_IP_OFFMASK 0x1fff  // mask for fragmenting bits
  unsigned char ip_ttl;		    // time to live
  unsigned char ip_proto;	    // protocol
  uint16_t ip_sum;		    // checksum
  uint32_t ip_src;                  // source address
  uint32_t ip_dst;                  // dest address
};
#define SPINDUMP_IP_HL(ip)    (((ip)->ip_vhl) & 0x0f)
#define SPINDUMP_IP_V(ip)     (((ip)->ip_vhl) >> 4)
#define SPINDUMP_IP_ECN(ip)   (((ip)->ip_tos) & 0x3)

struct spindump_ip6addr {
  uint8_t addr[16];
};

//
// IPv6 header, as defined in RFC 2460:
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
//

struct spindump_ip6 {
  unsigned char ip6_vtc;	           // version & traffic class
  unsigned char ip6_tcfl;	           // traffic class & flow label
  uint8_t ip6_flowlabel[2];	           // flow label
  uint16_t ip6_payloadlen;	           // payload length
  unsigned char ip6_nextheader;	           // protocol
  unsigned char ip6_hoplimit;	           // hop limit
  struct spindump_ip6addr ip6_source;      // source address
  struct spindump_ip6addr ip6_destination; // destination address
};
#define SPINDUMP_IP6_V(ip)		(((ip)->ip6_vtc) >> 4)
#define SPINDUMP_IP6_ECN(ip)            ((((ip)->ip6_tcfl >> 4)) & 0x3)
  
//
// Fragment header from RFC 2460:
//
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Next Header  |   Reserved    |      Fragment Offset    |Res|M|
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Identification                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//

//
// IPv6 fragment header (FH) as defined in RFC 2460:
//
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |  Next Header  |   Reserved    |      Fragment Offset    |Res|M|
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                         Identification                        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//
   
#define SPINDUMP_IP6_FH_NEXTHDR         44

#define spindump_ip6_fh_header_size      8

struct spindump_ip6_fh {
  uint8_t fh_nextheader;	        // protocol
  uint8_t fh_reserved;                  // reserved
  uint16_t fh_off;                      // offset, reserved, and more flag
  uint32_t fh_identification;           // identification
# define spindump_ip6_fh_fragoff(field)    ((field)>>2)
# define spindump_ip6_fh_morefrag(field)   ((field)&1)
};

//
// ICMP header, as defined in RFC 792:
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

#define spindump_icmp_header_size        4
#define spindump_icmp_echo_header_size   (spindump_icmp_header_size+4)

struct spindump_icmp {
  uint8_t  ih_type;        	// type
  uint8_t  ih_code;        	// code
  uint16_t ih_csum;      	// checksum
  union {
    struct {
      uint16_t ih_id;      	// identifier
      uint16_t ih_seq;      	// sequence number
      uint8_t  ih_data[2];     	// data (zero or more bytes)
    } ih_echo;
  } ih_u;
};

//
// ICMPv6 header, as defined in RFC 2463:
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

struct spindump_icmpv6 {
  uint8_t  ih6_type;        	// type
  uint8_t  ih6_code;        	// code
  uint16_t ih6_csum;      	// checksum
  union {
    struct {
      uint16_t ih6_id;      	// identifier
      uint16_t ih6_seq;      	// sequence number
      uint8_t  ih6_data[2];    	// data (zero or more bytes)
    } ih6_echo;
  } ih6_u;
};

//
// UDP header is defined in RFC 768:
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

#define spindump_udp_header_size 8

struct spindump_udp {
  spindump_port uh_sport;      	// source port
  spindump_port uh_dport;    	// destination port
  uint16_t uh_len;         	// UDP header and payload length
  uint16_t uh_csum;      	// checksum
};

//
// DNS header from RFC 1035, Section 4.1.1:
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
// And from IANA DNS registry
// (https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml):
//
// DNS OpCodes
//
// 0	Query	[RFC1035]
// 1	IQuery (Inverse Query, OBSOLETE)	[RFC3425]
// 2	Status	[RFC1035]
// 4	Notify	[RFC1996]
// 5	Update	[RFC2136]
// 6	DNS Stateful Operations (DSO)	[RFC-ietf-dnsop-session-signal-20]
//
// DNS RCODEs
//
// 0	NoError	No Error	[RFC1035]
// 1	FormErr	Format Error	[RFC1035]
// 2	ServFail	Server Failure	[RFC1035]
// 3	NXDomain	Non-Existent Domain	[RFC1035]
// 4	NotImp	Not Implemented	[RFC1035]
// 5	Refused	Query Refused	[RFC1035]
// 6	YXDomain	Name Exists when it should not	[RFC2136][RFC6672]
// 7	YXRRSet	RR Set Exists when it should not	[RFC2136]
// 8	NXRRSet	RR Set that should exist does not	[RFC2136]
// 9	NotAuth	Server Not Authoritative for zone	[RFC2136]
// 9	NotAuth	Not Authorized	[RFC2845]
// 10	NotZone	Name not contained in zone	[RFC2136]
// 11	DSOTYPENI	DSO-TYPE Not Implemented	[RFC-ietf-dnsop-session-signal-20]
// 16	BADVERS	Bad OPT Version	[RFC6891]
// 16	BADSIG	TSIG Signature Failure	[RFC2845]
// 17	BADKEY	Key not recognized	[RFC2845]
// 18	BADTIME	Signature out of time window	[RFC2845]
// 19	BADMODE	Bad TKEY Mode	[RFC2930]
// 20	BADNAME	Duplicate key name	[RFC2930]
// 21	BADALG	Algorithm not supported	[RFC2930]
// 22	BADTRUNC	Bad Truncation	[RFC4635]
// 23	BADCOOKIE	Bad/missing Server Cookie	[RFC7873]
//

#define spindump_dns_header_size     (2+1+1+4*2)

struct spindump_dns {
  uint16_t id;                  // message identifier
  uint8_t flagsOpcode;          // QR, Opcode, AA, TC, and RD fields
# define spindump_dns_flagsopcode_qr        0x80
# define spindump_dns_flagsopcode_qr_shift     7
# define spindump_dns_flagsopcode_opcode    0x78
# define spindump_dns_flagsopcode_opcode_shift 3
# define spindump_dns_flagsopcode_aa        0x04
# define spindump_dns_flagsopcode_aa_shift     2
# define spindump_dns_flagsopcode_tc        0x02
# define spindump_dns_flagsopcode_tc_shift     1
# define spindump_dns_flagsopcode_rd        0x01
# define spindump_dns_flagsopcode_rd_shift     0
# define spindump_dns_opcode_query             0
# define spindump_dns_opcode_iquery            1
# define spindump_dns_opcode_status            2
# define spindump_dns_opcode_notify            4
# define spindump_dns_opcode_update            5
# define spindump_dns_opcode_dso               6
  uint8_t flagsRcode;           // RA, Z, and RCODE fields
# define spindump_dns_flagsrcode_ra         0x80
# define spindump_dns_flagsrcode_z          0x70
# define spindump_dns_flagsrcode_rcode      0x0F
# define spindump_dns_rcode_NoError            0
# define spindump_dns_rcode_FormErr            1
# define spindump_dns_rcode_ServFail           2
# define spindump_dns_rcode_NXDomain           3
# define spindump_dns_rcode_NotImp             4
# define spindump_dns_rcode_Refused            5
# define spindump_dns_rcode_YXDomain           6
# define spindump_dns_rcode_YXRRSet            7
# define spindump_dns_rcode_NXRRSet            8
# define spindump_dns_rcode_NotAuthorative     9
# define spindump_dns_rcode_NotAuthorized      9
# define spindump_dns_rcode_NotZone           10
# define spindump_dns_rcode_DSOTYPENI         11
# define spindump_dns_rcode_BADVERS           16
# define spindump_dns_rcode_BADSIG            16
# define spindump_dns_rcode_BADKEY            17
# define spindump_dns_rcode_BADTIME           18
# define spindump_dns_rcode_BADMODE           19
# define spindump_dns_rcode_BADNAME           20
# define spindump_dns_rcode_BADALG            21
# define spindump_dns_rcode_BADTRUNC          22
# define spindump_dns_rcode_BADCOOKIE         23
  uint16_t QDCount;             // QDCOUNT
  uint16_t ANCount;             // ANCOUNT
  uint16_t NSCount;             // NSCOUNT
  uint16_t ARCount;             // ARCOUNT
};

//
// COAP protocol, RFC 7252, Figure 7:
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

#define spindump_coap_header_size       (1+1+2)

struct spindump_coap {
  uint8_t verttkl;              // version, T, and TKL fields
  uint8_t code;                 // code
  uint16_t id;                  // message identifier
};

#define spindump_coap_verttkl_vermask                0xC0
#define spindump_coap_verttkl_ver1                   0x40
#define spindump_coap_verttkl_tmask                  0x30
#define spindump_coap_verttkl_tcomfirmable           0x00
#define spindump_coap_verttkl_tnoncomfirmable        0x10
#define spindump_coap_verttkl_tacknowledgement       0x20
#define spindump_coap_verttkl_treset                 0x30
#define spindump_coap_verttkl_tklmask                0x0F
#define spindump_coap_code_classmask                 0xE0
#define spindump_coap_code_classrequest              0x00
#define spindump_coap_code_classsuccessresponse      0x40
#define spindump_coap_code_classclienterrorresponse  0x80
#define spindump_coap_code_classservererrorresponse  0xA0

//
// TLS and DTLS protocol (for coaps: traffic). See RFCs 6066, 6347
// and 8446.
//
// Base TLS 1.3 from RFC 8446:
//
// Record layer:
//
//      enum {
//          invalid(0),
//          change_cipher_spec(20),
//          alert(21),
//          handshake(22),
//          application_data(23),
//          (255)
//      } ContentType;
//
//      struct {
//         ContentType type;
//         ProtocolVersion legacy_record_version;
//         uint16 length;
//         opaque fragment[TLSPlaintext.length];
//      } TLSPlaintext;
//
//
// DTLS record layer from RFC 6347:
//
//      struct {
//          ContentType type;
//          ProtocolVersion version;
//          uint16 epoch;                                    // New field
//          uint48 sequence_number;                          // New field
//          uint16 length;
//          opaque fragment[DTLSPlaintext.length];
//      } DTLSPlaintext;
//
//
// Handshakes:
//
//      enum {
//          client_hello(1),
//          server_hello(2),
//          new_session_ticket(4),
//          end_of_early_data(5),
//          encrypted_extensions(8),
//          certificate(11),
//          certificate_request(13),
//          certificate_verify(15),
//          finished(20),
//          key_update(24),
//          message_hash(254),
//          (255)
//      } HandshakeType;
//
//      struct {
//          HandshakeType msg_type;    // handshake type
//          uint24 length;             // bytes in message
//          select (Handshake.msg_type) {
//              case client_hello:          ClientHello;
//              case server_hello:          ServerHello;
//              case end_of_early_data:     EndOfEarlyData;
//              case encrypted_extensions:  EncryptedExtensions;
//              case certificate_request:   CertificateRequest;
//              case certificate:           Certificate;
//              case certificate_verify:    CertificateVerify;
//              case finished:              Finished;
//              case new_session_ticket:    NewSessionTicket;
//              case key_update:            KeyUpdate;
//          };
//      } Handshake;
//
//  And from RFC 6347, the handshake format is as follows:
//
//      struct {
//          HandshakeType msg_type;
//          uint24 length;
//          uint16 message_seq;
//          uint24 fragment_offset;
//          uint24 fragment_length;
//          select (HandshakeType) {
//              case hello_request: HelloRequest;
//              case client_hello:  ClientHello;
//              case hello_verify_request: HelloVerifyRequest;  // New type
//              case server_hello:  ServerHello;
//              case certificate:Certificate;
//              case server_key_exchange: ServerKeyExchange;
//              case certificate_request: CertificateRequest;
//              case server_hello_done:ServerHelloDone;
//              case certificate_verify:  CertificateVerify;
//              case client_key_exchange: ClientKeyExchange;
//              case finished: Finished;
//          } body;
//      } Handshake;
//
//
//  A client hello:
//
//      uint16 ProtocolVersion;
//      opaque Random[32];
//
//      uint8 CipherSuite[2];    // Cryptographic suite selector
//
//      struct {
//          ProtocolVersion legacy_version = 0x0303;    // TLS v1.2
//          Random random;
//          opaque legacy_session_id<0..32>;
//          CipherSuite cipher_suites<2..2^16-2>;
//          opaque legacy_compression_methods<1..2^8-1>;
//          Extension extensions<8..2^16-1>;
//      } ClientHello;
//
//  A server hello:
//
//       struct {
//           ProtocolVersion legacy_version = 0x0303;    // TLS v1.2
//           Random random;
//           opaque legacy_session_id_echo<0..32>;
//           CipherSuite cipher_suite;
//           uint8 legacy_compression_method = 0;
//           Extension extensions<6..2^16-1>;
//       } ServerHello;
//
//
//  A server hello verify request in DTLS (RFC 6347):
//
//  struct {
//      ProtocolVersion server_version;
//      opaque cookie<0..2^8-1>;
//  } HelloVerifyRequest;
//
//

#define spindump_tls_recordlayer_content_type_invalid            0
#define spindump_tls_recordlayer_content_type_changecipherspec  20
#define spindump_tls_recordlayer_content_type_alert             21
#define spindump_tls_recordlayer_content_type_handshake         22
#define spindump_tls_recordlayer_content_type_applicationdata   23

#define spindump_tls_handshake_client_hello                      1
#define spindump_tls_handshake_server_hello                      2
#define spindump_tls_handshake_hello_verify_request              3
#define spindump_tls_handshake_new_session_ticket                4
#define spindump_tls_handshake_end_of_early_data                 5
#define spindump_tls_handshake_encrypted_extensions              8
#define spindump_tls_handshake_certificate                      11
#define spindump_tls_handshake_certificate_request              13
#define spindump_tls_handshake_certificate_verify               15
#define spindump_tls_handshake_finished                         20
#define spindump_tls_handshake_key_update                       24
#define spindump_tls_handshake_message_hash                    254

//
// From RFC 5246:
//
//   TLS Version 1.2, which uses the version { 3, 3 }.  The
//   version value 3.3 is historical, deriving from the use of {3, 1}
//   for TLS 1.0.
//
// And from RFC 4346:
//
//   The version of the protocol being employed.  This document
//   describes TLS Version 1.1, which uses the version { 3, 2 }.  The
//   version value 3.2 is historical: TLS version 1.1 is a minor
//   modification to the TLS 1.0 protocol, which was itself a minor
//   modification to the SSL 3.0 protocol, which bears the version
//   value 3.0.
//
// And from RFC 8446:
//
//   While the eventual version indicator for the RFC version of TLS 1.3
//   will be 0x0304, implementations of draft versions of this
//   specification SHOULD instead advertise 0x7f00 | draft_version in the
//   ServerHello and HelloRetryRequest "supported_versions" extension.
//   For instance, draft-17 would be encoded as the 0x7f11.  This allows
//   pre-RFC implementations to safely negotiate with each other, even if
//   they would otherwise be incompatible.
//

#define spindump_tls_legacy_version_10			0x0301
#define spindump_tls_legacy_version_11			0x0302
#define spindump_tls_legacy_version_12			0x0303
#define spindump_tls_tls_version_13			0x0304
#define spindump_tls_tls_version_dtlstotls(v)           ((~(v)) + 0x0201)
#define spindump_tls_tls_version_13_is_draft(v)		(((v)&0xff00) == 0x7f00)
#define spindump_tls_tls_version_13_draft_ver(v)	(((v)&0x00ff))
#define spindump_tls_tls_version_is_valid(v)		(((v)>>8) >= 0x03 && ((v)&0xff) >= 0x01)
#define spindump_tls_tls_version_major(v)		((((v)>>8) == 0x7f) ? 1 : (((v)>>8) - 2))
#define spindump_tls_tls_version_minor(v)		((((v)>>8) == 0x7f) ? 3 : (((v)&0xff) - 1))

typedef uint16_t spindump_tls_version;                  // internal representation in host byte order
typedef uint8_t spindump_tls_version_inpacket[2];       // 16 bit number
#define spindump_tls_2bytenum2touint16(x)               ((uint16_t)(((((uint16_t)((x)[0])) << 8) | ((uint16_t)((x)[1])))))
typedef uint8_t spindump_tls_epoch[2];                  // 16 bit number
typedef uint8_t spindump_tls_seqno[6];                  // 48 bit sequence numbers
typedef uint8_t spindump_tls_recordlength[2];           // 16 bit length
typedef uint8_t spindump_tls_handshakelength[3];        // 24 bit length
#define spindump_tls_handshakelength_touint(l)          ((((uint32_t)((l)[0])) << 16) | (((uint32_t)((l)[1]))<<8) | ((uint32_t)((l)[2])))
typedef uint8_t spindump_tls_random[32];
typedef uint8_t spindump_dtls_sequencenumber[2];
typedef uint8_t spindump_dtls_fragmentnumber[3];

#define spindump_tls_recordlayer_header_size (1+2+2)

struct spindump_tls_recordlayer {
  uint8_t type;
  spindump_tls_version_inpacket version;
  spindump_tls_recordlength length;
};

#define spindump_dtls_recordlayer_header_size (1+2+2+2+2)

struct spindump_dtls_recordlayer {
  uint8_t type;
  spindump_tls_version_inpacket version;
  spindump_tls_epoch epoch;
  spindump_tls_seqno sequenceNumber;
  spindump_tls_recordlength length;
};

#define spindump_tls_handshake_header_size (1+3)

struct spindump_tls_handshake {
  uint8_t handshakeType;
  spindump_tls_handshakelength length;
};

struct spindump_tls_handshake_clienthello {
  struct spindump_tls_handshake hdr;
  spindump_tls_version_inpacket version;
  spindump_tls_random random;
};

struct spindump_tls_handshake_serverhello {
  struct spindump_tls_handshake hdr;
  spindump_tls_version_inpacket version;
  spindump_tls_random random;
};

#define spindump_dtls_handshake_header_size (1+3+2+3+3)

struct spindump_dtls_handshake {
  uint8_t handshakeType;
  spindump_tls_handshakelength length;
  spindump_dtls_sequencenumber messageSeq;
  spindump_dtls_fragmentnumber fragmentOffset;
  spindump_dtls_fragmentnumber fragmentLength;
};

struct spindump_dtls_handshake_clienthello {
  struct spindump_dtls_handshake hdr;
  spindump_tls_version_inpacket version;
  spindump_tls_random random;
};

struct spindump_dtls_handshake_serverhello {
  struct spindump_dtls_handshake hdr;
  spindump_tls_version_inpacket version;
  spindump_tls_random random;
};

struct spindump_dtls_handshake_helloverifyrequest {
  struct spindump_dtls_handshake hdr;
  spindump_tls_version_inpacket version;
};

//
// TCP headers from RFC 793:
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

typedef uint32_t tcp_seq;

#define spindump_tcp_header_length     (2+2+4+4+1+1+2+2+2)

struct spindump_tcp {
  spindump_port th_sport;      	// source port
  spindump_port th_dport;    	// destination port
  tcp_seq th_seq;		// sequence number
  tcp_seq th_ack;		// acknowledgement number
  unsigned char th_offx2;	// data offset, rsvd
#define SPINDUMP_TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
  unsigned char th_flags;
#define SPINDUMP_TH_FIN 0x01
#define SPINDUMP_TH_SYN 0x02
#define SPINDUMP_TH_RST 0x04
#define SPINDUMP_TH_PUSH 0x08
#define SPINDUMP_TH_ACK 0x10
#define SPINDUMP_TH_URG 0x20
#define SPINDUMP_TH_ECE 0x40
#define SPINDUMP_TH_CWR 0x80
#define SPINDUMP_TH_FLAGS (SPINDUMP_TH_FIN | SPINDUMP_TH_SYN | SPINDUMP_TH_RST | \
			   SPINDUMP_TH_ACK | SPINDUMP_TH_URG | SPINDUMP_TH_ECE | \
			   SPINDUMP_TH_CWR)
  uint16_t th_win;		// window
  uint16_t th_sum;		// checksum
  uint16_t th_urp;		// urgent pointer
};

//
// Draft 17 high order bits
//

#define spindump_quic_byte_header_form         0xC0
#define spindump_quic_byte_form_short          0x40
#define spindump_quic_byte_form_long           0xC0
#define spindump_quic_byte_spin                0x20

//
// Draft 16 high order bits
//

#define spindump_quic_byte_header_form_draft16 0x80
#define spindump_quic_byte_form_long_draft16   0x80
#define spindump_quic_byte_form_short_draft16  0x00
#define spindump_quic_byte_spin_draft16        0x04

//
// Draft 17 message types
//
// +------+-----------------+--------------+
// | Type | Name            | Section      |
// +------+-----------------+--------------+
// |  0x0 | Initial         | Section 17.5 |
// |      |                 |              |
// |  0x1 | 0-RTT Protected | Section 12.1 |
// |      |                 |              |
// |  0x2 | Handshake       | Section 17.6 |
// |      |                 |              |
// |  0x3 | Retry           | Section 17.7 |
// +------+-----------------+--------------+
//
//

#define spindump_quic_byte_type                0x30
#define spindump_quic_byte_type_initial        0x00
#define spindump_quic_byte_type_0rttprotected  0x10
#define spindump_quic_byte_type_handshake      0x20
#define spindump_quic_byte_type_retry          0x30

enum spindump_quic_message_type {
  spindump_quic_message_type_data,
  spindump_quic_message_type_initial,
  spindump_quic_message_type_versionnegotiation,
  spindump_quic_message_type_retry,
  spindump_quic_message_type_other
};

//
// Draft 16 message types:
//
// +------+-----------------+--------------+
// | Type | Name            | Section      |
// +------+-----------------+--------------+
// | 0x7F | Initial         | Section 17.5 |
// |      |                 |              |
// | 0x7E | Retry           | Section 17.7 |
// |      |                 |              |
// | 0x7D | Handshake       | Section 17.6 |
// |      |                 |              |
// | 0x7C | 0-RTT Protected | Section 12.1 |
// +------+-----------------+--------------+
//
//

#define spindump_quic_byte_type_draft16                  0x7f
#define spindump_quic_byte_type_initial_draft16          0x7f
#define spindump_quic_byte_type_retry_draft16            0x7e
#define spindump_quic_byte_type_handshake_draft16        0x7d
#define spindump_quic_byte_type_0rttprotected_draft16    0x7c

//
// QUIC versions
//

#define spindump_quic_version_negotiation      0x00000000
#define spindump_quic_version_rfc              0x00000001
#define spindump_quic_version_draft17          0xff000011
#define spindump_quic_version_draft16          0xff000010
#define spindump_quic_version_draft15          0xff00000f
#define spindump_quic_version_draft14          0xff00000e
#define spindump_quic_version_draft13          0xff00000d
#define spindump_quic_version_draft12          0xff00000c
#define spindump_quic_version_draft11          0xff00000b
#define spindump_quic_version_draft10          0xff00000a
#define spindump_quic_version_draft09          0xff000009
#define spindump_quic_version_draft08          0xff000008
#define spindump_quic_version_draft07          0xff000007
#define spindump_quic_version_draft06          0xff000006
#define spindump_quic_version_draft05          0xff000005
#define spindump_quic_version_draft04          0xff000004
#define spindump_quic_version_draft03          0xff000003
#define spindump_quic_version_draft02          0xff000002
#define spindump_quic_version_draft01          0xff000001
#define spindump_quic_version_draft00          0xff000000
#define spindump_quic_version_huitema          0x50435131
#define spindump_quic_version_mozilla          0xf123f0c5
#define spindump_quic_version_forcenegotmask   0x0f0f0f0f
#define spindump_quic_version_forcenegotiation 0x0a0a0a0a
#define spindump_quic_version_unknown          0xffffffff

#define spindump_quic_header_length            1
#define spindump_quic_longheader_length        (1+4+1)

struct spindump_quic {

  union {

    struct {

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

      uint8_t   qh_byte;
      uint8_t   qh_destCid[1]; // could be 0-18 bytes

    } shortheader;

    struct {

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
      //

      uint8_t   qh_byte;
      uint8_t   qh_destCID;

    } shortheaderv16;

    struct {

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

      uint8_t   qh_byte;
      uint8_t   qh_version[4];
      uint8_t   qh_cidLengths;
      uint8_t   qh_cids[1];        // can be 0..2*14 bytes

    } longheader;

    struct {

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

      uint8_t   qh_byte;
      uint8_t   qh_version[4];
      uint8_t   qh_cidLengths;
      uint8_t   qh_cids[1];       // can be 0..2*14 bytes

    } longheaderv16;

    struct {

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

      uint8_t   qh_byte;
      uint8_t   qh_version[4];
      uint8_t   qh_cidLengths;
      uint8_t   qh_cids[1];      // can be 0..2*14 bytes

    } versionnegotiation;

  } u;
};

//
// Macros helping the decoding of messages ----------------------------------------------------
//

#define spindump_decodebyte(field,payload,position)     \
  memcpy(&(field),(payload)+((position)++),1)
#define spindump_decodebytes(field,payload,n,position)	\
  memcpy(&(field),(payload)+(position),(n));		\
  (position) += (n);
#define spindump_decode2byteint(field,payload,position) \
  memcpy(&(field),(payload)+(position),2);              \
  (position) += 2;                                      \
  (field) = ntohs((field))
#define spindump_decode4byteint(field,payload,position) \
  memcpy(&(field),(payload)+(position),4);              \
  (position) += 4;                                      \
  (field) = ntohl((field))

//
// External API interface ---------------------------------------------------------------------
//

const char*
spindump_protocols_tcp_flagstostring(uint8_t flags);
void
spindump_protocols_ethernet_header_decode(const unsigned char* header,
					  struct spindump_ethernet* decoded);
void
spindump_protocols_ip_header_decode(const unsigned char* header,
				    struct spindump_ip* decoded);
void
spindump_protocols_ip6_header_decode(const unsigned char* header,
				     struct spindump_ip6* decoded);
void
spindump_protocols_ip6_fh_header_decode(const unsigned char* header,
					struct spindump_ip6_fh* decoded);
void
spindump_protocols_icmp_header_decode(const unsigned char* header,
				      struct spindump_icmp* decoded);
void
spindump_protocols_icmp6_header_decode(const unsigned char* header,
				       struct spindump_icmpv6* decoded);
void
spindump_protocols_udp_header_decode(const unsigned char* header,
				     struct spindump_udp* decoded);
void
spindump_protocols_dns_header_decode(const unsigned char* header,
				     struct spindump_dns* decoded);
void
spindump_protocols_coap_header_decode(const unsigned char* header,
				      struct spindump_coap* decoded);
void
spindump_protocols_tcp_header_decode(const unsigned char* header,
				     struct spindump_tcp* decoded);
void
spindump_protocols_quic_header_decode(const unsigned char* header,
				      unsigned char* decoded);
void
spindump_protocols_quic_longheader_decode(const unsigned char* header,
					  struct spindump_quic* decoded);
void
spindump_protocols_tls_recordlayerheader_decode(const unsigned char* header,
						struct spindump_tls_recordlayer* decoded);
void
spindump_protocols_dtls_recordlayerheader_decode(const unsigned char* header,
						 struct spindump_dtls_recordlayer* decoded);
void
spindump_protocols_tls_handshakeheader_decode(const unsigned char* header,
					      struct spindump_tls_handshake* decoded);
void
spindump_protocols_dtls_handshakeheader_decode(const unsigned char* header,
					       struct spindump_dtls_handshake* decoded);

#endif // SPINDUMP_PROTOCOLS_H
