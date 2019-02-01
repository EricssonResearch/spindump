
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
#include "spindump_connections.h"
#include "spindump_analyze.h"
#include "spindump_analyze_tls_parser.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static int
spindump_analyze_tls_parser_parse_tlshandshakepacket(const unsigned char* payload,
						     unsigned int payload_len,
						     unsigned int record_layer_payload_len,
						     int isDatagram,
						     int* p_isInitialHandshake,
						     spindump_tls_version* p_tlsVersion,
						     int* p_isResponse);
static int
spindump_analyze_tls_isvalid_recordlayer_content_type(uint8_t type);
static void
spindump_analyze_tls_parse_versionconversion(spindump_tls_version_inpacket* valueInPacket,
					     int isDatagram,
					     spindump_tls_version* result);
static void
spindump_analyze_tls_parser_parse_tlshandshakepacket_finalperhtype_dtls(struct spindump_dtls_handshake* handshake,
									int* p_isInitialHandshake,
									spindump_tls_version* p_tlsVersion,
									int* p_isResponse);
static void
spindump_analyze_tls_parser_parse_tlshandshakepacket_finalperhtype_tls(struct spindump_tls_handshake* handshake,
								       int* p_isInitialHandshake,
								       spindump_tls_version* p_tlsVersion,
								       int* p_isResponse);

//
// Actual code --------------------------------------------------------------------------------
//

//
// Return a string representation of a TLS version number, e.g.,
// "1.3".  The returned string need not be freed, but it will not
// surive the next call to this function.
//
// Note: This function is not thread safe.
//

const char*
spindump_analyze_tls_parser_versiontostring(const spindump_tls_version version) {
  static char buf[40];

  if (version == 0) {
    
    sprintf(buf,"no version");
    
  } else if (!spindump_tls_tls_version_is_valid(version)) {
    
    sprintf(buf,"unknown version");
    
  } else if (spindump_tls_tls_version_13_is_draft(version)) {
    
    sprintf(buf,"1.3 draft %u", spindump_tls_tls_version_13_draft_ver(version));
    
  } else {
    
    unsigned char majorver = spindump_tls_tls_version_major(version);
    unsigned char minorver = spindump_tls_tls_version_minor(version);
    sprintf(buf,"%u.%u", majorver, minorver);
    
  }
  
  spindump_deepdebugf("TLS version %04x to string = %s", version, buf);
  
  return(buf);
}

//
// Retrieve a TLS version number from the packet, and after byte order
// conversion, do the DTLS mapping of version numbers if needed (TLS
// version numbers can be algorithmically determined from the
// corresponding DTLS version number).
//

static void
spindump_analyze_tls_parse_versionconversion(spindump_tls_version_inpacket* valueInPacket,
					     int isDatagram,
					     spindump_tls_version* result) {
  
  //
  // Input checks
  //
  
  spindump_assert(spindump_isbool(isDatagram));
  spindump_assert(valueInPacket != 0);
  spindump_assert(result != 0);

  //
  // Retrieve value from packet and make a byte order conversion
  //
  
  spindump_tls_version hostVersion = spindump_tls_2bytenum2touint16(*valueInPacket);
  
  //
  // Do the DTLS version number conversion, if necessary
  //
  
  if (isDatagram) {
    *result = spindump_tls_tls_version_dtlstotls(hostVersion);
  } else {
    *result = hostVersion;
  }
}

//
// Look to see if a packet is a likely TLS/DTLS packet. This check is
// on the basics of packet format (length sufficient, first byte
// values reasonable, if there's a version field, the version looks
// reasonable, etc)
//

int
spindump_analyze_tls_parser_isprobabletlspacket(const unsigned char* payload,
						unsigned int payload_len,
						int isDatagram) {

  //
  // Input checks
  // 

  spindump_assert(payload != 0);
  spindump_assert(spindump_isbool(isDatagram));

  //
  // Check that the packet is long enough for TLS record layer
  // 
  
  unsigned int recordLayerSize =
    isDatagram ?
    sizeof(struct spindump_dtls_recordlayer) :
    sizeof(struct spindump_tls_recordlayer);

  spindump_deepdebugf("spindump TLS analyzer payload length %u", payload_len);
  if (payload_len < recordLayerSize) {
    spindump_deepdebugf("spindump TLS analyzer payload size %u too small", payload_len);
    return(0);
  }

  //
  // Check that the packet header could be a record layer packet, 
  // with correct type etc
  // 

  uint16_t carriesLength;
  
  if (isDatagram) {

    struct spindump_dtls_recordlayer* record = (struct spindump_dtls_recordlayer*)payload;
    
    spindump_deepdebugf("spindump TLS analyzer precheck datagram content type %u",
			record->type);
    if (!spindump_analyze_tls_isvalid_recordlayer_content_type(record->type)) {
      spindump_deepdebugf("spindump TLS analyzer content type %u is invalid",
			  record->type);
      return(0);
    }

    spindump_tls_version version;
    spindump_analyze_tls_parse_versionconversion(&record->version,isDatagram,&version);
    spindump_deepdebugf("spindump TLS analyzer precheck datagram version %04x (in the packet %04x)",
			version,
			spindump_tls_2bytenum2touint16(record->version));
    if (!spindump_tls_tls_version_is_valid(version)) {
      spindump_deepdebugf("spindump TLS analyzer version %04x is invalid",
			  version);
      return(0);
    }

    carriesLength = spindump_tls_2bytenum2touint16(record->length);
    
  } else {
    
    struct spindump_tls_recordlayer* record = (struct spindump_tls_recordlayer*)payload;
    
    spindump_deepdebugf("spindump TLS analyzer precheck content type %u",
			record->type);
    if (!spindump_analyze_tls_isvalid_recordlayer_content_type(record->type)) {
      spindump_deepdebugf("spindump TLS analyzer content type %u is invalid",
			  record->type);
      return(0);
    }
    
    spindump_tls_version version;
    spindump_analyze_tls_parse_versionconversion(&record->version,isDatagram,&version);
    spindump_deepdebugf("spindump TLS analyzer precheck version %04x (in the packet %04x)",
			version,
			spindump_tls_2bytenum2touint16(record->version));
    if (!spindump_tls_tls_version_is_valid(version)) {
      spindump_deepdebugf("spindump TLS analyzer version %x is invalid",
			  version);
      return(0);
    }
    
    carriesLength = spindump_tls_2bytenum2touint16(record->length);
    
  }
  
  //
  // Check that the carried handshake/data is not of illegal length
  // RFC 6437 says: "the length should not exceed 2^14".
  // 
  
  spindump_deepdebugf("spindump TLS analyzer precheck internal size %u",
		      carriesLength);
  if (carriesLength > 16384) {
      spindump_deepdebugf("spindump TLS analyzer carried length %u is invalid",
			  carriesLength);
    return(0);
  }
  
  //
  // A propable TLS packet!
  // 
  
  return(1);
}

//
// This is the main entry point to the TLS parser. Spindump does not
// parse TLS packets beyond what the header is, as it is not a party
// of the communication and does not have encryption keys and does not
// want to have them either :-) But the parser looks at the header and
// basic connection establishment messages conveyed by the header.
//
// The inputs are pointer to the beginning of the TLS packet (= UDP or TCP
// payload), length of that payload, and how much of that has been
// captured in the part given to Spindump (as it may not use the full
// packets).
//
// This function returns 0 if the parsing fails, and then we can be
// sure that the packet is either invalid TLS/DTLS packet or from a
// version that this parser does not support.
//
// If the function returns 1, it will update the output parameters, by
// setting p_isHandshake to 1 if this is a TLS handshake,
// p_isInitialHandshake if it is the initial handshake, p_tlsVersion
// to the negotiated version, and p_isResponse to 1 if this is a
// response from a server.
//

int
spindump_analyze_tls_parser_parsepacket(const unsigned char* payload,
					unsigned int payload_len,
					unsigned int remainingCaplen,
					int isDatagram,
					int* p_isHandshake,
					int* p_isInitialHandshake,
					spindump_tls_version* p_tlsVersion,
					int* p_isResponse) {
  
  //
  // Input checks
  // 
  
  spindump_assert(payload != 0);
  spindump_assert(spindump_isbool(isDatagram));
  spindump_assert(p_isHandshake != 0);
  spindump_assert(p_isInitialHandshake != 0);
  spindump_assert(p_tlsVersion != 0);
  spindump_assert(p_isResponse != 0);

  //
  // Debugs
  // 

  spindump_deepdebugf("spindump TLS analyzer full parser");
  
  //
  // Check that the packet is long enough for TLS record layer
  // 
  
  unsigned int recordLayerSize =
    isDatagram ?
    sizeof(struct spindump_dtls_recordlayer) :
    sizeof(struct spindump_tls_recordlayer);
  
  if (payload_len < recordLayerSize ||
      remainingCaplen < recordLayerSize) {
    spindump_deepdebugf("spindump TLS analyzer payload size %u too small", payload_len);
    return(0);
  }

  //
  // Check that the packet header could be a record layer packet, 
  // with correct type etc
  // 

  uint16_t carriesLength;
  
  if (isDatagram) {

    struct spindump_dtls_recordlayer* record = (struct spindump_dtls_recordlayer*)payload;
    
    if (!spindump_analyze_tls_isvalid_recordlayer_content_type(record->type)) {
      spindump_deepdebugf("spindump TLS analyzer content type %u is invalid", record->type);
      return(0);
    }
    
    spindump_tls_version version;
    spindump_analyze_tls_parse_versionconversion(&record->version,isDatagram,&version);
    spindump_deepdebugf("spindump TLS analyzer datagram version in the packet %04x, converted as %04x",
			spindump_tls_2bytenum2touint16(record->version),
			version);
    if (!spindump_tls_tls_version_is_valid(version)) {
      spindump_deepdebugf("spindump TLS analyzer version %x is invalid", version);
      return(0);
    }

    carriesLength = spindump_tls_2bytenum2touint16(record->length);
    
  } else {
    
    struct spindump_tls_recordlayer* record = (struct spindump_tls_recordlayer*)payload;
    
    if (!spindump_analyze_tls_isvalid_recordlayer_content_type(record->type)) {
      spindump_deepdebugf("spindump TLS analyzer content type %u is invalid", record->type);
      return(0);
    }
    
    spindump_tls_version version;
    spindump_analyze_tls_parse_versionconversion(&record->version,isDatagram,&version);
    spindump_deepdebugf("spindump TLS analyzer version in the packet %04x, converted as %04x",
			spindump_tls_2bytenum2touint16(record->version),
			version);
    if (!spindump_tls_tls_version_is_valid(version)) {
      spindump_deepdebugf("spindump TLS analyzer version %x is invalid", version);
      return(0);
    }
    
    carriesLength = spindump_tls_2bytenum2touint16(record->length);
    
  }

  //
  // Check that the carried handshake/data is not of illegal length
  // RFC 6437 says: "the length should not exceed 2^14".
  // 
  
  if (carriesLength > 16384) {
      spindump_deepdebugf("spindump TLS analyzer carried length %u is invalid", carriesLength);
    return(0);
  }
  
  //
  // Check whether the packet is also a handshake packet
  // 

  if (spindump_analyze_tls_parser_parse_tlshandshakepacket(payload + recordLayerSize,
							   payload_len - recordLayerSize,
							   carriesLength,
							   isDatagram,
							   p_isInitialHandshake,
							   p_tlsVersion,
							   p_isResponse)) {
    spindump_deepdebugf("spindump TLS analyzer detects handshake packet initial %u version %04x response %u",
			*p_isInitialHandshake, *p_tlsVersion, *p_isResponse);
    *p_isHandshake = 1;
  } else {
    spindump_deepdebugf("spindump TLS analyzer detects non-handshake packet");
    *p_isHandshake = 0;
    *p_isInitialHandshake = 0;
    *p_tlsVersion = 0;
    *p_isResponse = 0;
  }
  
  //
  // A propable TLS packet!
  // 
  
  return(1);
}

//
// Parse a TLS handshake packet
//

static int
spindump_analyze_tls_parser_parse_tlshandshakepacket(const unsigned char* payload,
						     unsigned int payload_len,
						     unsigned int record_layer_payload_len,
						     int isDatagram,
						     int* p_isInitialHandshake,
						     spindump_tls_version* p_tlsVersion,
						     int* p_isResponse) {
  
  //
  // Input checks
  // 
  
  spindump_assert(payload != 0);
  spindump_assert(spindump_isbool(isDatagram));
  spindump_assert(p_isInitialHandshake != 0);
  spindump_assert(p_tlsVersion != 0);
  spindump_assert(p_isResponse != 0);
  
  //
  // Check that the remaining packet is long enough for TLS handshake:
  // 
  
  if (payload_len < sizeof(struct spindump_tls_handshake) ||
      record_layer_payload_len < sizeof(struct spindump_tls_handshake)) {
    spindump_deepdebugf("spindump TLS analyzer too small payload lengths %u %u", payload_len, record_layer_payload_len);
    return(0);
  }
  
  //
  // Check if the handshake type is know
  // 

  struct spindump_tls_handshake* handshake = (struct spindump_tls_handshake*)payload;
  spindump_deepdebugf("spindump TLS analyzer handshake type %u", handshake->handshakeType);
  switch (handshake->handshakeType) {
  case spindump_tls_handshake_client_hello:
  case spindump_tls_handshake_server_hello:
  case spindump_tls_handshake_hello_verify_request:
  case spindump_tls_handshake_new_session_ticket:
  case spindump_tls_handshake_end_of_early_data:
  case spindump_tls_handshake_encrypted_extensions:
  case spindump_tls_handshake_certificate:
  case spindump_tls_handshake_certificate_request:
  case spindump_tls_handshake_certificate_verify:
  case spindump_tls_handshake_finished:
  case spindump_tls_handshake_key_update:
  case spindump_tls_handshake_message_hash:
    break;
  default:
    spindump_deepdebugf("spindump TLS analyzer invalid handshake type %u", handshake->handshakeType);
    return(0);
  }

  //
  // Check that the handshake length fits inside the claimed payload size
  // 
  
  uint32_t length = spindump_tls_handshakelength_touint(handshake->length);
  if (length < sizeof(struct spindump_tls_handshake) ||
      length > payload_len ||
      length > record_layer_payload_len) {
    spindump_deepdebugf("spindump TLS analyzer invalid handshake length %u", handshake->handshakeType);
    return(0);
  }
  
  //
  // We're good. Probably handshake payload. Set the flags on output.
  // 

  if (isDatagram) {

    struct spindump_dtls_handshake* dtlsHandshake = (struct spindump_dtls_handshake*)handshake;
    spindump_analyze_tls_parser_parse_tlshandshakepacket_finalperhtype_dtls(dtlsHandshake,
									    p_isInitialHandshake,
									    p_tlsVersion,
									    p_isResponse);
    return(1);
    
  } else {
    
    spindump_analyze_tls_parser_parse_tlshandshakepacket_finalperhtype_tls(handshake,
									   p_isInitialHandshake,
									   p_tlsVersion,
									   p_isResponse);
    return(1);
    
  }
  
}

//
// Parse the handshake type and the handshake (e.g., client hello) within DTLS.
//

static void
spindump_analyze_tls_parser_parse_tlshandshakepacket_finalperhtype_dtls(struct spindump_dtls_handshake* handshake,
									int* p_isInitialHandshake,
									spindump_tls_version* p_tlsVersion,
									int* p_isResponse) {
  
  switch (handshake->handshakeType) {
    
  case spindump_tls_handshake_client_hello:
    {
      struct spindump_dtls_handshake_clienthello* hello =
	(struct spindump_dtls_handshake_clienthello*)handshake;
      *p_isInitialHandshake = 1;
      spindump_analyze_tls_parse_versionconversion(&hello->version,1,p_tlsVersion);
      spindump_deepdebugf("spindump DTLS analyzer setting version from client DTLS hello packet to %04x (originally %02x.%02x)",
			  *p_tlsVersion,
			  hello->version[0],
			  hello->version[1]);
      *p_isResponse = 0;
    }
    break;
    
  case spindump_tls_handshake_server_hello:
    {
      struct spindump_dtls_handshake_serverhello* hello =
	(struct spindump_dtls_handshake_serverhello*)handshake;
      *p_isInitialHandshake = 1;
      spindump_analyze_tls_parse_versionconversion(&hello->version,1,p_tlsVersion);
      spindump_deepdebugf("spindump DTLS analyzer setting version from server DTLS hello packet to %04x (originally %02x.%02x)",
			  *p_tlsVersion,
			  hello->version[0],
			  hello->version[1]);
      *p_isResponse = 1;
    }
    break;

  case spindump_tls_handshake_hello_verify_request:
    {
      struct spindump_dtls_handshake_helloverifyrequest* verify =
	(struct spindump_dtls_handshake_helloverifyrequest*)handshake;
      *p_isInitialHandshake = 1;
      spindump_analyze_tls_parse_versionconversion(&verify->version,1,p_tlsVersion);
      spindump_deepdebugf("spindump DTLS analyzer setting version from server DTLS hello verify request packet to %04x (originally %02x.%02x)",
			  *p_tlsVersion,
			  verify->version[0],
			  verify->version[1]);
      *p_isResponse = 1;
    }
    break;

  default:
    spindump_deepdebugf("spindump DTLS analyzer other handshake type, ignoring");
    *p_isInitialHandshake = 0;
    *p_tlsVersion = 0;
    *p_isResponse = 0;
    break;
  }

}

//
// Parse the handshake type and the handshake (e.g., client hello) within TLS.
//

static void
spindump_analyze_tls_parser_parse_tlshandshakepacket_finalperhtype_tls(struct spindump_tls_handshake* handshake,
								       int* p_isInitialHandshake,
								       spindump_tls_version* p_tlsVersion,
								       int* p_isResponse) {
  
  switch (handshake->handshakeType) {
    
  case spindump_tls_handshake_client_hello:
    {
      struct spindump_tls_handshake_clienthello* hello =
	(struct spindump_tls_handshake_clienthello*)handshake;
      *p_isInitialHandshake = 1;
      spindump_analyze_tls_parse_versionconversion(&hello->version,0,p_tlsVersion);
      spindump_deepdebugf("spindump TLS analyzer setting version from client TLS hello packet to %04x (originally %02x.%02x)",
			  *p_tlsVersion,
			  hello->version[0],
			  hello->version[1]);
      *p_isResponse = 0;
    }
    break;
    
  case spindump_tls_handshake_server_hello:
    {
      struct spindump_tls_handshake_serverhello* hello =
	(struct spindump_tls_handshake_serverhello*)handshake;
      *p_isInitialHandshake = 1;
      spindump_analyze_tls_parse_versionconversion(&hello->version,0,p_tlsVersion);
      spindump_deepdebugf("spindump TLS analyzer setting version from server TLS hello packet to %04x (originally %02x.%02x)",
			  *p_tlsVersion,
			  hello->version[0],
			  hello->version[1]);
      *p_isResponse = 1;
    }
    break;

  default:
    spindump_deepdebugf("spindump TLS analyzer other handshake type, ignoring");
    *p_isInitialHandshake = 0;
    *p_tlsVersion = 0;
    *p_isResponse = 0;
    break;
  }

}

//
// Determine whether a given TLS record layer content type is valid
//

static int
spindump_analyze_tls_isvalid_recordlayer_content_type(uint8_t type) {
  switch (type) {
  case spindump_tls_recordlayer_content_type_changecipherspec:
  case spindump_tls_recordlayer_content_type_alert:
  case spindump_tls_recordlayer_content_type_handshake:
  case spindump_tls_recordlayer_content_type_applicationdata:
    return(1);
  case spindump_tls_recordlayer_content_type_invalid:
  default:
    return(0);
  }
}
  
