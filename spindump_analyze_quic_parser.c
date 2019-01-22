
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

#include <stdlib.h>
#include <string.h>
#include "spindump_util.h"
#include "spindump_connections.h"
#include "spindump_analyze.h"
#include "spindump_analyze_quic.h"
#include "spindump_analyze_quic_parser.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static const char*
spindump_analyze_quic_parser_typetostring(enum spindump_quic_message_type type);
static unsigned int
spindump_analyze_quic_parser_onecidlength(uint8_t value);
static void
spindump_analyze_quic_parser_cidlengths(uint8_t lengthsbyte,
					unsigned int* p_destinationLength,
					unsigned int* p_sourceLength);

//
// Actual code --------------------------------------------------------------------------------
//

int
spindump_analyze_quic_quicidequal(struct spindump_quic_connectionid* id1,
				  struct spindump_quic_connectionid* id2) {
  spindump_assert(id1 != 0);
  spindump_assert(id2 != 0);
  return(id1->len == id2->len &&
	 memcmp(id1->id,id2->id,id2->len) == 0);
}

int
spindump_analyze_quic_partialquicidequal(const unsigned char* id1,
					struct spindump_quic_connectionid* id2) {
  spindump_assert(id1 != 0);
  spindump_assert(id2 != 0);
  return(memcmp(id1,id2->id,id2->len) == 0);
}

static const char*
spindump_analyze_quic_parser_typetostring(enum spindump_quic_message_type type) {
  switch (type) {
  case spindump_quic_message_type_data: return("data");
  case spindump_quic_message_type_initial: return("initial");
  case spindump_quic_message_type_versionnegotiation: return("version negotiation");
  case spindump_quic_message_type_retry: return("retry");
  case spindump_quic_message_type_other: return("other");
  default:
    spindump_fatalf("invalid QUIC message type %u", type);
    return("invalid");
  }
}

static unsigned int
spindump_analyze_quic_parser_onecidlength(uint8_t value) {
  spindump_assert(value < 16);
  if (value == 0) return(0);
  else return(value + 3);
}

static void
spindump_analyze_quic_parser_cidlengths(uint8_t lengthsbyte,
					unsigned int* p_destinationLength,
					unsigned int* p_sourceLength) {
  *p_destinationLength = spindump_analyze_quic_parser_onecidlength(lengthsbyte >> 4);
  *p_sourceLength = spindump_analyze_quic_parser_onecidlength(lengthsbyte & 0x0F);
  spindump_deepdebugf("CID lengths destination = %u, source = %u",
		      *p_destinationLength,
		      *p_sourceLength);
}

int
spindump_analyze_quic_parser_isprobablequickpacket(const unsigned char* payload,
						   unsigned int payload_len,
						   uint16_t sourcePort,
						   uint16_t destPort) {

  //
  // Make some checks
  // 

  spindump_assert(payload != 0);
  
  //
  // Look at the ports. Web ports and UDP implies likely QUIC.
  // 
  
  if (SPINDUMP_IS_QUIC_PORT(sourcePort) ||
      SPINDUMP_IS_QUIC_PORT(destPort)) {
    return(1);
  }

  //
  // Look at the packet contents, can we parse it?
  // 
  
  struct spindump_quic* quic = (struct spindump_quic*)payload;
  
  //
  // Parse initial byte
  // 
  
  if (payload_len < 1) return(0);
  uint8_t headerByte = quic->u.shortheader.qh_byte;
  int longForm = 0;
  uint32_t version = spindump_quic_version_unknown;
  if ((headerByte & spindump_quic_byte_header_form_draft16) == spindump_quic_byte_form_long_draft16) {
    spindump_deepdebugf("recognised v16 long header");
    longForm = 1;
    if (payload_len < 6) {
      return(0);
    }
  } else if ((headerByte & spindump_quic_byte_header_form) == spindump_quic_byte_form_long) {
    spindump_deepdebugf("recognised v17 long header");
    longForm = 1;
    if (payload_len < 6) {
      return(0);
    }
  }
  
  //
  // Can't really say much about the short version,
  // better say it is not QUIC.
  // 
  
  if (!longForm) return(0);
  
  //
  // Look at the version
  // 
  
  version = ((quic->u.longheader.qh_version[0] << 24) +
	     (quic->u.longheader.qh_version[1] << 16) +
	     (quic->u.longheader.qh_version[2] << 8) +
	     (quic->u.longheader.qh_version[3] << 0));
  spindump_deepdebugf("got the version %08x", version);
  if ((version & spindump_quic_version_forcenegotmask) == spindump_quic_version_forcenegotiation) {
    version = spindump_quic_version_forcenegotiation;
  }
  switch (version) {
  case spindump_quic_version_rfc:
  case spindump_quic_version_draft17:
  case spindump_quic_version_draft16:
  case spindump_quic_version_draft15:
  case spindump_quic_version_draft14:
  case spindump_quic_version_draft13:
  case spindump_quic_version_draft12:
  case spindump_quic_version_draft11:
  case spindump_quic_version_draft10:
  case spindump_quic_version_draft09:
  case spindump_quic_version_draft08:
  case spindump_quic_version_draft07:
  case spindump_quic_version_draft06:
  case spindump_quic_version_draft05:
  case spindump_quic_version_draft04:
  case spindump_quic_version_draft03:
  case spindump_quic_version_draft02:
  case spindump_quic_version_draft01:
  case spindump_quic_version_draft00:
  case spindump_quic_version_negotiation:
  case spindump_quic_version_forcenegotiation:
    break;
  default:
    return(0);
  }
  
  //
  // Look at the message type
  // 

  uint8_t messageType;
  switch (version) {
    
  case spindump_quic_version_rfc:
  case spindump_quic_version_draft17:
    messageType = headerByte & spindump_quic_byte_type;
    spindump_deepdebugf("looking at v17 message type %02x", messageType);
    switch (messageType) {
    case spindump_quic_byte_type_initial:
    case spindump_quic_byte_type_0rttprotected:
      break;
    case spindump_quic_byte_type_handshake:
    case spindump_quic_byte_type_retry:
    default:
      return(0);
    }
    break;
    
  case spindump_quic_version_draft16:
    messageType = headerByte & spindump_quic_byte_type_draft16;
    spindump_deepdebugf("looking at v16 message type %02x", messageType);
    switch (messageType) {
    case spindump_quic_byte_type_initial_draft16:
    case spindump_quic_byte_type_0rttprotected_draft16:
      break;
    case spindump_quic_byte_type_handshake_draft16:
    case spindump_quic_byte_type_retry_draft16:
    default:
      return(0);
    }
    break;

  case spindump_quic_version_negotiation:
    spindump_deepdebugf("looking at a version negotiation message");
    break;
    
  case spindump_quic_version_forcenegotiation:
    spindump_deepdebugf("looking at a version negotiation-forcing message");
    break;
    
  default:
    return(0);
  }
  
  //
  // If we got this far, the packet is likely a QUIC
  // long form packet from a recent draft version.
  // 

  spindump_deepdebugf("probably is a quic packet returns yes!");
  return(1);
}

int
spindump_analyze_quic_parser_parse(const unsigned char* payload,
				   unsigned int payload_len,
				   int* p_longform,
				   uint32_t* p_version,
				   int* p_destinationCidLengthKnown,
				   struct spindump_quic_connectionid* p_destinationCid,
				   int* p_sourceCidPresent,
				   struct spindump_quic_connectionid* p_sourceCid,
				   enum spindump_quic_message_type* p_type,
				   struct spindump_stats* stats) {
  
  //
  // Make some checks
  // 
  
  spindump_assert(payload != 0);
  spindump_assert(p_longform != 0);
  spindump_assert(p_version != 0);
  spindump_assert(p_destinationCid != 0);
  spindump_assert(p_sourceCid != 0);

  //
  // Initialize output parameters
  // 
  
  *p_longform = 0;
  *p_destinationCidLengthKnown = 0;
  memset(p_destinationCid,0,sizeof(*p_destinationCid));
  *p_sourceCidPresent = 0;
  memset(p_sourceCid,0,sizeof(*p_sourceCid));
  *p_type = spindump_quic_message_type_other;
  
  //
  // Look at the packet, determine whether the format is long (initial) exchange
  // or short (data phase).
  // 
  
  struct spindump_quic* quic = (struct spindump_quic*)payload;
  if (payload_len < 1) {
    stats->notEnoughPacketForQuicHdr++;
    return(0);
  }
  
  int longForm = 0;
  uint32_t version = spindump_quic_version_unknown;
  
  //
  // Parse initial byte
  // 
  
  uint8_t headerByte = quic->u.shortheader.qh_byte;
  if ((headerByte & spindump_quic_byte_header_form_draft16) == spindump_quic_byte_form_long_draft16) {
    longForm = 1;
    spindump_deepdebugf("QUIC long form packet first byte = %02x (payload %02x)", headerByte, payload[0]);
  } else {
    spindump_deepdebugf("QUIC short form packet first byte = %02x (payload %02x)", headerByte, payload[0]);
  }
  
  //
  // Parse version number
  // 
  
  if (longForm) {
    if (payload_len < 6) {
      stats->notEnoughPacketForQuicHdr++;
      return(0);
    }
    version = ((quic->u.longheader.qh_version[0] << 24) +
	       (quic->u.longheader.qh_version[1] << 16) +
	       (quic->u.longheader.qh_version[2] << 8) +
	       (quic->u.longheader.qh_version[3] << 0));
    spindump_deepdebugf("QUIC long form packet version = %lx", version);
    if ((version & spindump_quic_version_forcenegotmask) == spindump_quic_version_forcenegotiation) {
      version = spindump_quic_version_forcenegotiation;
    }
    switch (version) {
      
    case spindump_quic_version_rfc:
      // OK// 
      spindump_deepdebugf("QUIC version rfc ok");
      break;
      
    case spindump_quic_version_draft17:
    case spindump_quic_version_draft16:
      // OK// 
      spindump_deepdebugf("QUIC version ok");
      break;
      
    case spindump_quic_version_draft15:
    case spindump_quic_version_draft14:
    case spindump_quic_version_draft13:
    case spindump_quic_version_draft12:
    case spindump_quic_version_draft11:
    case spindump_quic_version_draft10:
    case spindump_quic_version_draft09:
    case spindump_quic_version_draft08:
    case spindump_quic_version_draft07:
    case spindump_quic_version_draft06:
    case spindump_quic_version_draft05:
    case spindump_quic_version_draft04:
    case spindump_quic_version_draft03:
    case spindump_quic_version_draft02:
    case spindump_quic_version_draft01:
    case spindump_quic_version_draft00:
      spindump_deepdebugf("QUIC version !ok");
      version = spindump_quic_version_unknown;
      stats->unsupportedQuicVersion++;
      return(0);
      
    case spindump_quic_version_negotiation:
      spindump_deepdebugf("QUIC version negotiation");
      version = spindump_quic_version_unknown;
      break;
      
    case spindump_quic_version_forcenegotiation:
      spindump_deepdebugf("QUIC forcing version negotiation");
      version = spindump_quic_version_unknown;
      break;
      
    default:
      spindump_deepdebugf("QUIC version just not recognised !ok");
      version = spindump_quic_version_unknown;
      stats->unrecognisedQuicVersion++;
      return(0);
      
    }
  }
  
  //
  // Parse message type
  // 
  
  enum spindump_quic_message_type type = spindump_quic_message_type_data;
  uint8_t messageType;
  if (longForm) {
    switch (version) {
      
    case spindump_quic_version_rfc:
    case spindump_quic_version_draft17:
      messageType = headerByte & spindump_quic_byte_type;
      spindump_deepdebugf("QUIC v17 message type %02x", messageType);
      switch (messageType) {
      case spindump_quic_byte_type_initial:
	type = spindump_quic_message_type_initial;
	spindump_deepdebugf("QUIC message type = initial");
	break;
      case spindump_quic_byte_type_0rttprotected:
	spindump_deepdebugf("QUIC message type = 0rttprotected");
	stats->unsupportedQuicType++;
	return(0);
      case spindump_quic_byte_type_handshake:
	spindump_deepdebugf("QUIC message type = handshake");
	stats->unsupportedQuicType++;
	return(0);
      case spindump_quic_byte_type_retry:
	spindump_deepdebugf("QUIC message type = retry");
	type = spindump_quic_message_type_retry;
	return(0);
      default:
	stats->unrecognisedQuicType++;
	return(0);
      }
      break;
      
    case spindump_quic_version_draft16:
      messageType = headerByte & spindump_quic_byte_type_draft16;
      spindump_deepdebugf("QUIC v17 message type %02x", messageType);
      switch (messageType) {
      case spindump_quic_byte_type_initial_draft16:
	type = spindump_quic_message_type_initial;
	spindump_deepdebugf("QUIC message type = initial");
	break;
      case spindump_quic_byte_type_0rttprotected_draft16:
	spindump_deepdebugf("QUIC message type = 0rttprotected");
	stats->unsupportedQuicType++;
	return(0);
      case spindump_quic_byte_type_handshake_draft16:
	spindump_deepdebugf("QUIC message type = handshake");
	stats->unsupportedQuicType++;
	return(0);
      case spindump_quic_byte_type_retry_draft16:
	spindump_deepdebugf("QUIC message type = retry");
	type = spindump_quic_message_type_retry;
	return(0);
      default:
	stats->unrecognisedQuicType++;
	return(0);
      }
      break;
      
    case spindump_quic_version_negotiation:
	type = spindump_quic_message_type_versionnegotiation;
	spindump_deepdebugf("QUIC message type = versionnegotiation");
	break;
	
    case spindump_quic_version_forcenegotiation:
      type = spindump_quic_message_type_initial;
      spindump_deepdebugf("QUIC message type = initial (via forced negotiation)");
      break;
      
    default:
      spindump_debugf("invalid version %lx", version);
      stats->unrecognisedQuicVersion++;
      return(0);
      
    }
  }
  
  //
  // Parse connection IDs
  // 
  
  if (longForm) {
    unsigned int destLen;
    unsigned int sourceLen;
    spindump_analyze_quic_parser_cidlengths(quic->u.longheader.qh_cidLengths,
					    &destLen,
					    &sourceLen);
    if (payload_len < 6 + destLen + sourceLen) {
      spindump_deepdebugf("not enough bytes in packet for dest & source CIDs");
      stats->notEnoughPacketForQuicHdr++;
      return(0);
    }
    *p_destinationCidLengthKnown = 1;
    p_destinationCid->len = destLen;
    memcpy(p_destinationCid->id,&quic->u.longheader.qh_cids[0],destLen);
    *p_sourceCidPresent = 1;
    p_sourceCid->len = sourceLen;
    memcpy(p_sourceCid->id,&quic->u.longheader.qh_cids[destLen],sourceLen);
    spindump_deepdebugf("destination CID = %s", spindump_connection_quicconnectionid_tostring(p_destinationCid));
    spindump_deepdebugf("source CID = %s", spindump_connection_quicconnectionid_tostring(p_sourceCid));
  } else {
    *p_destinationCidLengthKnown = 0;
    memcpy(p_destinationCid->id,&quic->u.shortheader.qh_destCid[0],spindump_min(18,payload_len-1));
    *p_sourceCidPresent = 0;
  }

  //
  // All seems ok.
  // 
  
  *p_longform = longForm;
  *p_version = version;
  *p_type = type;
  spindump_deepdebugf("successfully parsed the QUIC packet, long form = %u, version = %lx, type = %s",
		      longForm,
		      version,
		      spindump_analyze_quic_parser_typetostring(type));
  spindump_deepdebugf("destination cid = %s (length known %u)",
		      spindump_connection_quicconnectionid_tostring(p_destinationCid),
		      *p_destinationCidLengthKnown);
  spindump_deepdebugf("source cid = %s (present %u)",
		      spindump_connection_quicconnectionid_tostring(p_sourceCid),
		      *p_sourceCidPresent);
  return(1);
}

int
spindump_analyze_quic_parser_getspinbit(const unsigned char* payload,
					unsigned int payload_len,
					int longform,
					uint32_t version,
					int fromResponder,
					int* p_spin) {
  spindump_assert(payload != 0);
  if (payload_len < 1) return(0);
  uint8_t firstByte = payload[0];
  if (longform != 0) {
    spindump_deepdebugf("SPIN not parseable for the long version header");
    return(0);
  } else if (version == spindump_quic_version_rfc ||
	     version == spindump_quic_version_draft17) {
    int altSpin = ((firstByte & spindump_quic_byte_spin_draft16) != 0);
    *p_spin = ((firstByte & spindump_quic_byte_spin) != 0);
    spindump_deepdebugf("SPIN = %u (draft 17) from %s (as an aside, draft 16 spin would be %u)",
			*p_spin,
			fromResponder ? "responder" : "initiator",
			altSpin);
#ifdef SPINBITCONFUSION
    *p_spin = altSpin;
#endif
    return(1);
  } else if (version == spindump_quic_version_draft16) {
    *p_spin = ((firstByte & spindump_quic_byte_spin_draft16) != 0);
    spindump_deepdebugf("SPIN = %u (draft 16) from %s",
			*p_spin,
			fromResponder ? "responder" : "initiator");
    return(1);
  } else {
    spindump_deepdebugf("SPIN not parseable for this version (%lx)", version);
    return(0);
  }
}

const char*
spindump_analyze_quic_parser_versiontostring(uint32_t version) {
  switch (version) {
  case spindump_quic_version_rfc:
    return("rfc");
  case spindump_quic_version_draft17:
    return("v17");
  case spindump_quic_version_draft16:
    return("v16");
  case spindump_quic_version_draft15:
    return("v15");
  case spindump_quic_version_draft14:
    return("v14");
  case spindump_quic_version_draft13:
    return("v13");
  case spindump_quic_version_draft12:
    return("v12");
  case spindump_quic_version_draft11:
    return("v11");
  case spindump_quic_version_draft10:
    return("v10");
  case spindump_quic_version_draft09:
    return("v09");
  case spindump_quic_version_draft08:
    return("v08");
  case spindump_quic_version_draft07:
    return("v07");
  case spindump_quic_version_draft06:
    return("v06");
  case spindump_quic_version_draft05:
    return("v05");
  case spindump_quic_version_draft04:
    return("v04");
  case spindump_quic_version_draft03:
    return("v03");
  case spindump_quic_version_draft02:
    return("v02");
  case spindump_quic_version_draft01:
    return("v01");
  case spindump_quic_version_draft00:
    return("v00");
  case spindump_quic_version_negotiation:
    return("v tbd");
  default:
    return(0);
  }
}
