
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
//  AUTHOR: JARI ARKKO AND MARCUS IHLAR AND SZILVESZTER NADAS
//
// 

//
// Includes -----------------------------------------------------------------------------------
//

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "spindump_util.h"
#include "spindump_connections.h"
#include "spindump_analyze.h"
#include "spindump_analyze_quic.h"
#include "spindump_analyze_quic_parser.h"
#include "spindump_analyze_quic_parser_util.h"
#include "spindump_analyze_quic_parser_versions.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static int
spindump_analyze_quic_parse_parseheaderbyte(const unsigned char* payload,
                                            unsigned int payload_len,
                                            unsigned int remainingCapLen,
                                            uint8_t* headerByte,
                                            int* longForm,
                                            int* googleQuic,
                                            struct spindump_stats* stats);
static int
spindump_analyze_quic_parser_parseversionnumber(const unsigned char* payload,
                                                unsigned int payload_len,
                                                unsigned int remainingCaplen,
                                                uint8_t headerByte,
                                                uint32_t* p_version,
                                                uint32_t* p_originalVersion,
                                                struct spindump_quic* quic,
                                                struct spindump_stats* stats);
static int
spindump_analyze_quic_parser_parsemessagetype(uint8_t headerByte,
                                              uint32_t version,
                                              enum spindump_quic_message_type* p_type,
                                              uint8_t* p_messageType,
                                              int* p_0rttAttempted,
                                              struct spindump_stats* stats);
static int
spindump_analyze_quic_parser_parsemessagelength(const unsigned char* payload,
                                                unsigned int payload_len,
                                                unsigned int remainingCaplen,
                                                uint32_t version,
                                                enum spindump_quic_message_type type,
                                                unsigned int cidLengthsInBytes,
                                                unsigned int* p_messageLen,
                                                struct spindump_stats* stats);
static int
spindump_analyze_quic_parser_parsemessagelength_initial(const unsigned char* payload,
                                                        unsigned int payload_len,
                                                        unsigned int remainingCaplen,
                                                        unsigned int cidLengthsInBytes,
                                                        unsigned int* p_messageLen,
                                                        struct spindump_stats* stats);
static int
spindump_analyze_quic_parser_parsemessagelength_0rtt(const unsigned char* payload,
                                                     unsigned int payload_len,
                                                     unsigned int remainingCaplen,
                                                     unsigned int cidLengthsInBytes,
                                                     unsigned int* p_messageLen,
                                                     struct spindump_stats* stats);
static int
spindump_analyze_quic_parser_parsemessagelength_handshake(const unsigned char* payload,
                                                          unsigned int payload_len,
                                                          unsigned int remainingCaplen,
                                                          unsigned int cidLengthsInBytes,
                                                          unsigned int* p_messageLen,
                                                          struct spindump_stats* stats);
static int
spindump_analyze_quic_parser_parsemessagelength_retry(const unsigned char* payload,
                                                      unsigned int payload_len,
                                                      unsigned int remainingCaplen,
                                                      unsigned int cidLengthsInBytes,
                                                      unsigned int* p_messageLen,
                                                      struct spindump_stats* stats);
static int
spindump_analyze_quic_parser_parsemessagelength_versionnegotiation(const unsigned char* payload,
                                                                   unsigned int payload_len,
                                                                   unsigned int remainingCaplen,
                                                                   unsigned int* p_messageLen,
                                                                   struct spindump_stats* stats);
static int
spindump_analyze_quic_parser_seekquicpackets(const unsigned char* payload,
                                             unsigned int payload_len,
                                             unsigned int remainingCaplen,
                                             uint32_t version,
                                             int* p_0rttAttempted,
                                             struct spindump_stats* stats);
static int
spindump_analyze_quic_parser_parsecids(uint32_t version,
                                       const unsigned char* payload,
                                       unsigned int payload_len,
                                       unsigned int remainingCaplen,
                                       uint8_t cidLengths,
                                       int longForm,
                                       int* p_destinationCidLengthKnown,
                                       struct spindump_quic_connectionid* p_destinationCid,
                                       int* p_sourceCidPresent,
                                       struct spindump_quic_connectionid* p_sourceCid,
                                       struct spindump_stats* stats);

//
// Actual code --------------------------------------------------------------------------------
//

//
// Look to see if an UDP packet is a likely QUIC packet. This check is
// based on port numbers and the basics of packet format (length
// sufficient, first byte values reasonable, if there's a version
// field, the version looks reasonable, etc)
//

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
  
  const unsigned char* quic = payload;
  
  //
  // Parse initial byte
  // 
  
  if (payload_len < 1) return(0);
  uint8_t headerByte = quic[0];
  int longForm = 0;
  uint32_t version = spindump_quic_version_unknown;
  if ((headerByte & spindump_quic_byte_header_form_draft16) == spindump_quic_byte_form_long_draft16) {
    spindump_deepdebugf("recognised v16 long header");
    longForm = 1;
    if (payload_len < 6) {
      return(0);
    }
  } else if ((headerByte & spindump_quic_byte_header_form) == spindump_quic_byte_form_long) {
    spindump_deepdebugf("recognised v18 long header");
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
  
  version = ((((uint32_t)quic[1]) << 24) +
             (((uint32_t)quic[2]) << 16) +
             (((uint32_t)quic[3]) << 8) +
             (((uint32_t)quic[4]) << 0));
  spindump_deepdebugf("got the version %08x", version);
  if (spindump_quic_version_isforcenegot(version)) {
    version = spindump_quic_version_forcenegotiation;
  }

  //
  // Look up from the database of versions what this version is
  // and if it is recognised.
  //
  
  const struct spindump_quic_versiondescr* descriptor =
    spindump_analyze_quic_parser_version_findversion(version);
  if (version != spindump_quic_version_negotiation &&
      version != spindump_quic_version_forcenegotiation &&
      descriptor == 0) {
    return(0);
  }
  
  
  //
  // Look at the message type
  // 
  
  enum spindump_quic_message_type type;
  if (!spindump_analyze_quic_parser_version_getmessagetype(version,headerByte,&type)) {
    return(0);
  }

  //
  // If we got this far, the packet is likely a QUIC
  // long form packet from a recent draft version.
  // 

  spindump_deepdebugf("probably is a quic packet returns yes!");
  return(1);
}

//
// This is the main entry point to the QUIC parser. Spindump does not
// parse QUIC packets beyond what the header is, as it is not a party
// of the communication and does not have encryption keys and does not
// want to have them either :-) But the parser looks at the header and
// basic connection establishment messages conveyed by the header.
//
// The inputs are pointer to the beginning of the QUIC packet (= UDP
// payload), length of that payload, and how much of that has been
// captured in the part given to Spindump (as it may not use the full
// packets).
//
// This function returns 0 if the parsing fails, and then we can be
// sure that the packet is either invalid QUIC packet or from a
// version that this parser does not support.
//
// If the function returns 1, it will update the output parameters, by
// setting p_longForm to 1 if the packet is a QUIC long form packet,
// p_version to the QUIC version indicated in the packet, set the
// destination and source CIDs if they are known, and set the abstract
// QUIC message type to the message carried by this packet.
//

int
spindump_analyze_quic_parser_parse(const unsigned char* payload,
                                   unsigned int payload_len,
                                   unsigned int remainingCaplen,
                                   int* p_hasVersion,
                                   uint32_t* p_version,
                                   int* p_mayHaveSpinBit,
                                   int* p_0rttAttempted,
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
  spindump_assert(p_hasVersion != 0);
  spindump_assert(p_version != 0);
  spindump_assert(p_mayHaveSpinBit != 0);
  spindump_assert(p_0rttAttempted != 0);
  spindump_assert(p_destinationCid != 0);
  spindump_assert(p_sourceCid != 0);
  spindump_assert(stats != 0);
  
  //
  // Initialize output parameters
  // 
  
  *p_version = 0;
  *p_mayHaveSpinBit = 0;
  *p_0rttAttempted = 0;
  *p_destinationCidLengthKnown = 0;
  memset(p_destinationCid,0,sizeof(*p_destinationCid));
  *p_sourceCidPresent = 0;
  memset(p_sourceCid,0,sizeof(*p_sourceCid));
  *p_type = spindump_quic_message_type_other;
  
  //
  // Look at the packet, determine whether the format is long (initial) exchange
  // or short (data phase).
  // 
  
  if (payload_len < 1 || remainingCaplen < 1) {
    stats->notEnoughPacketForQuicHdr++;
    return(0);
  }
  
  uint32_t version = spindump_quic_version_unknown;
  uint32_t originalVersion = spindump_quic_version_unknown;
  
  //
  // Parse initial byte
  //
  
  uint8_t headerByte;
  int googleQuic;
  int longForm;
  
  if (!spindump_analyze_quic_parse_parseheaderbyte(payload,
                                                   payload_len,
                                                   remainingCaplen,
                                                   &headerByte,
                                                   &longForm,
                                                   &googleQuic,
                                                   stats)) {
    return(0);
  }
  
  if (googleQuic) {
    return(spindump_analyze_quic_parser_parse_google_quic(payload,
                                                          payload_len,
                                                          remainingCaplen,
                                                          p_hasVersion,
                                                          p_version,
                                                          p_mayHaveSpinBit,
                                                          p_0rttAttempted,
                                                          p_destinationCidLengthKnown,
                                                          p_destinationCid,
                                                          p_sourceCidPresent,
                                                          p_sourceCid,
                                                          p_type,
                                                          stats));
  }
  
  //
  // Parse version number
  // 
  
  struct spindump_quic quic;
  memset(&quic,0,sizeof(quic));
  if (longForm &&
      !spindump_analyze_quic_parser_parseversionnumber(payload,
                                                       payload_len,
                                                       remainingCaplen,
                                                       headerByte,
                                                       &version,
                                                       &originalVersion,
                                                       &quic,
                                                       stats)) {
    return(0);
  }
  
  //
  // Parse message type
  // 
  
  enum spindump_quic_message_type type = spindump_quic_message_type_data;
  uint8_t messageType;
  if (longForm &&
      !spindump_analyze_quic_parser_parsemessagetype(headerByte,
                                                     version,
                                                     &type,
                                                     &messageType,
                                                     p_0rttAttempted,
                                                     stats)) {
    return(0);
  }
  
  //
  // Parse connection IDs
  // 

  if (!spindump_analyze_quic_parser_parsecids(version,
                                              payload,
                                              payload_len,
                                              remainingCaplen,
                                              quic.u.longheader.qh_cidLengths,
                                              longForm,
                                              p_destinationCidLengthKnown,
                                              p_destinationCid,
                                              p_sourceCidPresent,
                                              p_sourceCid,
                                              stats)) {
    return(0);
  }
  
  //
  // If this QUIC packet was not a 0-RTT packet, check to see if
  // there's a 0-RTT packet later in the same IP packet
  //

  if (longForm && *p_0rttAttempted == 0) {
    int ans = spindump_analyze_quic_parser_seekquicpackets(payload,
                                                           payload_len,
                                                           remainingCaplen,
                                                           originalVersion,
                                                           p_0rttAttempted,
                                                           stats);
    if (!ans) {
      spindump_deepdebugf("note: could not seek QUIC packet to the end");
    }
  }
  
  //
  // All seems ok.
  // 
  
  *p_hasVersion = longForm;
  *p_mayHaveSpinBit = !longForm;
  spindump_deepdebugf("may have spin bit = %u (based on long form being %u)", *p_mayHaveSpinBit, longForm);
  spindump_deepdebugf("may have 0-rtt = %u (based on seeking QUIC packets)", *p_0rttAttempted);
  *p_version = originalVersion;
  *p_type = type;
  spindump_deepdebugf("successfully parsed the QUIC packet, long form = %u, version = %x, type = %s",
                      longForm,
                      version,
                      spindump_analyze_quic_parser_util_typetostring(type));
  char tempid[100];
  spindump_deepdebugf("destination cid = %s (length known %u)",
                      spindump_connection_quicconnectionid_tostring(p_destinationCid,tempid,sizeof(tempid)),
                      *p_destinationCidLengthKnown);
  spindump_deepdebugf("source cid = %s (present %u)",
                      spindump_connection_quicconnectionid_tostring(p_sourceCid,tempid,sizeof(tempid)),
                      *p_sourceCidPresent);
  return(1);
}

//
// Parser for Google's QUIC version (it is quite different from the ietf quic version)
// https://docs.google.com/document/d/1WJvyZflAO2pq77yOLbp9NsGjC1CHetAXV8I0fQe-B_U/edit
//
// Same input as spindump_analyze_quic_parser_parse.
// Simplified implementation, it might not work for all Google QUIC versions.
// tested with Google Chrome Version 73.0.3683.86 (Official Build) (64-bit)
//

int
spindump_analyze_quic_parser_parse_google_quic(const unsigned char* payload,
                                               unsigned int payload_len,
                                               unsigned int remainingCaplen,
                                               int* p_hasVersion,
                                               uint32_t* p_version,
                                               int* p_mayHaveSpinBit,
                                               int* p_0rttAttempted,
                                               int* p_destinationCidLengthKnown,
                                               struct spindump_quic_connectionid* p_destinationCid,
                                               int* p_sourceCidPresent,
                                               struct spindump_quic_connectionid* p_sourceCid,
                                               enum spindump_quic_message_type* p_type,
                                               struct spindump_stats* stats) {

  //
  // Assumes all inits in spindump_analyze_quic_parser_parse has
  // happened, ie setting *p_version, *p_mayHaveSpinBit,
  // *p_0rttAttempted, *p_destinationCidLengthKnown,
  // *p_destinationCid, *p_sourceCidPresent, *p_sourceCid, and
  // *p_type.
  //
  
  uint32_t version = spindump_quic_version_unknown;
  uint32_t googleVersion = spindump_quic_version_unknown;
  
  //
  // Parse initial byte
  //
  
  uint8_t publicFlags; //It is called publicFlags in GQUIC
  spindump_protocols_quic_header_decode(payload,&publicFlags);

  //
  // At this point we are "pretty sure" it is Google QUIC
  //
  
  int hasVersion = (publicFlags & 0x01) ? 1 : 0;

  //
  // Internal only to determine the position of version
  // will not return CID to avoid issues
  //
  
  int hasCid = (publicFlags & 0x08) ? 1 : 0;

  //
  // Indicates the presence of a 32 byte diversification nonce in the header.
  //

  int hasDiversificationNonce = (publicFlags & 0x04) ? 1 : 0;

  //
  // Parse version number first
  // Even though it is not the first header field, the rest might not be valid if the version is not
  //
  
  if (hasVersion) {
    unsigned int versionPosition = hasCid ? 9 : 1; //cid is 8 bytes
    if (payload_len < versionPosition + 4 || remainingCaplen < versionPosition + 4) { //version is 4 bytes ASCII
      stats->notEnoughPacketForQuicHdr++;
      return(0);
    }
    version =
      ((((uint32_t)payload[versionPosition+0]) << 24) +
       (((uint32_t)payload[versionPosition+1]) << 16) +
       (((uint32_t)payload[versionPosition+2]) << 8) +
       (((uint32_t)payload[versionPosition+3]) << 0));
    spindump_deepdebugf("QUIC Google QUIC packet version = %x", version);
    
    googleVersion=spindump_analyze_quic_parser_getgoogleversion(version);
    if (googleVersion == spindump_quic_version_unknown) {
      spindump_deepdebugf("QUIC Google version number !ok");
      version = spindump_quic_version_unknown;
      stats->unsupportedQuicVersion++;
      return(0);
    }
    spindump_deepdebugf("QUIC Google QUIC packet numeral version = %u", (unsigned int)googleVersion);
  }

  //
  // set p_sourceCid to Google CID
  //
  
  if (hasCid) {
    if (payload_len < 9 || remainingCaplen < 9) {
      stats->notEnoughPacketForQuicHdr++;
      return(0);
    }
    
    *p_sourceCidPresent = 1;
    p_sourceCid->len = 8;
    memcpy(p_sourceCid->id,&(payload[1]),p_sourceCid->len);
    
    //p_destinationCid set to 0 (1 byte long) only if source cid is present
    *p_destinationCidLengthKnown = 1;
    p_destinationCid->len = 1;
    p_destinationCid->id[0] = 0;
  }
  
  uint32_t sequenceNumber = 0;
  if ((publicFlags & 0x30) == 0 ) { //only determine SN for 1 byte encoding, we only check SN=1, which is anyway 1 byte (normally)
    unsigned int snPosition = 1;
    if (hasVersion) snPosition +=4;
    if (hasCid) snPosition+=8;
    if (hasDiversificationNonce) snPosition+=32;
    const unsigned int snLength=1; // (publicFlags & 0x30) == 0
    if (payload_len < snPosition + snLength || remainingCaplen < snPosition + snLength) {
      stats->notEnoughPacketForQuicHdr++;
      return(0);
    }

    //
    // After Q039, Integers and floating numbers are written in big
    // endian (before little endian) as this is a single byte that
    // does not matter however, has to be updated if multi-byte SNs
    // are to be supported
    //
    
    sequenceNumber = ((uint32_t)payload[snPosition]);
  }
  
  enum spindump_quic_message_type type = spindump_quic_message_type_data;

  //
  // A simple hack: spindump_quic_message_type_initial if SN==1
  //
  
  if (sequenceNumber == 1) {
    type = spindump_quic_message_type_initial;
    spindump_deepdebugf("QUIC Google QUIC packet with SN=1, treated as initial message");
  }
  
  //
  // All seems ok.
  //
  
  *p_hasVersion = hasVersion;
  *p_mayHaveSpinBit = 0;
  *p_version = version;
  *p_type = type;
  spindump_deepdebugf("successfully parsed the Google QUIC packet, version = %x, sn = %x, type = %s",
                      version,
                      sequenceNumber,
                      spindump_analyze_quic_parser_util_typetostring(type));
  return(1);
}

//
// Helper function to parse through a sequence coalesced QUIC messages
// in a single UDP/IP packet. We're doing this primarily to scan for
// 0-RTT messages.
//

static int
spindump_analyze_quic_parser_seekquicpackets(const unsigned char* payload,
                                             unsigned int payload_len,
                                             unsigned int remainingCaplen,
                                             uint32_t version,
                                             int* p_0rttAttempted,
                                             struct spindump_stats* stats) {
  
  //
  // Make some checks
  // 
  
  spindump_assert(payload != 0);
  spindump_assert(p_0rttAttempted != 0);
  spindump_assert(stats != 0);
  
  //
  // Initialize output parameters
  // 
  
  *p_0rttAttempted = 0;

  while (1) {
    
    //
    // Look at the packet, determine whether the format is long (initial) exchange
    // or short (data phase).
    // 
    
    if (payload_len < 1 || remainingCaplen < 1) {
      stats->notEnoughPacketForQuicHdr++;
      return(0);
    }
    
    //
    // Parse initial byte
    // 
    
    uint8_t headerByte;
    int longForm;
    int googleQuic;
    if (!spindump_analyze_quic_parse_parseheaderbyte(payload,
                                                     payload_len,
                                                     remainingCaplen,
                                                     &headerByte,
                                                     &longForm,
                                                     &googleQuic,
                                                     stats)) {
      return(0);
    }

    //
    // Quit if Google QUIC
    //
    
    if (googleQuic) {
      stats->notAbleToHandleGoogleQuicCoalescing++;
      return(0);
    }

    //
    // Quit if short form
    //

    if (!longForm) {
      return(1);
    }
    
    //
    // Parse version number
    //
    
    struct spindump_quic quic;
    uint32_t originalVersion = spindump_quic_version_unknown;
    if (!spindump_analyze_quic_parser_parseversionnumber(payload,
                                                         payload_len,
                                                         remainingCaplen,
                                                         headerByte,
                                                         &version,
                                                         &originalVersion,
                                                         &quic,
                                                         stats)) {
      return(0);
    }
    
    //
    // Parse message type
    // 
    
    enum spindump_quic_message_type type = spindump_quic_message_type_data;
    uint8_t messageType;
    int here0rttAttempted = 0;
    
    if (longForm &&
        !spindump_analyze_quic_parser_parsemessagetype(headerByte,
                                                       version,
                                                       &type,
                                                       &messageType,
                                                       &here0rttAttempted,
                                                       stats)) {
      return(0);
    }
    
    if (here0rttAttempted) {
      spindump_deepdebugf("saw a 0-RTT attempt in seeked header");
      *p_0rttAttempted = 1;
    }
    
    //
    // Parse connection IDs
    // 
    
    int destinationCidLengthKnown;
    struct spindump_quic_connectionid destinationCid;
    int sourceCidPresent;
    struct spindump_quic_connectionid sourceCid;
    if (!spindump_analyze_quic_parser_parsecids(version,
                                                payload,
                                                payload_len,
                                                remainingCaplen,
                                                quic.u.longheader.qh_cidLengths,
                                                longForm,
                                                &destinationCidLengthKnown,
                                                &destinationCid,
                                                &sourceCidPresent,
                                                &sourceCid,
                                                stats)) {
      return(0);
    }
    
    //
    // Parse the rest of this message and find out how long the message is
    //
    
    unsigned int messageLen;
    unsigned int cidLengthsInBytes = 0;
    if (destinationCidLengthKnown) cidLengthsInBytes += destinationCid.len;
    if (sourceCidPresent) cidLengthsInBytes += sourceCid.len;
    
    if (!spindump_analyze_quic_parser_parsemessagelength(payload,
                                                         payload_len,
                                                         remainingCaplen,
                                                         version,
                                                         type,
                                                         cidLengthsInBytes,
                                                         &messageLen,
                                                         stats)) {
      return(0);
    }
    
    //
    // See if we have enough packet left to look at the next message in
    // this UDP/IP packet.
    //
    
    spindump_deepdeepdebugf("seeking QUIC packets: message length %u out of %u/%u",
                            messageLen, payload_len, remainingCaplen);
    if (messageLen == payload_len) {
      spindump_deepdeepdebugf("seeking QUIC packets: just one");
      break;
    } else if (messageLen > payload_len) {
      spindump_deepdeepdebugf("seeking QUIC packets: payload too short for this packet");
      return(0);
    } else if (messageLen > remainingCaplen) {
      spindump_deepdeepdebugf("seeking QUIC packets: capture length too short for this packet");
      return(0);
    } else {
      spindump_deepdeepdebugf("seeking QUIC packets: continuing");
      payload += messageLen;
      payload_len -= messageLen;
      remainingCaplen -= messageLen;
      continue;
    }
    
  }
  
  //
  // Done, end
  //
  
  return(1);
}

//
// Helper function to parse an entire message and determine its length
//

static int
spindump_analyze_quic_parser_parsemessagelength(const unsigned char* payload,
                                                unsigned int payload_len,
                                                unsigned int remainingCaplen,
                                                uint32_t version,
                                                enum spindump_quic_message_type type,
                                                unsigned int cidLengthsInBytes,
                                                unsigned int* p_messageLen,
                                                struct spindump_stats* stats) {

  //
  // Sanity checks and debugs
  //
  
  spindump_assert(payload != 0);
  spindump_assert(p_messageLen != 0);
  spindump_assert(stats != 0);
  spindump_deepdeepdebugf("seeking QUIC packets: parsemessagelength with cidl = %u", cidLengthsInBytes);
  
  //
  // Initialize outputs
  //
  
  *p_messageLen = 0;
  
  //
  // Switch based on version and message type and then find out the lengths
  //

  return(spindump_analyze_quic_parser_version_parselengths(version,
                                                           payload,
                                                           payload_len,
                                                           remainingCaplen,
                                                           type,
                                                           cidLengthsInBytes,
                                                           p_messageLen,
                                                           stats));
}

int
spindump_analyze_quic_parser_parsemessagelength_pertype(const unsigned char* payload,
                                                        unsigned int payload_len,
                                                        unsigned int remainingCaplen,
                                                        enum spindump_quic_message_type type,
                                                        unsigned int cidLengthsInBytes,
                                                        unsigned int* p_messageLen,
                                                        struct spindump_stats* stats) {
  switch (type) {
  case spindump_quic_message_type_initial:
    return(spindump_analyze_quic_parser_parsemessagelength_initial(payload,
                                                                   payload_len,
                                                                   remainingCaplen,
                                                                   cidLengthsInBytes,
                                                                   p_messageLen,
                                                                   stats));
  case spindump_quic_message_type_versionnegotiation:
    return(spindump_analyze_quic_parser_parsemessagelength_versionnegotiation(payload,
                                                                              payload_len,
                                                                              remainingCaplen,
                                                                              p_messageLen,
                                                                              stats));
  case spindump_quic_message_type_0rtt:
    return(spindump_analyze_quic_parser_parsemessagelength_0rtt(payload,
                                                                payload_len,
                                                                remainingCaplen,
                                                                cidLengthsInBytes,
                                                                p_messageLen,
                                                                stats));
  case spindump_quic_message_type_handshake:
    return(spindump_analyze_quic_parser_parsemessagelength_handshake(payload,
                                                                     payload_len,
                                                                     remainingCaplen,
                                                                     cidLengthsInBytes,
                                                                     p_messageLen,
                                                                     stats));
  case spindump_quic_message_type_retry:
    return(spindump_analyze_quic_parser_parsemessagelength_retry(payload,
                                                                 payload_len,
                                                                 remainingCaplen,
                                                                 cidLengthsInBytes,
                                                                 p_messageLen,
                                                                 stats));
  case spindump_quic_message_type_other:
  case spindump_quic_message_type_data:
    spindump_deepdebugf("message type %u not supported for seeking packets", type);
    return(0);
  default:
    spindump_errorf("invalid message type");
    return(0);
  }
}

//
// Helper function to parse an entire message and determine its length
//

static int
spindump_analyze_quic_parser_parsemessagelength_initial(const unsigned char* payload,
                                                        unsigned int payload_len,
                                                        unsigned int remainingCaplen,
                                                        unsigned int cidLengthsInBytes,
                                                        unsigned int* p_messageLen,
                                                        struct spindump_stats* stats) {

  //
  // Sanity checks and debugs
  //
  
  spindump_assert(payload != 0);
  spindump_assert(p_messageLen != 0);
  spindump_assert(stats != 0);
  spindump_deepdeepdebugf("seeking QUIC packets: spindump_analyze_quic_parser_parsemessagelength_initial cidl = %u",
                          cidLengthsInBytes);
  
  //
  // From the specification:
  //
  //  +-+-+-+-+-+-+-+-+
  //  |1|1| 0 |R R|P P|
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                         Version (32)                          |
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |DCIL(4)|SCIL(4)|
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |               Destination Connection ID (0/32..144)         ...
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                 Source Connection ID (0/32..144)            ...
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                         Token Length (i)                    ...
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                            Token (*)                        ...
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                           Length (i)                        ...
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                    Packet Number (8/16/24/32)               ...
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                          Payload (*)                        ...
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //
  //                   Figure 11: Initial Packet
  //

  //
  // Parse the token length and token
  //
  
  unsigned int tokenLengthPosition = 1 + 4 + 1 + cidLengthsInBytes;
  if (tokenLengthPosition >= payload_len || tokenLengthPosition >= remainingCaplen) {
    spindump_deepdeepdebugf("seeking QUIC packets: token not within packet");
    stats->notEnoughPacketForQuicHdrToken++;
    return(0);
  }
  unsigned int intLength;
  uint64_t tokenLength;
  if (!spindump_analyze_quic_parser_util_parseint(payload + tokenLengthPosition,
                                                  payload_len - tokenLengthPosition,
                                                  remainingCaplen - tokenLengthPosition,
                                                  &intLength,
                                                  &tokenLength)) {
    spindump_deepdeepdebugf("seeking QUIC packets: token not within packet");
    stats->notEnoughPacketForQuicHdrToken++;
    return(0);
  }
  spindump_deepdeepdebugf("seeking QUIC packets: token length %u %llu", intLength, tokenLength);
  if (tokenLength > UINT_MAX) {
    spindump_deepdeepdebugf("seeking QUIC packets: token length insane");
    stats->notEnoughPacketForQuicHdrToken++;
    return(0);
  }
  unsigned int positionAfterToken =
    tokenLengthPosition +
    intLength +
    ((unsigned int)tokenLength);
  if (positionAfterToken >= payload_len || positionAfterToken >= remainingCaplen) {
    spindump_deepdeepdebugf("seeking QUIC packets: no packet left after token");
    stats->notEnoughPacketForQuicHdrToken++;
    return(0);
  }
  
  //
  // Parse the length field
  //

  uint64_t length;
  if (!spindump_analyze_quic_parser_util_parseint(payload + positionAfterToken,
                                                  payload_len - positionAfterToken,
                                                  remainingCaplen - positionAfterToken,
                                                  &intLength,
                                                  &length)) {
    spindump_deepdeepdebugf("seeking QUIC packets: length not within packet");
    stats->notEnoughPacketForQuicHdrLength++;
    return(0);
  }
  spindump_deepdeepdebugf("seeking QUIC packets: packet length %u %llu", intLength, length);
  if (length > UINT_MAX) {
    spindump_deepdeepdebugf("seeking QUIC packets: packet length insane");
    stats->notEnoughPacketForQuicHdrLength++;
    return(0);
  }
  unsigned int positionAfterLength =
    positionAfterToken +
    intLength +
    ((unsigned int)length);
  if (positionAfterLength > payload_len || positionAfterLength > remainingCaplen) {
    spindump_deepdeepdebugf("seeking QUIC packets: no packet left after length");
    stats->notEnoughPacketForQuicHdrLength++;
    return(0);
  }
  
  //
  // Success
  //

  *p_messageLen = positionAfterLength;
  spindump_deepdeepdebugf("seeking QUIC packets: success in parsing one message, length = %u",
                          *p_messageLen);
  return(1);
}

//
// Helper function to parse an entire message and determine its length
//

static int
spindump_analyze_quic_parser_parsemessagelength_0rtt(const unsigned char* payload,
                                                     unsigned int payload_len,
                                                     unsigned int remainingCaplen,
                                                     unsigned int cidLengthsInBytes,
                                                     unsigned int* p_messageLen,
                                                     struct spindump_stats* stats) {

  //
  // Sanity checks and debugs
  //
  
  spindump_assert(payload != 0);
  spindump_assert(p_messageLen != 0);
  spindump_assert(stats != 0);
  spindump_deepdeepdebugf("seeking QUIC packets: spindump_analyze_quic_parser_parsemessagelength_0rtt cidl = %u",
                          cidLengthsInBytes);
  
  //
  // From the specification:
  //
  //  +-+-+-+-+-+-+-+-+
  //  |1|1| 0 |R R|P P|
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                         Version (32)                          |
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |DCIL(4)|SCIL(4)|
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |               Destination Connection ID (0/32..144)         ...
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                 Source Connection ID (0/32..144)            ...
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                           Length (i)                        ...
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                    Packet Number (8/16/24/32)               ...
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                          Payload (*)                        ...
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //
  //                            0-RTT Packet
  //
  
  //
  // Parse the length field
  //

  unsigned int lengthPosition = 1 + 4 + 1 + cidLengthsInBytes;
  if (payload_len <= lengthPosition || remainingCaplen <= lengthPosition) {
    spindump_deepdeepdebugf("seeking QUIC packets: not enough for packet length in 0-rtt packet");
    stats->notEnoughPacketForQuicHdrLength++;
    return(0);
  }
  
  unsigned int intLength;
  uint64_t length;
  if (!spindump_analyze_quic_parser_util_parseint(payload + lengthPosition,
                                                  payload_len - lengthPosition,
                                                  remainingCaplen - lengthPosition,
                                                  &intLength,
                                                  &length)) {
    spindump_deepdeepdebugf("seeking QUIC packets: length not within packet in 0-rtt packet");
    stats->notEnoughPacketForQuicHdrLength++;
    return(0);
  }
  spindump_deepdeepdebugf("seeking QUIC packets: packet length %u %llu", intLength, length);
  if (length > UINT_MAX) {
    spindump_deepdeepdebugf("seeking QUIC packets: packet length insane in 0-rtt packet");
    stats->notEnoughPacketForQuicHdrLength++;
    return(0);
  }
  unsigned int positionAfterLength =
    lengthPosition +
    intLength +
    ((unsigned int)length);
  if (positionAfterLength > payload_len || positionAfterLength > remainingCaplen) {
    spindump_deepdeepdebugf("seeking QUIC packets: no packet left after length in 0-rtt packet");
    stats->notEnoughPacketForQuicHdrLength++;
    return(0);
  }
  
  //
  // Success
  //
  
  *p_messageLen = positionAfterLength;
  spindump_deepdeepdebugf("seeking QUIC packets: success in parsing one 0-rtt message, length = %u",
                          *p_messageLen);
  return(1);
}

//
// Helper function to parse an entire message and determine its length
//

static int
spindump_analyze_quic_parser_parsemessagelength_handshake(const unsigned char* payload,
                                                          unsigned int payload_len,
                                                          unsigned int remainingCaplen,
                                                          unsigned int cidLengthsInBytes,
                                                          unsigned int* p_messageLen,
                                                          struct spindump_stats* stats) {

  //
  // Sanity checks and debugs
  //
  
  spindump_assert(payload != 0);
  spindump_assert(p_messageLen != 0);
  spindump_assert(stats != 0);
  spindump_deepdeepdebugf("seeking QUIC packets: spindump_analyze_quic_parser_parsemessagelength_handshake cidl = %u",
                          cidLengthsInBytes);
  
  //
  // From the specification:
  //
  //  +-+-+-+-+-+-+-+-+
  //  |1|1| 2 |R R|P P|
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                         Version (32)                          |
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |DCIL(4)|SCIL(4)|
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |               Destination Connection ID (0/32..144)         ...
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                 Source Connection ID (0/32..144)            ...
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                           Length (i)                        ...
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                    Packet Number (8/16/24/32)               ...
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                          Payload (*)                        ...
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //
  //                Figure 12: Handshake Protected Packet
  //
  
  //
  // Parse the length field
  //
  
  unsigned int lengthPosition = 1 + 4 + 1 + cidLengthsInBytes;
  if (payload_len <= lengthPosition || remainingCaplen <= lengthPosition) {
    spindump_deepdeepdebugf("seeking QUIC packets: not enough for packet length in handshake packet");
    stats->notEnoughPacketForQuicHdrLength++;
    return(0);
  }
  
  unsigned int intLength;
  uint64_t length;
  if (!spindump_analyze_quic_parser_util_parseint(payload + lengthPosition,
                                                  payload_len - lengthPosition,
                                                  remainingCaplen - lengthPosition,
                                                  &intLength,
                                                  &length)) {
    spindump_deepdeepdebugf("seeking QUIC packets: length not within packet in handshake packet");
    stats->notEnoughPacketForQuicHdrLength++;
    return(0);
  }
  spindump_deepdeepdebugf("seeking QUIC packets: packet length %u %llu", intLength, length);
  if (length > UINT_MAX) {
    spindump_deepdeepdebugf("seeking QUIC packets: packet length insane in handshake packet");
    stats->notEnoughPacketForQuicHdrLength++;
    return(0);
  }
  unsigned int positionAfterLength =
    lengthPosition +
    intLength +
    ((unsigned int)length);
  if (positionAfterLength > payload_len || positionAfterLength > remainingCaplen) {
    spindump_deepdeepdebugf("seeking QUIC packets: no packet left after length in handshake packet");
    stats->notEnoughPacketForQuicHdrLength++;
    return(0);
  }
  
  //
  // Success
  //
  
  *p_messageLen = positionAfterLength;
  spindump_deepdeepdebugf("seeking QUIC packets: success in parsing one handshake message, length = %u",
                          *p_messageLen);
  return(1);
}

//
// Helper function to parse an entire message and determine its length
//

static int
spindump_analyze_quic_parser_parsemessagelength_retry(const unsigned char* payload,
                                                      unsigned int payload_len,
                                                      unsigned int remainingCaplen,
                                                      unsigned int cidLengthsInBytes,
                                                      unsigned int* p_messageLen,
                                                      struct spindump_stats* stats) {
  
  //
  // Sanity checks and debugs
  //
  
  spindump_assert(payload != 0);
  spindump_assert(p_messageLen != 0);
  spindump_assert(stats != 0);
  spindump_deepdeepdebugf("seeking QUIC packets: spindump_analyze_quic_parser_parsemessagelength_retry cidl = %u",
                          cidLengthsInBytes);
  
  //
  // From the specification:
  //
  //   0                   1                   2                   3
  //   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  //  +-+-+-+-+-+-+-+-+
  //  |1|1| 3 | ODCIL |
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                         Version (32)                          |
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |DCIL(4)|SCIL(4)|
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |               Destination Connection ID (0/32..144)         ...
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                 Source Connection ID (0/32..144)            ...
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |          Original Destination Connection ID (0/32..144)     ...
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                        Retry Token (*)                      ...
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //
  //                        Figure 13: Retry Packet
  //
  
  //
  // Parse the length field
  //
  
  unsigned int lengthPosition = 1 + 4 + 1 + cidLengthsInBytes;
  if (payload_len <= lengthPosition || remainingCaplen <= lengthPosition) {
    spindump_deepdeepdebugf("seeking QUIC packets: not enough for packet length in handshake packet");
    stats->notEnoughPacketForQuicHdrLength++;
    return(0);
  }
  
  unsigned int intLength;
  uint64_t length;
  if (!spindump_analyze_quic_parser_util_parseint(payload + lengthPosition,
                                                  payload_len - lengthPosition,
                                                  remainingCaplen - lengthPosition,
                                                  &intLength,
                                                  &length)) {
    spindump_deepdeepdebugf("seeking QUIC packets: length not within packet in handshake packet");
    stats->notEnoughPacketForQuicHdrLength++;
    return(0);
  }
  spindump_deepdeepdebugf("seeking QUIC packets: packet length %u %llu", intLength, length);
  if (length > UINT_MAX) {
    spindump_deepdeepdebugf("seeking QUIC packets: packet length insane in handshake packet");
    stats->notEnoughPacketForQuicHdrLength++;
    return(0);
  }
  unsigned int positionAfterLength =
    lengthPosition +
    intLength +
    ((unsigned int)length);
  if (positionAfterLength > payload_len || positionAfterLength > remainingCaplen) {
    spindump_deepdeepdebugf("seeking QUIC packets: no packet left after length in handshake packet");
    stats->notEnoughPacketForQuicHdrLength++;
    return(0);
  }
  
  //
  // Success
  //
  
  *p_messageLen = positionAfterLength;
  spindump_deepdeepdebugf("seeking QUIC packets: success in parsing one handshake message, length = %u",
                          *p_messageLen);
  return(1);
}

//
// Helper function to parse an entire message and determine its length
//

static int
spindump_analyze_quic_parser_parsemessagelength_versionnegotiation(const unsigned char* payload,
                                                                   unsigned int payload_len,
                                                                   unsigned int remainingCaplen,
                                                                   unsigned int* p_messageLen,
                                                                   struct spindump_stats* stats) {
  
  //
  // Sanity checks and debugs
  //
  
  spindump_assert(payload != 0);
  spindump_assert(p_messageLen != 0);
  spindump_assert(stats != 0);
  spindump_deepdeepdebugf("seeking QUIC packets: spindump_analyze_quic_parser_parsemessagelength_versionnegotiation");
  
  //
  // From the specification (up until -21):
  //
  //  +-+-+-+-+-+-+-+-+
  //  |1|1| 0 |R R|P P|
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                         Version (32)                          |
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |DCIL(4)|SCIL(4)|
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |               Destination Connection ID (0/32..144)         ...
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                 Source Connection ID (0/32..144)            ...
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                    Supported Version 1 (32)                 ...
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                   [Supported Version 2 (32)]                ...
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //                              ...
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                   [Supported Version N (32)]                ...
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //
  //              Figure 10: Version Negotiation Packet
  //
  // and from -22 onwards:
  //
  //    0                   1                   2                   3
  //    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  //   +-+-+-+-+-+-+-+-+
  //   |1|  Unused (7) |
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                          Version (32)                         |
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   | DCID Len (8)  |
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |               Destination Connection ID (0..2040)           ...
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   | SCID Len (8)  |
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                 Source Connection ID (0..2040)              ...
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                    Supported Version 1 (32)                 ...
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                   [Supported Version 2 (32)]                ...
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //                                  ...
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //   |                   [Supported Version N (32)]                ...
  //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //
  //                   Figure 10: Version Negotiation Packet
  //  

  if (payload_len > remainingCaplen) {
    spindump_deepdeepdebugf("seeking QUIC packets: no packet left after length");
    stats->notEnoughPacketForQuicHdrLength++;
    return(0);
  }
  
  //
  // Success -- this packet always consumes everything until the end of the UDP packet
  //
  
  *p_messageLen = payload_len;
  spindump_deepdeepdebugf("seeking QUIC packets: success in parsing one message, length = %u",
                          *p_messageLen);
  return(1);
}

//
// Helper function to parse the first byte of a QUIC message.
//

static int
spindump_analyze_quic_parse_parseheaderbyte(const unsigned char* payload,
                                            unsigned int payload_len,
                                            unsigned int remainingCapLen,
                                            uint8_t* headerByte,
                                            int* longForm,
                                            int* googleQuic,
                                            struct spindump_stats* stats) {

  //
  // Initialize output parameters
  //
  
  *longForm = 0;
  *googleQuic = 0;
  
  //
  // Parse first byte
  //
  
  spindump_protocols_quic_header_decode(payload,headerByte);
  
  //
  // Check for Google QUIC version
  //
  
  if ((*headerByte & spindump_quic_byte_header_alwaysunset) == 0) {
    
    //
    // This is Google QUIC, likely Q043 or below Google will use the
    // ietf version from Q044
    //
    
    spindump_deepdebugf("QUIC Google QUIC packet first byte = %02x (payload %02x)", *headerByte, payload[0]);
    *googleQuic = 1;
    return(1);
  }

  //
  // Check for long or short form header
  //
  
  if ((*headerByte & spindump_quic_byte_header_form_draft16) == spindump_quic_byte_form_long_draft16) {
    *longForm = 1;
    spindump_deepdebugf("QUIC long form packet first byte = %02x (payload %02x)", *headerByte, payload[0]);
  } else {
    spindump_deepdebugf("QUIC short form packet first byte = %02x (payload %02x)", *headerByte, payload[0]);
  }

  //
  // Done
  //
  
  return(1);
}

//
// Helper function to parse a version number in a QUIC message.
//

static int
spindump_analyze_quic_parser_parseversionnumber(const unsigned char* payload,
                                                unsigned int payload_len,
                                                unsigned int remainingCaplen,
                                                uint8_t headerByte,
                                                uint32_t* p_version,
                                                uint32_t* p_originalVersion,
                                                struct spindump_quic* quic,
                                                struct spindump_stats* stats) {
  quic->u.shortheader.qh_byte = headerByte;
  if (payload_len < 6 || remainingCaplen < 6) {
    stats->notEnoughPacketForQuicHdr++;
    return(0);
  }
  spindump_protocols_quic_longheader_decode(payload,quic);
  *p_version =
    *p_originalVersion = ((((uint32_t)quic->u.longheader.qh_version[0]) << 24) +
                          (((uint32_t)quic->u.longheader.qh_version[1]) << 16) +
                          (((uint32_t)quic->u.longheader.qh_version[2]) << 8) +
                          (((uint32_t)quic->u.longheader.qh_version[3]) << 0));
  spindump_deepdebugf("QUIC long form packet version = %x", *p_version);
  if (spindump_quic_version_isforcenegot(*p_version)) {
    *p_version = spindump_quic_version_forcenegotiation;
  }
  
  //
  // Look up from the database of versions what this version is
  // and if it is recognised.
  //
  
  if (*p_version == spindump_quic_version_negotiation) {
    spindump_deepdebugf("QUIC version negotiation");
    *p_version = spindump_quic_version_negotiation;
  } else if (*p_version == spindump_quic_version_forcenegotiation) {
    spindump_deepdebugf("QUIC forcing version negotiation");
    *p_version = spindump_quic_version_negotiation;
  } else {
    const struct spindump_quic_versiondescr* descriptor =
    spindump_analyze_quic_parser_version_findversion(*p_version);
    if (descriptor == 0) {
      spindump_deepdebugf("QUIC version just not recognised !ok (ver = %x)", *p_version);
      *p_version = spindump_quic_version_unknown;
      stats->unrecognisedQuicVersion++;
      return(0);
    } else if (!descriptor->supported) {
      *p_version = spindump_quic_version_unknown;
      stats->unsupportedQuicVersion++;
      return(0);
    }
  }
  
  //
  // Parsed ok
  //
  
  return(1);
}


//
// Helper function to parse the message type in a QUIC message.
//

static int
spindump_analyze_quic_parser_parsemessagetype(uint8_t headerByte,
                                              uint32_t version,
                                              enum spindump_quic_message_type* p_type,
                                              uint8_t* p_messageType,
                                              int* p_0rttAttempted,
                                              struct spindump_stats* stats) {

  //
  // Sanity checks
  //

  spindump_assert(p_type != 0);
  spindump_assert(p_messageType != 0);
  spindump_assert(p_0rttAttempted != 0);
  spindump_assert(stats != 0);

  //
  // Initialize
  //

  *p_type = spindump_quic_message_type_other;
  *p_messageType = 0;
  *p_0rttAttempted = 0;

  //
  // Switch the decoding based on what version we are using
  //

  if (version == spindump_quic_version_negotiation) {
    
    *p_type = spindump_quic_message_type_versionnegotiation;
    spindump_deepdebugf("QUIC message type = versionnegotiation");
    
  } else if (version == spindump_quic_version_forcenegotiation) {
    
    *p_type = spindump_quic_message_type_initial;
    spindump_deepdebugf("QUIC message type = initial (via forced negotiation)");

  } else {
    
    //
    // All other versions. First look up from the database of versions
    // what this version is and if it is recognised.
    //

    if (spindump_analyze_quic_parser_version_getmessagetype(version,headerByte,p_type)) {
      if (*p_type == spindump_quic_message_type_0rtt) {
        *p_0rttAttempted = 1;
      }
    } else {
      stats->unrecognisedQuicType++;
      return(0);
    }
  }
  
  //
  // Ok
  //
  
  return(1);
}

//
// Helper function to parse one or two CIDs in a QUIC message.
//

static int
spindump_analyze_quic_parser_parsecids(uint32_t version,
                                       const unsigned char* payload,
                                       unsigned int payload_len,
                                       unsigned int remainingCaplen,
                                       uint8_t cidLengths,
                                       int longForm,
                                       int* p_destinationCidLengthKnown,
                                       struct spindump_quic_connectionid* p_destinationCid,
                                       int* p_sourceCidPresent,
                                       struct spindump_quic_connectionid* p_sourceCid,
                                       struct spindump_stats* stats) {
  if (longForm) {
    
    unsigned int destLen;
    unsigned int sourceLen;
    int longCids = spindump_analyze_quic_parser_version_useslongcidlength(version);
    
    unsigned int packetHeaderSoFar =
      1 +                   // for first byte
      4;                    // for version number
    unsigned int packetHeaderSoFarWithFirstCIDLength =
      packetHeaderSoFar +   // for first byte and version number
      1;                    // for CID lengths or the first CID length
    unsigned int packetHeaderSoFarWithBothCIDLengths =
      packetHeaderSoFarWithFirstCIDLength +   // for first byte and version number and first CID length
      (longCids ? 1 : 0);                     // for CID lengths

    int ans;
    if (longCids) {
      ans = spindump_analyze_quic_parser_util_cidlengths_long(cidLengths,
                                                              payload + packetHeaderSoFarWithFirstCIDLength,
                                                              (payload_len >= packetHeaderSoFarWithFirstCIDLength ?
                                                               payload_len - packetHeaderSoFarWithFirstCIDLength :
                                                               0),
                                                              (remainingCaplen >= packetHeaderSoFarWithFirstCIDLength ?
                                                               remainingCaplen - packetHeaderSoFarWithFirstCIDLength :
                                                               0),
                                                              &destLen,
                                                              &sourceLen);
    } else {
      ans = spindump_analyze_quic_parser_util_cidlengths_short(cidLengths,
                                                               &destLen,
                                                               &sourceLen);
    }
    if (!ans ||
        payload_len < packetHeaderSoFarWithBothCIDLengths + destLen + sourceLen ||
        remainingCaplen < packetHeaderSoFarWithBothCIDLengths + destLen + sourceLen) {
      spindump_deepdebugf("not enough bytes in packet for dest & source CIDs");
      stats->notEnoughPacketForQuicHdr++;
      return(0);
    }
    *p_destinationCidLengthKnown = 1;
    p_destinationCid->len = destLen;
    memcpy(p_destinationCid->id,payload + spindump_quic_longheader_length,destLen);
    *p_sourceCidPresent = 1;
    p_sourceCid->len = sourceLen;
    memcpy(p_sourceCid->id,&((payload + spindump_quic_longheader_length)[destLen]),sourceLen);
    char tempid[100];
    spindump_deepdebugf("destination CID = %s", spindump_connection_quicconnectionid_tostring(p_destinationCid,tempid,sizeof(tempid)));
    spindump_deepdebugf("source CID = %s", spindump_connection_quicconnectionid_tostring(p_sourceCid,tempid,sizeof(tempid)));
  } else {
    *p_destinationCidLengthKnown = 0;
    memcpy(p_destinationCid->id,payload + spindump_quic_header_length,spindump_min(18,payload_len-1));
    *p_sourceCidPresent = 0;
  }

  //
  // Done
  //
  
  return(1);
}

//
// This is the third entry point to the QUIC parser. If a packet has
// been determined to be a QUIC packet, this function determines its
// Spin bit value. If the function succeeds in retrieving a Spin bit
// value, it returns 1, otherwise 0.
//
// The output parameter is p_spin, which will hold the value of the
// Spin bit (either 0 or 1).
//

int
spindump_analyze_quic_parser_getspinbit(const unsigned char* payload,
                                        unsigned int payload_len,
                                        int mayHaveSpinBit,
                                        uint32_t version,
                                        int fromResponder,
                                        int* p_spin) {
  spindump_assert(payload != 0);
  spindump_assert(spindump_isbool(mayHaveSpinBit));
  
  if (payload_len < 1) return(0);
  uint8_t firstByte = payload[0];
  
  if (mayHaveSpinBit == 0) {
    
    spindump_deepdebugf("SPIN not parseable for the long version header");
    return(0);
    
  } else {

    if (spindump_analyze_quic_parser_version_getspinbitvalue(version,firstByte,p_spin)) {
      spindump_deepdebugf("SPIN = %u (v.%08x) from %s",
                          *p_spin, version,
                          fromResponder ? "responder" : "initiator");
      return(1);
    } else {
      spindump_deepdebugf("SPIN not parseable for this version (%x)", version);
      return(0);
    }

  }
  
}

//
// This is the xth entry point to the QUIC parser.
// this determines the extra measurements present in the packet
// typically using the reserved bits.
// If the function succeeds in retrieving any extra measurement
// value, it returns 1, otherwise 0.
//
// The output parameter is p_extrameas.
//

int
spindump_analyze_quic_parser_getextrameas(const unsigned char* payload,
                                          unsigned int payload_len,
                                          int longform,
                                          uint32_t version,
                                          int fromResponder,
                                          int spin,
                                          struct spindump_extrameas* p_extrameas) {
  spindump_assert(payload != 0);
  spindump_assert(spindump_isbool(longform));

  if (payload_len < 1) return(0);
  uint8_t firstByte = payload[0];

  if (longform == 0) {

    spindump_deepdebugf("Reserved bits are not parseable for the long version header");
    return(0);

  } else {
    if (spindump_analyze_quic_parser_version_getextrameas(version,firstByte,spin,p_extrameas)) {
      //TODO: debug print needed here
      /*spindump_deepdebugf("SPIN = %u (v.%08x) from %s",
                          *p_spin, version,
                          fromResponder ? "responder" : "initiator");*/
      return(1);
    } else {
      spindump_deepdebugf("Reserved bits are not parseable for this version (%x)", version);
      return(0);
    }

  }
}

