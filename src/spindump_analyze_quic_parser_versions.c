
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

static void
spindump_analyze_quic_parser_version_fixedname(uint32_t version,
                                               const char* basename,
                                               char* buf,
                                               size_t bufsize);
static void
spindump_analyze_quic_parser_version_googlename(uint32_t version,
                                               const char* basename,
                                               char* buf,
                                               size_t bufsize);
static int
spindump_analyze_quic_parser_version_messagefunction17(uint32_t version,
                                                       uint8_t headerByte,
                                                       enum spindump_quic_message_type* type);
static int
spindump_analyze_quic_parser_version_messagefunction16(uint32_t version,
                                                       uint8_t headerByte,
                                                       enum spindump_quic_message_type* type);
static int
spindump_analyze_quic_parser_version_messagefunctiongoogle(uint32_t version,
                                                           uint8_t headerByte,
                                                           enum spindump_quic_message_type* type);
static int
spindump_analyze_quic_parser_version_getspinbitvalue_draft17(uint32_t version,
                                                             uint8_t headerByte,
                                                             int* p_spinValue);
static int
spindump_analyze_quic_parser_version_getspinbitvalue_draft16(uint32_t version,
                                                             uint8_t headerByte,
                                                             int* p_spinValue);

//
// Variables ----------------------------------------------------------------------------------
//

//
// Some shorthands
//

#define fixednamefn spindump_analyze_quic_parser_version_fixedname
#define googlenamefn spindump_analyze_quic_parser_version_googlename
#define messagefunc17 spindump_analyze_quic_parser_version_messagefunction17
#define messagefunc16 spindump_analyze_quic_parser_version_messagefunction16
#define messagefuncgo spindump_analyze_quic_parser_version_messagefunctiongoogle
#define parselengths17 spindump_analyze_quic_parser_parsemessagelength_pertype
#define spinbit17 spindump_analyze_quic_parser_version_getspinbitvalue_draft17
#define spinbit16 spindump_analyze_quic_parser_version_getspinbitvalue_draft16

//
// The following table determines the version-dependent behaviour of
// the QUIC parser. The first field is the version number, whereas the
// rest of the fields are parameters and function pointers to get Spin
// bit values, determine what the printable name of a version number
// might be, etc.
//
// You need to update this table when adding a new version! Depending
// on what the new version does, you may be able to use existing
// functions and settings from other draft versions, though.
//

static const struct spindump_quic_versiondescr versions[] = {
  //      version number            get name   basename supported? LongCIDs? getmessage     parselengths   getspinbit
  { spindump_quic_version_rfc,     fixednamefn,  "RFC",    1,        1,    messagefunc17,  parselengths17,  spinbit17 },
  { spindump_quic_version_draft22, fixednamefn,  "v22",    1,        1,    messagefunc17,  parselengths17,  spinbit17 },
  { spindump_quic_version_draft21, fixednamefn,  "v21",    1,        0,    messagefunc17,  parselengths17,  spinbit17 },
  { spindump_quic_version_draft20, fixednamefn,  "v20",    1,        0,    messagefunc17,  parselengths17,  spinbit17 },
  { spindump_quic_version_draft19, fixednamefn,  "v19",    1,        0,    messagefunc17,  parselengths17,  spinbit17 },
  { spindump_quic_version_draft18, fixednamefn,  "v18",    1,        0,    messagefunc17,  parselengths17,  spinbit17 },
  { spindump_quic_version_draft17, fixednamefn,  "v17",    1,        0,    messagefunc17,  parselengths17,  spinbit17 },
  { spindump_quic_version_draft16, fixednamefn,  "v16",    1,        0,    messagefunc16,  0,               spinbit16 },
  { spindump_quic_version_draft15, fixednamefn,  "v15",    0,        0,    0,              0,               0         },
  { spindump_quic_version_draft14, fixednamefn,  "v14",    0,        0,    0,              0,               0         },
  { spindump_quic_version_draft13, fixednamefn,  "v13",    0,        0,    0,              0,               0         },
  { spindump_quic_version_draft12, fixednamefn,  "v12",    0,        0,    0,              0,               0         },
  { spindump_quic_version_draft11, fixednamefn,  "v11",    0,        0,    0,              0,               0         },
  { spindump_quic_version_draft10, fixednamefn,  "v10",    0,        0,    0,              0,               0         },
  { spindump_quic_version_draft09, fixednamefn,  "v09",    0,        0,    0,              0,               0         },
  { spindump_quic_version_draft08, fixednamefn,  "v08",    0,        0,    0,              0,               0         },
  { spindump_quic_version_draft07, fixednamefn,  "v07",    0,        0,    0,              0,               0         },
  { spindump_quic_version_draft06, fixednamefn,  "v06",    0,        0,    0,              0,               0         },
  { spindump_quic_version_draft05, fixednamefn,  "v05",    0,        0,    0,              0,               0         },
  { spindump_quic_version_draft04, fixednamefn,  "v04",    0,        0,    0,              0,               0         },
  { spindump_quic_version_draft03, fixednamefn,  "v03",    0,        0,    0,              0,               0         },
  { spindump_quic_version_draft02, fixednamefn,  "v02",    0,        0,    0,              0,               0         },
  { spindump_quic_version_draft01, fixednamefn,  "v01",    0,        0,    0,              0,               0         },
  { spindump_quic_version_draft00, fixednamefn,  "v00",    0,        0,    0,              0,               0         },
  { spindump_quic_version_quant22, fixednamefn,  "v.qn22", 1,        1,    messagefunc17,  parselengths17,  spinbit17 },
  { spindump_quic_version_quant21, fixednamefn,  "v.qn21", 1,        0,    messagefunc17,  parselengths17,  spinbit17 },
  { spindump_quic_version_quant20, fixednamefn,  "v.qn20", 1,        0,    messagefunc17,  parselengths17,  spinbit17 },
  { spindump_quic_version_quant19, fixednamefn,  "v.qn19", 1,        0,    messagefunc17,  parselengths17,  spinbit17 },
  { spindump_quic_version_huitema, fixednamefn,  "v.huit", 1,        0,    messagefunc17,  parselengths17,  spinbit17 },
  { spindump_quic_version_mozilla, fixednamefn,  "v.moz",  1,        0,    messagefunc17,  parselengths17,  spinbit17 },
  { spindump_quic_version_google,  googlenamefn, "g.",     1,        0,    messagefuncgo,  0,               0         },
  { spindump_quic_version_titrlo1, fixednamefn,  "v.til1", 1,        0,    messagefunc17,  parselengths17,  spinbit17 },
  { spindump_quic_version_unknown, 0,            0,        0,        0,    0,              0,               0         }
};
  
//
// Actual code --------------------------------------------------------------------------------
//

//
// Find a version structure, or return 0 if none is founds
//

const struct spindump_quic_versiondescr*
spindump_analyze_quic_parser_version_findversion(uint32_t version) {
  if ((version & spindump_quic_version_googlemask) == spindump_quic_version_google) {
    version = spindump_quic_version_google;
  }
  const struct spindump_quic_versiondescr* search = &versions[0];
  while (search->version != spindump_quic_version_unknown) {
    if (search->version == version) {
      return(search);
    } else {
      search++;
    }
  }
  
  //
  // Not found
  //
  
  return(0);
}

//
// Return a string representation of a QUIC version number, e.g., "v17".
// The returned string need not be freed, but it will not surive the next call
// to this function.
//
// Note: This function is not thread safe.
//

void
spindump_analyze_quic_parser_versiontostring(uint32_t version,
                                             char* buf,
                                             size_t bufsize) {

  //
  // Sanity checks
  //

  spindump_assert(buf != 0);
  spindump_assert(bufsize > 0);
  
  //
  // Clear the buffer
  //
  
  spindump_deepdeepdebugf("versiontostring %08x %u", version, bufsize);
  memset(buf,0,bufsize);
  
  //
  // Find a version descriptor
  //

  const struct spindump_quic_versiondescr* descriptor =
    spindump_analyze_quic_parser_version_findversion(version);
  spindump_deepdeepdebugf("versiontostring got a descriptor %lx", descriptor);
  if (descriptor == 0) {
    snprintf(buf,bufsize-1,"v.0x%08x", version);
  } else {
    (*(descriptor->namefunction))(version,descriptor->basename,buf,bufsize);
  }

  //
  // Done
  //
}

//
// Checks whether this version number likely belongs to Google
// They look like Qddd, e.g. Q043 in ASCII
//

int
spindump_analyze_quic_parser_isgoogleversion(uint32_t version) {
  return ((version & spindump_quic_version_googlemask) == spindump_quic_version_google);
}

//
// Determines the google numeric version from the version data
// returns spindump_quic_version_unknown if the version data is a non-valid google version number
//

uint32_t
spindump_analyze_quic_parser_getgoogleversion(uint32_t version) {
  const unsigned char mask = 0x30;
  uint32_t d100= ((version >> 16) & 0xff) ^ mask;
  uint32_t d10= ((version >> 8) & 0xff) ^ mask;
  uint32_t d1= ((version >> 0) & 0xff) ^ mask;

  // this part makes sure that the Google version number is Q followed by 3 digits in ASCII
  if ( d100>9 || d10>9 || d1>9 || ((version >> 24) & 0xff) != 'Q') return(spindump_quic_version_unknown);

  return 100*d100+10*d10+d1;
}

//
// Get the name of the version, for one of the versions that have fixed names
//

static void
spindump_analyze_quic_parser_version_fixedname(uint32_t version,
                                               const char* basename,
                                               char* buf,
                                               size_t bufsize) {
  spindump_assert(basename != 0);
  spindump_assert(buf != 0);
  spindump_assert(bufsize > 0);
  memset(buf,0,bufsize);
  strncpy(buf,basename,bufsize-1);
}

//
// Get the name of the version, for one of the Google QUIC versions
//

static void
spindump_analyze_quic_parser_version_googlename(uint32_t version,
                                               const char* basename,
                                               char* buf,
                                               size_t bufsize) {
  spindump_assert(spindump_analyze_quic_parser_isgoogleversion(version));
  memset(buf,0,bufsize);
  snprintf(buf,bufsize-1,"%s%u",
           basename,
           (unsigned int)spindump_analyze_quic_parser_getgoogleversion(version));
}

//
// Get what the message type is in a draft-17 - draft-20 QUIC message
//

static int
spindump_analyze_quic_parser_version_messagefunction17(uint32_t version,
                                                       uint8_t headerByte,
                                                       enum spindump_quic_message_type* type) {
  uint8_t messageType = headerByte & spindump_quic_byte_type;
  spindump_deepdebugf("looking at v17-20 message type %02x", messageType);
  switch (messageType) {
  case spindump_quic_byte_type_initial:
    *type = spindump_quic_message_type_initial;
    return(1);
  case spindump_quic_byte_type_0rttprotected:
    *type = spindump_quic_message_type_0rtt;
    return(1);
  case spindump_quic_byte_type_handshake:
    *type = spindump_quic_message_type_handshake;
    return(1);
  case spindump_quic_byte_type_retry:
    *type = spindump_quic_message_type_retry;
    return(1);
  default:
    return(0);
  }
}

//
// Get what the message type is in a draft-16 QUIC message
//

static int
spindump_analyze_quic_parser_version_messagefunction16(uint32_t version,
                                                       uint8_t headerByte,
                                                       enum spindump_quic_message_type* type) {
  uint8_t messageType = headerByte & spindump_quic_byte_type_draft16;
  spindump_deepdebugf("looking at v16 message type %02x", messageType);
  switch (messageType) {
  case spindump_quic_byte_type_initial_draft16:
    *type = spindump_quic_message_type_initial;
    return(1);
  case spindump_quic_byte_type_0rttprotected_draft16:
    *type = spindump_quic_message_type_0rtt;
    return(1);
  case spindump_quic_byte_type_handshake_draft16:
    *type = spindump_quic_message_type_handshake;
    return(1);
  case spindump_quic_byte_type_retry_draft16:
    *type = spindump_quic_message_type_retry;
    return(1);
  default:
    return(0);
  }
}

//
// Get what the message type is in a Google QUIC message
//

static int
spindump_analyze_quic_parser_version_messagefunctiongoogle(uint32_t version,
                                                           uint8_t headerByte,
                                                           enum spindump_quic_message_type* type) {
  *type = spindump_quic_message_type_initial;
  return(1);
}

//
// Determine what the message type for this packet is, based on
// version and the header byte. Return 1 if the type was able to be
// determined, 0 otherwise. Set the output parameter type
// appropriately if successful.
//

int
spindump_analyze_quic_parser_version_getmessagetype(uint32_t version,
                                                    uint8_t headerByte,
                                                    enum spindump_quic_message_type* p_type) {
  const struct spindump_quic_versiondescr* descriptor =
    spindump_analyze_quic_parser_version_findversion(version);
  if (descriptor == 0 || !descriptor->supported) {
    return(0);
  } else {
    return((*(descriptor->messagetypefunction))(version,headerByte,p_type));
  }
}

//
// Parse packet lengths of a particular message. This will depend on version.
//

int
spindump_analyze_quic_parser_version_parselengths(uint32_t version,
                                                  const unsigned char* payload,
                                                  unsigned int payload_len,
                                                  unsigned int remainingCaplen,
                                                  enum spindump_quic_message_type type,
                                                  unsigned int cidLengthsInBytes,
                                                  unsigned int* p_messageLen,
                                                  struct spindump_stats* stats) {
  const struct spindump_quic_versiondescr* descriptor =
    spindump_analyze_quic_parser_version_findversion(version);
  if (descriptor != 0 && descriptor->supported && descriptor->parselengthsfunction != 0) {
    return((*(descriptor->parselengthsfunction))(payload,
                                                 payload_len,
                                                 remainingCaplen,
                                                 type,
                                                 cidLengthsInBytes,
                                                 p_messageLen,
                                                 stats));
  } else {
    return(0);
  }
}

//
// Get the value of the spin bit for draft-17 - draft-20 and other
// similar version short packets.
//

static int
spindump_analyze_quic_parser_version_getspinbitvalue_draft17(uint32_t version,
                                                             uint8_t headerByte,
                                                             int* p_spinValue) {
  *p_spinValue = ((headerByte & spindump_quic_byte_spin) != 0);
  return(1);
}

//
// Get the value of the spin bit for draft-16 and other similar version short packets.
//

static int
spindump_analyze_quic_parser_version_getspinbitvalue_draft16(uint32_t version,
                                                             uint8_t headerByte,
                                                             int* p_spinValue) {
  *p_spinValue = ((headerByte & spindump_quic_byte_spin_draft16) != 0);
  return(1);
}

//
// Get the value of the spin bit for this packet. The packet must be a
// short form packet. Depending on version, the bit may be in a
// different place.
//

int
spindump_analyze_quic_parser_version_getspinbitvalue(uint32_t version,
                                                     uint8_t headerByte,
                                                     int* p_spinValue) {
  const struct spindump_quic_versiondescr* descriptor =
    spindump_analyze_quic_parser_version_findversion(version);
  if (descriptor != 0 && descriptor->supported && descriptor->spinbitvaluefunction != 0) {
    return((*(descriptor->spinbitvaluefunction))(version,headerByte,p_spinValue));
  } else {
    return(0);
  }
}

int
spindump_analyze_quic_parser_version_getextrameas(uint32_t version,
                                                 uint8_t headerByte,
                                                 int spin,
                                                 struct spindump_extrameas* p_extrameasValue){
  /*const struct spindump_quic_versiondescr* descriptor =
    spindump_analyze_quic_parser_version_findversion(version);
  if (descriptor != 0 && descriptor->supported && descriptor->spinbitvaluefunction != 0) {
    return((*(descriptor->spinbitvaluefunction))(version,headerByte,p_spinValue));
  } else {
    return(0);
  }*/
  return(0);
}

//
// Find out if the version uses short (draft-21 and before) or long
// (draft-22 and onwards) CID length design.
//

int
spindump_analyze_quic_parser_version_useslongcidlength(uint32_t version) {
  const struct spindump_quic_versiondescr* descriptor =
    spindump_analyze_quic_parser_version_findversion(version);
  return(descriptor != 0 && descriptor->longCidLength);
}

