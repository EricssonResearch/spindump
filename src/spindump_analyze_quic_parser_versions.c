
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

static const struct spindump_quic_versiondescr*
spindump_analyze_quic_parser_version_findversion(uint32_t version);
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

//
// Variables ----------------------------------------------------------------------------------
//

static const struct spindump_quic_versiondescr versions[] = {
  //      version number              function to generate a name       basename supported?    
  { spindump_quic_version_rfc,     spindump_analyze_quic_parser_version_fixedname, "RFC",    1 },
  { spindump_quic_version_draft20, spindump_analyze_quic_parser_version_fixedname, "v20",    1 },
  { spindump_quic_version_draft19, spindump_analyze_quic_parser_version_fixedname, "v19",    1 },
  { spindump_quic_version_draft18, spindump_analyze_quic_parser_version_fixedname, "v18",    1 },
  { spindump_quic_version_draft17, spindump_analyze_quic_parser_version_fixedname, "v17",    1 },
  { spindump_quic_version_draft16, spindump_analyze_quic_parser_version_fixedname, "v16",    1 },
  { spindump_quic_version_draft15, spindump_analyze_quic_parser_version_fixedname, "v15",    1 },
  { spindump_quic_version_draft14, spindump_analyze_quic_parser_version_fixedname, "v14",    1 },
  { spindump_quic_version_draft13, spindump_analyze_quic_parser_version_fixedname, "v13",    1 },
  { spindump_quic_version_draft12, spindump_analyze_quic_parser_version_fixedname, "v12",    1 },
  { spindump_quic_version_draft11, spindump_analyze_quic_parser_version_fixedname, "v11",    1 },
  { spindump_quic_version_draft10, spindump_analyze_quic_parser_version_fixedname, "v10",    1 },
  { spindump_quic_version_draft09, spindump_analyze_quic_parser_version_fixedname, "v09",    1 },
  { spindump_quic_version_draft08, spindump_analyze_quic_parser_version_fixedname, "v08",    1 },
  { spindump_quic_version_draft07, spindump_analyze_quic_parser_version_fixedname, "v07",    1 },
  { spindump_quic_version_draft06, spindump_analyze_quic_parser_version_fixedname, "v06",    1 },
  { spindump_quic_version_draft05, spindump_analyze_quic_parser_version_fixedname, "v05",    1 },
  { spindump_quic_version_draft04, spindump_analyze_quic_parser_version_fixedname, "v04",    1 },
  { spindump_quic_version_draft03, spindump_analyze_quic_parser_version_fixedname, "v03",    1 },
  { spindump_quic_version_draft02, spindump_analyze_quic_parser_version_fixedname, "v02",    1 },
  { spindump_quic_version_draft01, spindump_analyze_quic_parser_version_fixedname, "v01",    1 },
  { spindump_quic_version_draft00, spindump_analyze_quic_parser_version_fixedname, "v00",    1 },
  { spindump_quic_version_quant20, spindump_analyze_quic_parser_version_fixedname, "v.qn20", 1 },
  { spindump_quic_version_quant19, spindump_analyze_quic_parser_version_fixedname, "v.qn19", 1 },
  { spindump_quic_version_huitema, spindump_analyze_quic_parser_version_fixedname, "v.huit", 1 },
  { spindump_quic_version_mozilla, spindump_analyze_quic_parser_version_fixedname, "v.moz",  1 },
  { spindump_quic_version_google,  spindump_analyze_quic_parser_version_googlename, "g.",    1 },
  { spindump_quic_version_unknown, 0,                                               0,       0 }
};
  
//
// Actual code --------------------------------------------------------------------------------
//

//
// Find a version structure, or return 0 if none is founds
//

static const struct spindump_quic_versiondescr*
spindump_analyze_quic_parser_version_findversion(uint32_t version) {
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

const char*
spindump_analyze_quic_parser_versiontostring(uint32_t version) {

  //
  // Reserve space for the name
  //
  
  static char buf[20];
  memset(buf,0,sizeof(buf));
  
  //
  // Find a version descriptor
  //

  const struct spindump_quic_versiondescr* descriptor =
    spindump_analyze_quic_parser_version_findversion(version);
  if (version == 0) {
    snprintf(buf,sizeof(buf)-1,"v.0x%08x", version);
  } else {
    (*(descriptor->namefunction))(version,descriptor->basename,buf,sizeof(buf));
  }

  //
  // Return the result
  //
  
  return(buf);
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
