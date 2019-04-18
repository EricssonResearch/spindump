
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

#ifndef SPIDUMP_MEMDEBUG_H
#define SPIDUMP_MEMDEBUG_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//
// Parameters ---------------------------------------------------------------------------------
//

#define spindump_memorytag_tagoverhead                   8
#define spindump_memorytag_beginoverhead                 (spindump_memorytag_tagoverhead+sizeof(size_t))
#define spindump_memorytag_endoverhead                   spindump_memorytag_tagoverhead
#define spindump_memorytag_fulloverhead                  (spindump_memorytag_beginoverhead+spindump_memorytag_endoverhead)
#define spindump_memorytag_begin                         "firsttag"
#define spindump_memorytag_end                           "xyzaazbb"

//
// External API interface to this module ------------------------------------------------------
//

void*
spindump_memdebug_malloc(size_t size);
void
spindump_memdebug_free(void* ptr);

#endif // SPINDUMP_MEMDEBUG_H
