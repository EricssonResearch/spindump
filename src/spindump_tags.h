

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
//  SPINDUMP (C) 2020 BY ERICSSON RESEARCH
//  AUTHOR: JARI ARKKO
//
// 

#ifndef SPINDUMP_TAGS_H
#define SPINDUMP_TAGS_H

//
// Includes -----------------------------------------------------------------------------------
//

#include "spindump_util.h"

//
// Parameters ---------------------------------------------------------------------------------
//

#define spindump_tags_maxlength                       24 // chars

//
// Data types ---------------------------------------------------------------------------------
//

struct spindump_tags_struct {
  char string[spindump_tags_maxlength];
};

typedef struct spindump_tags_struct spindump_tags;

//
// External API interface to this module ------------------------------------------------------
//

void
spindump_tags_initialize(spindump_tags* tags);
void
spindump_tags_copy(spindump_tags* to,
                   const spindump_tags* from);
int
spindump_tags_addtag(spindump_tags* tags,
                     const char* tag);
int
spindump_tags_compare(const spindump_tags* t1,
                      const spindump_tags* t2);
void
spindump_tags_uninitialize(spindump_tags* tags);

#endif // SPINDUMP_TAGS_H
