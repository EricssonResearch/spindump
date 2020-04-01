
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

#include "spindump_util.h"
#include "spindump_tags.h"

//
// Function prototypes ------------------------------------------------------------------------
//

//
// Actual code --------------------------------------------------------------------------------
//

//
// Initialize a tags object
//

void
spindump_tags_initialize(spindump_tags* tags) {
  spindump_assert(tags != 0);
  memset(tags,0,sizeof(*tags));
}

//
// Initialize a tags object from another one
//

void
spindump_tags_copy(spindump_tags* to,
                   const spindump_tags* from) {
  spindump_assert(to != 0);
  spindump_assert(from != 0);
  memcpy(to,from,sizeof(*to));
}

//
// Add a new tag to a tags object
//

int
spindump_tags_addtag(spindump_tags* tags,
                     const char* tag) {
  spindump_assert(tags != 0);
  spindump_assert(tag != 0);
  unsigned int comma = strlen(tags->string) > 0 ? 1 : 0;
  if (strlen(tags->string) + strlen(tag) + comma > sizeof(tags->string) - 1) {
    return(0);
  } else {
    if (comma) strncat(&tags->string[0],",",sizeof(tags->string));
    strncat(&tags->string[0],tag,sizeof(tags->string));
    return(1);
  }
}

//
// Compare tags, as in strcmp.
//

int
spindump_tags_compare(const spindump_tags* t1,
                      const spindump_tags* t2) {
  spindump_assert(t1 != 0);
  spindump_assert(t2 != 0);
  return(strcmp(t1->string,t2->string));
}

//
// Release a tag object
//

void
spindump_tags_uninitialize(spindump_tags* tags) {
  spindump_assert(tags != 0);
}

