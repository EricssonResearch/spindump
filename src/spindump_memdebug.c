
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

#include <stdio.h>
#include "spindump_util.h"
#include "spindump_memdebug.h"

//
// Actual code --------------------------------------------------------------------------------
//

#ifdef SPINDUMP_MEMDEBUG

//
// Debug version of "malloc"
//

void*
spindump_memdebug_malloc(size_t size) {
  spindump_assert(size > 0);
  spindump_assert(strlen(spindump_memorytag_begin) == spindump_memorytag_tagoverhead);
  spindump_assert(strlen(spindump_memorytag_end) == spindump_memorytag_tagoverhead);
  spindump_assert(spindump_memorytag_beginoverhead % 4 == 0);
  size_t newSize = size + spindump_memorytag_fulloverhead;
  spindump_assert(newSize > size);
  char* block = (char*)malloc(newSize);
  size_t* blockSize = (size_t*)(block + spindump_memorytag_tagoverhead);
  void* userBlock = (void*)(block + spindump_memorytag_beginoverhead);
  char* blockEnd = block + spindump_memorytag_beginoverhead + size;
  memcpy(block,spindump_memorytag_begin,spindump_memorytag_tagoverhead);
  *blockSize = size;
  memcpy(blockEnd,spindump_memorytag_end,spindump_memorytag_tagoverhead);
  return(userBlock);
}

//
// Debug version of "free"
//

void
spindump_memdebug_free(void* ptr) {
  spindump_assert(ptr != 0);
  char* block = ((char*)ptr) - spindump_memorytag_beginoverhead;
  size_t* blockSize = (size_t*)(block + spindump_memorytag_tagoverhead);
  size_t size = *blockSize;
  spindump_assert(size > 0);
  char* blockEnd = block + spindump_memorytag_beginoverhead + size;
  spindump_assert(memcmp(block,spindump_memorytag_begin,spindump_memorytag_tagoverhead) == 0);
  spindump_assert(memcmp(blockEnd,spindump_memorytag_end,spindump_memorytag_tagoverhead) == 0);
  free(block);
}

#endif // SPINDUMP_MEMDEBUG

