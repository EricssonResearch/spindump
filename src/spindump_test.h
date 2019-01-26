
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

#ifndef SPIDUMP_TEST_H
#define SPIDUMP_TEST_H

//
// Includes -----------------------------------------------------------------------------------
//

#include "spindump_util.h"

//
// Some helper macros -------------------------------------------------------------------------
//

#define spindump_checktest(cond)  {                             	                 \
                                    spindump_debugf("running check %s on line %u",       \
                                                    #cond, __LINE__);                    \
                                    if (!(cond)) {                             	         \
                                      spindump_fatalf("Test %s failed on %s line %u",    \
                                                      #cond,               	         \
                                                      __FILE__, __LINE__);		 \
                                    }                           	                 \
                                  }

#endif // SPIDUMP_TEST_H
