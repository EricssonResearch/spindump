
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
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "spindump_util.h"
#include "spindump_protocols.h"
#include "spindump_connections.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static void tests();

//
// Actual code --------------------------------------------------------------------------------
//

//
// The tests
//

static void tests() {
  
  //
  // Address tests
  // 
  
  spindump_address a1;
  spindump_address a2;
  spindump_address a3;
  spindump_address a4;
  spindump_address a5;
  spindump_address a6;
  spindump_address_fromstring(&a1,"10.30.0.1");
  spindump_address_fromstring(&a2,"10.30.0.2");
  spindump_address_fromstring(&a3,"10.20.7.8");
  const char* a1s = spindump_address_tostring(&a1);
  spindump_debugf("a1s = %s", a1s);
  spindump_assert(strcmp(a1s,"10.30.0.1") == 0);
  spindump_address_fromstring(&a4,"2001:14bb:150:4979:14fa:eae8:202e:f210");
  spindump_address_fromstring(&a5,"2001:14bb:150:4979::1");
  spindump_address_fromstring(&a6,"2a00:1450:400f:809::200e");
  spindump_assert(spindump_address_equal(&a1,&a1));
  spindump_assert(!spindump_address_equal(&a1,&a2));
  spindump_assert(!spindump_address_equal(&a3,&a4));
  spindump_assert(spindump_address_equal(&a6,&a6));
  spindump_assert(!spindump_address_equal(&a5,&a6));
  const char* a4s = spindump_address_tostring(&a4);
  spindump_debugf("a4s = %s", a4s);
  spindump_assert(strcmp(a4s,"2001:14bb:150:4979:14fa:eae8:202e:f210") == 0);

  //
  // Network tests
  // 

  spindump_network n1;
  spindump_network n2;
  spindump_network n3;
  spindump_network_fromstring(&n1,"10.30.0.0/24");
  spindump_network_fromstring(&n2,"10.30.0.0/8");
  spindump_network_fromstring(&n3,"2001:14bb:150:4979::0/64");
  spindump_assert(spindump_network_equal(&n1,&n1));
  spindump_assert(!spindump_network_equal(&n1,&n2));
  spindump_assert(!spindump_network_equal(&n1,&n3));
  spindump_assert(spindump_network_equal(&n3,&n3));
  spindump_assert(spindump_address_innetwork(&a1,&n1));
  spindump_assert(spindump_address_innetwork(&a1,&n2));
  spindump_assert(!spindump_address_innetwork(&a1,&n3));
  spindump_assert(!spindump_address_innetwork(&a3,&n1));
  spindump_assert(spindump_address_innetwork(&a3,&n2));
  spindump_assert(spindump_address_innetwork(&a4,&n3));
  spindump_assert(spindump_address_innetwork(&a5,&n3));
  spindump_assert(!spindump_address_innetwork(&a6,&n3));

  //
  // QUIC CID tests
  // 

  struct spindump_quic_connectionid id1;
  id1.len = 0;
  const char* id1s = spindump_connection_quicconnectionid_tostring(&id1);
  spindump_debugf("id1s = %s", id1s);
  spindump_assert(strcmp(id1s,"null") == 0);
  struct spindump_quic_connectionid id2;
  id2.len = 14;
  id2.id[0] = 0x01;
  id2.id[1] = 0x02;
  id2.id[2] = 0x03;
  id2.id[3] = 0x04;
  id2.id[4] = 0x05;
  id2.id[5] = 0x06;
  id2.id[6] = 0x07;
  id2.id[7] = 0x08;
  id2.id[8] = 0x09;
  id2.id[9] = 0x0a;
  id2.id[10] = 0x0b;
  id2.id[11] = 0x0c;
  id2.id[12] = 0x0d;
  id2.id[13] = 0x0e;
  const char* id2s = spindump_connection_quicconnectionid_tostring(&id2);
  spindump_debugf("id2s = %s", id2s);
  spindump_assert(strcmp(id2s,"0102030405060708090a0b0c0d0e") == 0);
}

//
// The main program
//

int main(int argc,char** argv) {
  
  //
  // Process arguments
  //
  
  argc--; argv++;
  while (argc > 0) {
    
    if (strcmp(argv[0],"--debug") == 0) {
      
      debug = 1;
      
    } else if (strcmp(argv[0],"--no-debug") == 0) {
      
      debug = 0;
      deepdebug = 0;
      
    } else if (strcmp(argv[0],"--deepdebug") == 0) {
      
      debug = 1;
      deepdebug = 1;
      
    } else if (strcmp(argv[0],"--no-deepdebug") == 0) {
      
      deepdebug = 0;

    } else {

      spindump_fatalf("invalid argument: %s", argv[0]);
      exit(1);
      
    }
    
    argc--; argv++;
  }

  printf("running tests...\n");
  tests();
  printf("all ok\n");
  
  exit(0);
}
  
