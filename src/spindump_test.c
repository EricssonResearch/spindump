
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
#include "spindump_analyze.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static void unittests();
static void systemtests();

//
// Actual code --------------------------------------------------------------------------------
//

//
// The tests -- unit tests
//

static void unittests() {
  
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
// The tests -- system tests
//

static void systemtests() {
  
  //
  // Analyzer tests -- ICMP
  //
  
  struct spindump_analyze* analyzer = spindump_analyze_initialize();
  spindump_assert(analyzer != 0);
  struct spindump_packet packet;
  struct spindump_connection* connection = 0;
  memset(&packet,0,sizeof(packet));
  const unsigned char packet1[] = {
    0x1c, 0x87, 0x2c, 0x5f, 0x28, 0x1b, 0xdc, 0xa9, 0x04, 0x92, 0x22, 0xb4, 0x86, 0xdd, 0x60, 0x08,
    0xaf, 0xa7, 0x00, 0x10, 0x3a, 0x40, 0x20, 0x01, 0x1b, 0xc8, 0x01, 0x01, 0xe9, 0x00, 0x84, 0x96,
    0xc2, 0xfb, 0xc4, 0x62, 0xf6, 0x49, 0x20, 0x01, 0x06, 0x7c, 0x02, 0xb0, 0x01, 0xc1, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x94, 0x80, 0x00, 0x1d, 0x59, 0xb4, 0xee, 0x00, 0x00, 0x5c, 0x4a,
    0xb5, 0x1d, 0x00, 0x0d, 0x47, 0x6c };
  const unsigned char packet2[] = {
    0xdc, 0xa9, 0x04, 0x92, 0x22, 0xb4, 0x1c, 0x87, 0x2c, 0x5f, 0x28, 0x1b, 0x86, 0xdd, 0x62, 0x00,
    0x00, 0x00, 0x00, 0x10, 0x3a, 0x35, 0x20, 0x01, 0x06, 0x7c, 0x02, 0xb0, 0x01, 0xc1, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x94, 0x20, 0x01, 0x1b, 0xc8, 0x01, 0x01, 0xe9, 0x00, 0x84, 0x96,
    0xc2, 0xfb, 0xc4, 0x62, 0xf6, 0x49, 0x81, 0x00, 0x1c, 0x59, 0xb4, 0xee, 0x00, 0x00, 0x5c, 0x4a,
    0xb5, 0x1d, 0x00, 0x0d, 0x47, 0x6c, };
  
  packet.timestamp.tv_usec = 0;
  packet.contents = packet1;
  packet.etherlen = sizeof(packet1);
  packet.caplen = packet.etherlen;
  spindump_analyze_process(analyzer,&packet,&connection);
  
  spindump_assert(connection != 0);
  spindump_assert(connection->type == spindump_connection_transport_icmp);
  spindump_assert(connection->state == spindump_connection_state_establishing);

  packet.timestamp.tv_usec = 1;
  packet.contents = packet2;
  packet.etherlen = sizeof(packet2);
  packet.caplen = packet.etherlen;
  connection = 0;
  spindump_analyze_process(analyzer,&packet,&connection);
  
  spindump_assert(connection != 0);
  spindump_assert(connection->type == spindump_connection_transport_icmp);
  spindump_assert(connection->state == spindump_connection_state_established);
  spindump_assert(connection->packetsFromSide1 == 1);
  spindump_assert(connection->packetsFromSide2 == 1);
  spindump_assert(connection->bytesFromSide1 == sizeof(packet1) - spindump_ethernet_header_size);
  spindump_assert(connection->bytesFromSide2 == sizeof(packet2) - spindump_ethernet_header_size);
  spindump_assert(connection->leftRTT.lastRTT == spindump_rtt_infinite);
  spindump_assert(connection->rightRTT.lastRTT == 1);
  
  spindump_analyze_uninitialize(analyzer);
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

  printf("running unit tests...\n");
  unittests();
  printf("running system tests...\n");
  systemtests();
  printf("all ok\n");
  
  exit(0);
}
  
