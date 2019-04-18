
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
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include "spindump_util.h"
#include "spindump_test.h"
#include "spindump_protocols.h"
#include "spindump_connections.h"
#include "spindump_event.h"
#include "spindump_event_parser_json.h"
#include "spindump_event_parser_text.h"
#include "spindump_analyze.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static void unittests(void);
static void unittests_util(void);
static void unittests_table(void);
static void unittests_textparser(void);
static void unittests_jsonparser(void);
static void systemtests(void);

//
// Actual code --------------------------------------------------------------------------------
//

//
// The tests -- unit tests
//

static void
unittests(void) {
  unittests_util();
  unittests_table();
  unittests_textparser();
  unittests_jsonparser();
}

//
// The tests -- unit tests for the Spindump util module
//

static void
unittests_util(void) {
  
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
  spindump_checktest(strcmp(a1s,"10.30.0.1") == 0);
  spindump_address_fromstring(&a4,"2001:14bb:150:4979:14fa:eae8:202e:f210");
  spindump_address_fromstring(&a5,"2001:14bb:150:4979::1");
  spindump_address_fromstring(&a6,"2a00:1450:400f:809::200e");
  spindump_checktest(spindump_address_equal(&a1,&a1));
  spindump_checktest(!spindump_address_equal(&a1,&a2));
  spindump_checktest(!spindump_address_equal(&a3,&a4));
  spindump_checktest(spindump_address_equal(&a6,&a6));
  spindump_checktest(!spindump_address_equal(&a5,&a6));
  const char* a4s = spindump_address_tostring(&a4);
  spindump_debugf("a4s = %s", a4s);
  spindump_checktest(strcmp(a4s,"2001:14bb:150:4979:14fa:eae8:202e:f210") == 0);

  //
  // Network tests
  // 

  spindump_network n1;
  spindump_network n2;
  spindump_network n3;
  spindump_network_fromstring(&n1,"10.30.0.0/24");
  spindump_network_fromstring(&n2,"10.30.0.0/8");
  spindump_network_fromstring(&n3,"2001:14bb:150:4979::0/64");
  spindump_checktest(spindump_network_equal(&n1,&n1));
  spindump_checktest(!spindump_network_equal(&n1,&n2));
  spindump_checktest(!spindump_network_equal(&n1,&n3));
  spindump_checktest(spindump_network_equal(&n3,&n3));
  spindump_checktest(spindump_address_innetwork(&a1,&n1));
  spindump_checktest(spindump_address_innetwork(&a1,&n2));
  spindump_checktest(!spindump_address_innetwork(&a1,&n3));
  spindump_checktest(!spindump_address_innetwork(&a3,&n1));
  spindump_checktest(spindump_address_innetwork(&a3,&n2));
  spindump_checktest(spindump_address_innetwork(&a4,&n3));
  spindump_checktest(spindump_address_innetwork(&a5,&n3));
  spindump_checktest(!spindump_address_innetwork(&a6,&n3));

  //
  // QUIC CID tests
  // 

  struct spindump_quic_connectionid id1;
  id1.len = 0;
  const char* id1s = spindump_connection_quicconnectionid_tostring(&id1);
  spindump_debugf("id1s = %s", id1s);
  spindump_checktest(strcmp(id1s,"null") == 0);
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
  spindump_checktest(strcmp(id2s,"0102030405060708090a0b0c0d0e") == 0);
}

//
// Unit tests for the connection table
//

static void
unittests_table(void) {

  //
  // Creation and deletion of the table itself
  //
  
  struct spindump_connectionstable* table = spindump_connectionstable_initialize();
  spindump_checktest(table != 0);
  spindump_connectionstable_uninitialize(table);
  table = spindump_connectionstable_initialize();
  spindump_checktest(table != 0);

  //
  // Adding a simple connection
  //

  spindump_address address1;
  spindump_address_fromstring(&address1,"127.0.0.1");
  spindump_address address2;
  spindump_address_fromstring(&address2,"127.0.0.2");
  struct timeval when1;
  when1.tv_sec = 17;
  when1.tv_usec = 900 * 1000;
  struct spindump_connection* connection1 =
    spindump_connections_newconnection_icmp(&address1,
					    &address2,
					    ICMP_ECHO,
					    500,
					    &when1,
					    table);
  spindump_checktest(connection1 != 0);

  //
  // Searching for a connection that does not exist
  //
  
  spindump_address address3;
  spindump_address_fromstring(&address3,"127.0.0.3");
  struct spindump_connection* connection2 =
    spindump_connections_searchconnection_icmp(&address1,
					       &address3,
					       ICMP_ECHO,
					       500,
					       table);
  spindump_checktest(connection2 == 0);
  struct spindump_connection* connection3 =
    spindump_connections_searchconnection_icmp(&address1,
					       &address2,
					       ICMP_ECHOREPLY,
					       500,
					       table);
  spindump_checktest(connection3 == 0);
  struct spindump_connection* connection4 =
    spindump_connections_searchconnection_icmp(&address1,
					       &address2,
					       ICMP_ECHO,
					       501,
					       table);
  spindump_checktest(connection4 == 0);
  
  //
  // Searching for the added connection
  //

  spindump_deepdebugf("address1 %s", spindump_address_tostring(&address1));
  spindump_deepdebugf("address2 %s", spindump_address_tostring(&address2));
  struct spindump_connection* connection5 =
    spindump_connections_searchconnection_icmp(&address1,
					       &address2,
					       ICMP_ECHO,
					       500,
					       table);
  spindump_checktest(connection5 != 0);
  spindump_checktest(connection5 == connection1);

  //
  // Create a more complicated connection, for QUIC
  //

  struct spindump_quic_connectionid cid1;
  cid1.len = 4;
  cid1.id[0] = 1;
  cid1.id[1] = 2;
  cid1.id[2] = 3;
  cid1.id[3] = 4;
  struct spindump_quic_connectionid cid2;
  cid2.len = 8;
  cid2.id[0] = 50;
  cid2.id[1] = 49;
  cid2.id[2] = 48;
  cid2.id[3] = 47;
  cid2.id[4] = 46;
  cid2.id[5] = 45;
  cid2.id[6] = 44;
  cid2.id[7] = 43;
  struct spindump_connection* connection6 =
    spindump_connections_newconnection_quic_5tupleandcids(&address1,
							  &address2,
							  5000,
							  4433,
							  &cid1,
							  &cid2,
							  &when1,
							  table);
  spindump_checktest(connection6 != 0);

  //
  // Search for the QUIC connection via addresses and type and ports
  //

  int fromResponder;
  struct spindump_connection* connection7 =
    spindump_connections_searchconnection_quic_5tuple_either(&address2,
							     &address1,
							     4433,
							     5000,
							     table,
							     &fromResponder);
  spindump_checktest(connection7 != 0);
  spindump_checktest(fromResponder == 1);
  spindump_checktest(connection7 == connection6);
  
  //
  // Search for the QUIC connection via CID
  //

  struct spindump_connection* connection8 =
    spindump_connections_searchconnection_quic_cids_either(&cid1,
							   &cid2,
							   table,
							   &fromResponder);
  spindump_checktest(connection8 != 0);
  spindump_checktest(fromResponder == 0);
  spindump_checktest(connection8 == connection6);
  
  spindump_connectionstable_uninitialize(table);
}

//
// Unittests -- spindump_event_parser_text
//

static void
unittests_textparser(void) {
  struct spindump_event event;
  unsigned long long million = 1000 * 1000;
  unsigned long long timestamp =
    ((unsigned long long)(60 * 365 * 24 * 3600 + 8 * 3600)) *
    million +
    (unsigned long long)1234;
  spindump_network network1;
  spindump_network network2;
  spindump_network_fromstring(&network1,"1.2.3.4/32");
  spindump_network_fromstring(&network2,"5.6.7.8/32");
  spindump_event_initialize(spindump_event_type_new_connection,
			    spindump_connection_transport_tcp,
			    &network1,
			    &network2,
			    "123:456",
			    timestamp,
			    1,
			    2,
			    &event);
  char buf[200];
  int ret;
  size_t consumed;
  ret = spindump_event_parser_text_print(&event,buf,1,&consumed);
  spindump_assert(ret == 0);
  ret = spindump_event_parser_text_print(&event,buf,sizeof(buf),&consumed);
  spindump_assert(ret == 1);
  spindump_deepdebugf("event text = %s (consumed %u bytes)", buf, consumed);
}

//
// Unittests -- spindump_event_parser_json
//

static void
unittests_jsonparser(void) {
}

//
// The tests -- system tests
//

static void
systemtests(void) {
  
  //
  // Analyzer tests -- ICMP
  //
  
  struct spindump_analyze* analyzer = spindump_analyze_initialize();
  spindump_checktest(analyzer != 0);
  struct spindump_packet packet1;
  struct spindump_connection* connection1 = 0;
  memset(&packet1,0,sizeof(packet1));
  const unsigned char packet1bytes[] = {
    // Ethernet header
    0x1c, 0x87, 0x2c, 0x5f, 0x28, 0x1b, 0xdc, 0xa9, 0x04, 0x92, 0x22, 0xb4, 0x86, 0xdd,
    // IPv6 header
    0x60, 0x08, 0xaf, 0xa7, 0x00, 0x10, 0x3a, 0x40,
    // IPv6 source address
    0x20, 0x01, 0x1b, 0xc8, 0x01, 0x01, 0xe9, 0x00, 0x84, 0x96, 0xc2, 0xfb, 0xc4, 0x62, 0xf6, 0x49,
    // IPv6 destination address
    0x20, 0x01, 0x06, 0x7c, 0x02, 0xb0, 0x01, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x94,
    // ICMPv6 header: type, code, csum
    0x80, 0x00, 0x1d, 0x59,
    // ICMPv6 echo header: id, seq, data
    0xb4, 0xee, 0x00, 0x00,
    0x5c, 0x4a, 0xb5, 0x1d, 0x00, 0x0d, 0x47, 0x6c
  };
  
  packet1.timestamp.tv_usec = 0;
  packet1.contents = packet1bytes;
  packet1.etherlen = sizeof(packet1bytes);
  packet1.caplen = packet1.etherlen;
  spindump_analyze_process(analyzer,spindump_capture_linktype_ethernet,&packet1,&connection1);
  
  spindump_checktest(connection1 != 0);
  spindump_checktest(connection1->type == spindump_connection_transport_icmp);
  spindump_checktest(connection1->state == spindump_connection_state_establishing);
  
  struct spindump_packet packet2;
  memset(&packet2,0,sizeof(packet2));
  const unsigned char packet2bytes[] = {
    // Ethernet header
    0xdc, 0xa9, 0x04, 0x92, 0x22, 0xb4, 0x1c, 0x87, 0x2c, 0x5f, 0x28, 0x1b, 0x86, 0xdd,
    // IPv6 header
    0x62, 0x00, 0x00, 0x00, 0x00, 0x10, 0x3a, 0x35,
    // IPv6 source address
    0x20, 0x01, 0x06, 0x7c, 0x02, 0xb0, 0x01, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x94,
    // IPv6 destination address
    0x20, 0x01, 0x1b, 0xc8, 0x01, 0x01, 0xe9, 0x00, 0x84, 0x96, 0xc2, 0xfb, 0xc4, 0x62, 0xf6, 0x49,
    // ICMPv6 header: type, code, csum
    0x81, 0x00, 0x1c, 0x59,
    // ICMPv6 echo header: id, seq, data
    0xb4, 0xee, 0x00, 0x00,
    0x5c, 0x4a, 0xb5, 0x1d, 0x00, 0x0d, 0x47, 0x6c
  };
  packet2.timestamp.tv_usec = 1;
  packet2.contents = packet2bytes;
  packet2.etherlen = sizeof(packet2bytes);
  packet2.caplen = packet2.etherlen;
  connection1 = 0;
  spindump_analyze_process(analyzer,spindump_capture_linktype_ethernet,&packet2,&connection1);
  
  spindump_checktest(connection1 != 0);
  spindump_checktest(connection1->type == spindump_connection_transport_icmp);
  spindump_checktest(connection1->state == spindump_connection_state_established);
  spindump_checktest(connection1->packetsFromSide1 == 1);
  spindump_checktest(connection1->packetsFromSide2 == 1);
  spindump_checktest(connection1->bytesFromSide1 == sizeof(packet1bytes) - spindump_ethernet_header_size);
  spindump_checktest(connection1->bytesFromSide2 == sizeof(packet2bytes) - spindump_ethernet_header_size);
  spindump_checktest(connection1->leftRTT.lastRTT == spindump_rtt_infinite);
  spindump_checktest(connection1->rightRTT.lastRTT == 1);
  
  //
  // Analyzer tests -- ICMP in the other direction (side 2 being the initiator)
  //
  
  struct spindump_packet packet3;
  struct spindump_connection* connection2 = 0;
  memset(&packet3,0,sizeof(packet3));
  const unsigned char packet3bytes[] = {
    // Ethernet header
    0xdc, 0xa9, 0x04, 0x92, 0x22, 0xb4, 0x1c, 0x87, 0x2c, 0x5f, 0x28, 0x1b, 0x86, 0xdd,
    // IPv6 header
    0x62, 0x00, 0x00, 0x00, 0x00, 0x10, 0x3a, 0x35,
    // IPv6 source address
    0x20, 0x01, 0x06, 0x7c, 0x02, 0xb0, 0x01, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x94,
    // IPv6 destination address
    0x20, 0x01, 0x1b, 0xc8, 0x01, 0x01, 0xe9, 0x00, 0x84, 0x96, 0xc2, 0xfb, 0xc4, 0x62, 0xf6, 0x49,
    // ICMPv6 header: type, code, csum
    0x80, 0x00, 0x1d, 0x59,
    // ICMPv6 echo header: id, seq, data
    0xb4, 0xee, 0x00, 0x00,
    0x5c, 0x4a, 0xb5, 0x1d, 0x00, 0x0d, 0x47, 0x6c
  };
  
  packet3.timestamp.tv_usec = 0;
  packet3.contents = packet3bytes;
  packet3.etherlen = sizeof(packet3bytes);
  packet3.caplen = packet3.etherlen;
  spindump_analyze_process(analyzer,spindump_capture_linktype_ethernet,&packet3,&connection2);
  
  spindump_checktest(connection2 != 0);
  spindump_checktest(connection2 != connection1);
  spindump_checktest(connection2->type == spindump_connection_transport_icmp);
  spindump_checktest(connection2->state == spindump_connection_state_establishing);
  
  struct spindump_packet packet4;
  memset(&packet4,0,sizeof(packet4));
  const unsigned char packet4bytes[] = {
    // Ethernet header
    0x1c, 0x87, 0x2c, 0x5f, 0x28, 0x1b, 0xdc, 0xa9, 0x04, 0x92, 0x22, 0xb4, 0x86, 0xdd,
    // IPv6 header
    0x60, 0x08, 0xaf, 0xa7, 0x00, 0x10, 0x3a, 0x40,
    // IPv6 source address
    0x20, 0x01, 0x1b, 0xc8, 0x01, 0x01, 0xe9, 0x00, 0x84, 0x96, 0xc2, 0xfb, 0xc4, 0x62, 0xf6, 0x49,
    // IPv6 destination address
    0x20, 0x01, 0x06, 0x7c, 0x02, 0xb0, 0x01, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x94,
    // ICMPv6 header: type, code, csum
    0x81, 0x00, 0x1c, 0x59,
    // ICMPv6 echo header: id, seq, data
    0xb4, 0xee, 0x00, 0x00,
    0x5c, 0x4a, 0xb5, 0x1d, 0x00, 0x0d, 0x47, 0x6c
  };
  packet4.timestamp.tv_usec = 1;
  packet4.contents = packet4bytes;
  packet4.etherlen = sizeof(packet4bytes);
  packet4.caplen = packet4.etherlen;
  connection2 = 0;
  spindump_analyze_process(analyzer,spindump_capture_linktype_ethernet,&packet4,&connection2);
  
  spindump_checktest(connection2 != 0);
  spindump_checktest(connection2 != connection1);
  spindump_checktest(connection2->type == spindump_connection_transport_icmp);
  spindump_checktest(connection2->state == spindump_connection_state_established);
  spindump_checktest(connection2->packetsFromSide1 == 1);
  spindump_checktest(connection2->packetsFromSide2 == 1);
  spindump_checktest(connection2->bytesFromSide1 == sizeof(packet3bytes) - spindump_ethernet_header_size);
  spindump_checktest(connection2->bytesFromSide2 == sizeof(packet4bytes) - spindump_ethernet_header_size);
  spindump_checktest(connection2->leftRTT.lastRTT == spindump_rtt_infinite);
  spindump_checktest(connection2->rightRTT.lastRTT == 1);
  
  //
  // Analyzer tests -- DNS
  //
  
  struct spindump_packet packet5;
  struct spindump_connection* connection3 = 0;
  memset(&packet5,0,sizeof(packet5));
  const unsigned char packet5bytes[] = {
    // Ethernet header
    0x00, 0x10, 0xdb, 0xff, 0x20, 0x02, 0xdc, 0xa9, 0x04, 0x92, 0x22, 0xb4, 0x08, 0x00,
    // IPv4 header
    0x45, 0x00, 0x00, 0x35, 0x45, 0xa8, 0x00, 0x00, 0x40, 0x11, 0xb2, 0xee,
    // IPv4 source address
    0xac, 0x1e, 0xc5, 0xf3,
    // IPv4 destination address
    0x08, 0x08, 0x08, 0x08, 
    // UPD header
    0xd6, 0x58, 0x00, 0x35, 0x00, 0x21, 0xc9, 0xc1,
    // DNS
    0xf5, 0x97, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x63, 0x6e, 0x6e, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00,
    0x01
  };
  
  packet5.timestamp.tv_usec = 0;
  packet5.contents = packet5bytes;
  packet5.etherlen = sizeof(packet5bytes);
  packet5.caplen = packet5.etherlen;
  spindump_analyze_process(analyzer,spindump_capture_linktype_ethernet,&packet5,&connection3);
  
  spindump_checktest(connection3 != 0);
  spindump_checktest(connection3->type == spindump_connection_transport_dns);
  spindump_checktest(connection3->state == spindump_connection_state_establishing);
  
  struct spindump_packet packet6;
  memset(&packet6,0,sizeof(packet6));
  const unsigned char packet6bytes[] = {
    // Ethernet header
    0xdc, 0xa9, 0x04, 0x92, 0x22, 0xb4, 0x00, 0x10, 0xdb, 0xff, 0x20, 0x02, 0x08, 0x00,
    // IPv4 header
    0x45, 0x00, 0x00, 0x75, 0x8d, 0x5e, 0x00, 0x00, 0x79, 0x11, 0x31, 0xf8, 
    // IPv4 source address
    0x08, 0x08, 0x08, 0x08,
    // IPv4 destination address
    0xac, 0x1e, 0xc5, 0xf3,
    // UDP
    0x00, 0x35, 0xd6, 0x58, 0x00, 0x61, 0x11, 0xda,
    // DNS
    0xf5, 0x97, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x03, 0x63, 0x6e, 0x6e,
    0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x12, 0x00, 0x04, 0x97, 0x65, 0x01, 0x43, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x12, 0x00, 0x04, 0x97, 0x65, 0x81, 0x43, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x12, 0x00, 0x04, 0x97, 0x65, 0xc1, 0x43, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x12, 0x00, 0x04, 0x97, 0x65, 0x41, 0x43
  };
  packet6.timestamp.tv_usec = 1;
  packet6.contents = packet6bytes;
  packet6.etherlen = sizeof(packet6bytes);
  packet6.caplen = packet6.etherlen;
  connection3 = 0;
  spindump_analyze_process(analyzer,spindump_capture_linktype_ethernet,&packet6,&connection3);
  
  spindump_checktest(connection3 != 0);
  spindump_checktest(connection3->type == spindump_connection_transport_dns);
  spindump_checktest(connection3->state == spindump_connection_state_closed);
  spindump_checktest(connection3->packetsFromSide1 == 1);
  spindump_checktest(connection3->packetsFromSide2 == 1);
  spindump_checktest(connection3->bytesFromSide1 == sizeof(packet5bytes) - spindump_ethernet_header_size);
  spindump_checktest(connection3->bytesFromSide2 == sizeof(packet6bytes) - spindump_ethernet_header_size);
  spindump_checktest(connection3->leftRTT.lastRTT == spindump_rtt_infinite);
  spindump_checktest(connection3->rightRTT.lastRTT == 1);
  
  //
  // Analyzer tests -- DNS from the other direction
  //
  
  struct spindump_packet packet7;
  struct spindump_connection* connection4 = 0;
  memset(&packet7,0,sizeof(packet7));
  const unsigned char packet7bytes[] = {
    // Ethernet header
    0xdc, 0xa9, 0x04, 0x92, 0x22, 0xb4, 0x00, 0x10, 0xdb, 0xff, 0x20, 0x02, 0x08, 0x00,
    // IPv4 header
    0x45, 0x00, 0x00, 0x35, 0x8d, 0x5e, 0x00, 0x00, 0x79, 0x11, 0x31, 0xf8, 
    // IPv4 source address
    0x08, 0x08, 0x08, 0x08,
    // IPv4 destination address
    0xac, 0x1e, 0xc5, 0xf3,
    // UDP
    0xd6, 0x58, 0x00, 0x35, 0x00, 0x21, 0xc9, 0xc1,
    // DNS
    0xf5, 0x97, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x63, 0x6e, 0x6e, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00,
    0x01
  };
  
  packet7.timestamp.tv_usec = 0;
  packet7.contents = packet7bytes;
  packet7.etherlen = sizeof(packet7bytes);
  packet7.caplen = packet7.etherlen;
  spindump_analyze_process(analyzer,spindump_capture_linktype_ethernet,&packet7,&connection4);
  
  spindump_checktest(connection4 != 0);
  spindump_checktest(connection4 != connection3);
  spindump_checktest(connection4->type == spindump_connection_transport_dns);
  spindump_checktest(connection4->state == spindump_connection_state_establishing);
  
  struct spindump_packet packet8;
  memset(&packet8,0,sizeof(packet8));
  const unsigned char packet8bytes[] = {
    // Ethernet header
    0x00, 0x10, 0xdb, 0xff, 0x20, 0x02, 0xdc, 0xa9, 0x04, 0x92, 0x22, 0xb4, 0x08, 0x00,
    // IPv4 header
    0x45, 0x00, 0x00, 0x75, 0x45, 0xa8, 0x00, 0x00, 0x40, 0x11, 0xb2, 0xee,
    // IPv4 source address
    0xac, 0x1e, 0xc5, 0xf3,
    // IPv4 destination address
    0x08, 0x08, 0x08, 0x08, 
    // UPD header
    0x00, 0x35, 0xd6, 0x58, 0x00, 0x61, 0x11, 0xda,
    // DNS
    0xf5, 0x97, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x03, 0x63, 0x6e, 0x6e,
    0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x12, 0x00, 0x04, 0x97, 0x65, 0x01, 0x43, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x12, 0x00, 0x04, 0x97, 0x65, 0x81, 0x43, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x12, 0x00, 0x04, 0x97, 0x65, 0xc1, 0x43, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x12, 0x00, 0x04, 0x97, 0x65, 0x41, 0x43
  };
  packet8.timestamp.tv_usec = 1;
  packet8.contents = packet8bytes;
  packet8.etherlen = sizeof(packet8bytes);
  packet8.caplen = packet8.etherlen;
  connection4 = 0;
  spindump_analyze_process(analyzer,spindump_capture_linktype_ethernet,&packet8,&connection4);
  
  spindump_checktest(connection4 != 0);
  spindump_checktest(connection4 != connection3);
  spindump_checktest(connection4->type == spindump_connection_transport_dns);
  spindump_checktest(connection4->state == spindump_connection_state_closed);
  spindump_checktest(connection4->packetsFromSide1 == 1);
  spindump_checktest(connection4->packetsFromSide2 == 1);
  spindump_checktest(connection4->bytesFromSide1 == sizeof(packet7bytes) - spindump_ethernet_header_size);
  spindump_checktest(connection4->bytesFromSide2 == sizeof(packet8bytes) - spindump_ethernet_header_size);
  spindump_checktest(connection4->leftRTT.lastRTT == spindump_rtt_infinite);
  spindump_checktest(connection4->rightRTT.lastRTT == 1);

  //
  // Analyzer tests -- capture length being first not the whole packet
  // and then too small to contain an IP header.
  //
  
  struct spindump_packet packet9;
  struct spindump_connection* connection5 = 0;
  memset(&packet9,0,sizeof(packet9));
  
  spindump_checktest(spindump_analyze_getstats(analyzer)->notEnoughPacketForIpHdr == 0);
  
  packet9.timestamp.tv_usec = 0;
  packet9.contents = packet1bytes;
  packet9.etherlen = sizeof(packet1bytes);
  packet9.caplen = packet1.etherlen - 4; // miss the last bytes of the ICMPv6, should not matter
  spindump_analyze_process(analyzer,spindump_capture_linktype_ethernet,&packet9,&connection5);
  
  spindump_checktest(connection5 != 0);

  connection5 = 0;
  packet9.timestamp.tv_usec = 0;
  packet9.contents = packet1bytes;
  packet9.etherlen = sizeof(packet1bytes);
  packet9.caplen = packet1.etherlen - 20; // miss plenty, including some of the IPv6 header, should be an error
  spindump_analyze_process(analyzer,spindump_capture_linktype_ethernet,&packet9,&connection5);
  
  spindump_checktest(connection5 == 0);
  spindump_checktest(spindump_analyze_getstats(analyzer)->notEnoughPacketForIpHdr == 1);

  //
  // Analyzer tests -- check that IP header size is validated before trying accessing the data.
  // Note that external tool such as valgrind or address sanitizer is required to detect potential
  // flaws.
  //
  const unsigned char shortipv4packetbytes[] = {
    // Ethernet header
    0xdc, 0xa9, 0x04, 0x92, 0x22, 0xb4, 0x00, 0x10, 0xdb, 0xff, 0x20, 0x02, 0x08, 0x00,
    // IPv4 header (too short)
    0x45, 0x00, 0x00, 0x35, 0x8d
  };

  // Allocate memory from heap in order to easily detect the error with tools
  unsigned char* bytesheap = malloc(sizeof(shortipv4packetbytes));
  spindump_assert(bytesheap != 0);
  memcpy(bytesheap, shortipv4packetbytes, sizeof(shortipv4packetbytes));

  struct spindump_packet packet10;
  memset(&packet10, 0, sizeof(packet10));
  connection5 = 0;

  packet10.timestamp.tv_usec = 0;
  packet10.contents = bytesheap;
  packet10.etherlen = sizeof(shortipv4packetbytes);
  packet10.caplen = packet10.etherlen;

  spindump_analyze_process(analyzer,spindump_capture_linktype_ethernet,&packet10,&connection5);
  // In addition to this test, the program should be run with memory analyzer such as valgrind
  // to detect possible memory problems
  spindump_checktest(connection5 == 0);
  free(bytesheap);

  const unsigned char shortipv6packetbytes[] = {
    // Ethernet header
    0x1c, 0x87, 0x2c, 0x5f, 0x28, 0x1b, 0xdc, 0xa9, 0x04, 0x92, 0x22, 0xb4, 0x86, 0xdd,
    // IPv6 header
    0x60, 0x08, 0xaf, 0xa7, 0x00, 0x10, 0x3a,
  };

  // Allocate memory from heap in order to easily detect the error with tools
  bytesheap = malloc(sizeof(shortipv6packetbytes));
  spindump_assert(bytesheap != 0);
  memcpy(bytesheap, shortipv6packetbytes, sizeof(shortipv6packetbytes));

  memset(&packet10, 0, sizeof(packet10));
  connection5 = 0;
  packet10.timestamp.tv_usec = 0;
  packet10.contents = bytesheap;
  packet10.etherlen = sizeof(shortipv6packetbytes);
  packet10.caplen = packet10.etherlen;

  spindump_analyze_process(analyzer,spindump_capture_linktype_ethernet,&packet10,&connection5);
  // In addition to this test, the program should be run with memory analyzer such as valgrind
  // to detect possible memory problems
  spindump_checktest(connection5 == 0);
  free(bytesheap);

  //
  // Analyzer tests -- packets too small. Firsttoo small to contain an
  // Ethernet header. Then too small to contain a full ICMP message.
  //
  
  connection5 = 0;
  packet9.timestamp.tv_usec = 0;
  packet9.contents = packet1bytes;
  packet9.etherlen = 12; // miss plenty, including all of IP and some of Ethernet header
  packet9.caplen = packet9.etherlen; 
  spindump_analyze_process(analyzer,spindump_capture_linktype_ethernet,&packet9,&connection5);
  
  spindump_checktest(connection5 == 0);
  spindump_checktest(spindump_analyze_getstats(analyzer)->notEnoughPacketForEthernetHdr == 1);
  
  connection5 = 0;
  packet9.timestamp.tv_usec = 0;
  packet9.contents = packet1bytes;
  packet9.etherlen = packet1.etherlen;
  packet9.caplen = 56; // include just two bytes of the ICMP part (14+40=54)
  spindump_analyze_process(analyzer,spindump_capture_linktype_ethernet,&packet9,&connection5);
  
  spindump_checktest(connection5 == 0);
  spindump_checktest(spindump_analyze_getstats(analyzer)->notEnoughPacketForIcmpHdr == 1);
  
  connection5 = 0;
  packet9.timestamp.tv_usec = 0;
  packet9.contents = packet1bytes;
  packet9.etherlen = packet1.etherlen;
  packet9.caplen = 58; // include ICMP header but no other parts (14+40=54)
  spindump_analyze_process(analyzer,spindump_capture_linktype_ethernet,&packet9,&connection5);
  
  spindump_checktest(connection5 == 0);
  spindump_checktest(spindump_analyze_getstats(analyzer)->notEnoughPacketForIcmpHdr == 2);

  //
  // Cleanup
  //
  
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
      
      spindump_debug = 1;
      
    } else if (strcmp(argv[0],"--no-debug") == 0) {
      
      spindump_debug = 0;
      spindump_deepdebug = 0;
      spindump_deepdeepdebug = 0;
      
    } else if (strcmp(argv[0],"--deepdebug") == 0) {
      
      spindump_debug = 1;
      spindump_deepdebug = 1;
      
    } else if (strcmp(argv[0],"--no-deepdebug") == 0) {
      
      spindump_deepdebug = 0;
      spindump_deepdeepdebug = 0;

    } else if (strcmp(argv[0],"--deepdeepdebug") == 0) {

      spindump_debug = 1;
      spindump_deepdebug = 1;
      spindump_deepdeepdebug = 1;
      
    } else if (strcmp(argv[0],"--no-deepdeepdebug") == 0) {
      
      spindump_deepdeepdebug = 0;
      
    } else {

      spindump_errorf("invalid argument: %s", argv[0]);
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
  
