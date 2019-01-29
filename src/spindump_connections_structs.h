
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

#ifndef SPINDUMP_CONNECTIONS_STRUCTS_H
#define SPINDUMP_CONNECTIONS_STRUCTS_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/in.h>
#include "spindump_util.h"
#include "spindump_rtt.h"
#include "spindump_seq.h"
#include "spindump_mid.h"
#include "spindump_spin_structs.h"

//
// Parameters ---------------------------------------------------------------------------------
//

#define spindump_connection_max_handlers 10         // should be equivalent to spindump_analyze_max_handlers

//
// Data structures ----------------------------------------------------------------------------
//

enum spindump_connection_type {
  spindump_connection_transport_tcp,
  spindump_connection_transport_udp,
  spindump_connection_transport_dns,
  spindump_connection_transport_coap,
  spindump_connection_transport_quic,
  spindump_connection_transport_icmp,
  spindump_connection_aggregate_hostpair,
  spindump_connection_aggregate_hostnetwork,
  spindump_connection_aggregate_networknetwork,
  spindump_connection_aggregate_multicastgroup
};

enum spindump_connection_state {
  spindump_connection_state_establishing,
  spindump_connection_state_established,
  spindump_connection_state_closing,
  spindump_connection_state_closed,
  spindump_connection_state_static
};

#define spindump_connection_deleted_timeout         (10*1000*1000) // us
#define spindump_connection_establishing_timeout    (30*1000*1000) // us
#define spindump_connection_inactive_timeout       (180*1000*1000) // us

struct spindump_quic_connectionid {
  unsigned int len;
  unsigned char id[18];
};

struct spindump_connection_set {
  unsigned int nConnections;
  unsigned int maxNConnections;
  struct spindump_connection** set;
};

struct spindump_connection {

  unsigned int id;                                  // sequentially allocated descriptive id for the connection
  enum spindump_connection_type type;               // the type of the connection (tcp, icmp, aggregate, etc)
  enum spindump_connection_state state;             // current state (establishing/established/etc)
  int manuallyCreated;                              // was this entry created by management action or dynamically?
  int deleted;                                      // is the connection closed/deleted (but not yet removed)?
  struct timeval creationTime;                      // when did we see the first packet?
  struct timeval latestPacketFromSide1;             // when did we see the last packet from side 1?
  struct timeval latestPacketFromSide2;             // when did we see the last packet from side 2?
  unsigned int packetsFromSide1;                    // packet counts
  unsigned int packetsFromSide2;                    // packet counts
  unsigned int bytesFromSide1;                      // byte counts
  unsigned int bytesFromSide2;                      // byte counts
  struct spindump_rtt leftRTT;                      // left-side (side 1) RTT calculations
  struct spindump_rtt rightRTT;                     // right-side (side 2) RTT calculations
  struct spindump_connection_set aggregates;        // aggregate connection sets where this connection belongs to
  void* handlerConnectionDatas
        [spindump_connection_max_handlers];         // data store for registered handlers to add data to a connection
  
  union {
    
    struct {
      spindump_address side1peerAddress;            // source address for the initial packet
      spindump_address side2peerAddress;            // destination address for the initial packet
      spindump_port side1peerPort;                  // source port for the initial packe
      spindump_port side2peerPort;                  // destination port for the initial packet
      int finFromSide1;                             // seen a FIN from side1?
      int finFromSide2;                             // seen a FIN from side2?
      struct spindump_seqtracker side1Seqs;         // when did we see sequence numbers from side1?
      struct spindump_seqtracker side2Seqs;         // when did we see sequence numbers from side2?
    } tcp;
    
    struct {
      spindump_address side1peerAddress;            // source address for the initial packet
      spindump_address side2peerAddress;            // destination address for the initial packet
      spindump_port side1peerPort;                  // source port for the initial packe
      spindump_port side2peerPort;                  // destination port for the initial packet
    } udp;
    
    struct {
      spindump_address side1peerAddress;            // source address for the initial packet
      spindump_address side2peerAddress;            // destination address for the initial packet
      spindump_port side1peerPort;                  // source port for the initial packe
      spindump_port side2peerPort;                  // destination port for the initial packet
      struct spindump_messageidtracker side1MIDs;   // when did we see message IDs from side1?
      struct spindump_messageidtracker side2MIDs;   // when did we see message IDs from side2?
      char lastQueriedName[40];                     // the latest name that was queried
    } dns;
    
    struct {
      spindump_address side1peerAddress;            // source address for the initial packet
      spindump_address side2peerAddress;            // destination address for the initial packet
      spindump_port side1peerPort;                  // source port for the initial packe
      spindump_port side2peerPort;                  // destination port for the initial packet
      int dtls;                                     // is DTLS/TLS in use?
      spindump_tls_version dtlsVersion;             // which DTLS/TLS version is in use
      struct spindump_messageidtracker side1MIDs;   // when did we see message IDs from side1?
      struct spindump_messageidtracker side2MIDs;   // when did we see message IDs from side2?
    } coap;
    
    struct {
      uint32_t version;                             // QUIC version
      uint32_t originalVersion;                     // original, offered QUIC version
      struct
      spindump_quic_connectionid peer1ConnectionID; // source connection id of the initial packet
      struct
      spindump_quic_connectionid peer2ConnectionID; // source connection id of the initial response packet
      spindump_address side1peerAddress;            // source address for the initial packet
      spindump_address side2peerAddress;            // destination address for the initial packet
      spindump_port side1peerPort;                  // source port for the initial packe
      spindump_port side2peerPort;                  // destination port for the initial packet
      struct timeval side1initialPacket;            // the time of the initial packet from side 1
      struct timeval side2initialResponsePacket;    // the time of the initial response packet from side 2
      unsigned long initialRightRTT;                // initial packet exchange RTT in us
      unsigned long initialLeftRTT;                 // initial packet exchange RTT in us (only available sometimes)
      struct spindump_spintracker spinFromPeer1to2; // tracking spin bit flips from side 1 to 2
      struct spindump_spintracker spinFromPeer2to1; // tracking spin bit flips from side 2 to 1
    } quic;
    
    struct {
      spindump_address side1peerAddress;            // source address for the initial packet
      spindump_address side2peerAddress;            // destination address for the initial packet
      u_int8_t side1peerType;                       // the ICMP type used in a request from side 1
      u_int16_t side1peerId;                        // the ICMP id used in a request from side 1
      u_int16_t	side1peerLatestSequence;            // latest seen sequence number from side 1
    } icmp;
    
    struct {
      spindump_address side1peerAddress;            // address of host on side 1
      spindump_address side2peerAddress;            // address of host on side 2
      struct spindump_connection_set connections;   // what actual connections fall under this aggregate
    } aggregatehostpair;
    
    struct {
      spindump_address side1peerAddress;            // address of host on side 1
      spindump_network side2Network;                // network address on side 2
      struct spindump_connection_set connections;   // what actual connections fall under this aggregate
    } aggregatehostnetwork;
    
    struct {
      spindump_network side1Network;                // network address on side 1
      spindump_network side2Network;                // network address on side 2
      struct spindump_connection_set connections;   // what actual connections fall under this aggregate
    } aggregatenetworknetwork;
    
    struct {
      spindump_address group;                       // multicast group address
      struct spindump_connection_set connections;   // what actual connections fall under this aggregate
    } aggregatemulticastgroup;
    
  } u;
  
};

enum spindump_connection_searchcriteria_srcdst {
  spindump_connection_searchcriteria_srcdst_none = 0,
  spindump_connection_searchcriteria_srcdst_destinationonly = 1,
  spindump_connection_searchcriteria_srcdst_both = 2,
  spindump_connection_searchcriteria_srcdst_both_allowreverse = 3
};

struct spindump_connection_searchcriteria {
  
  int matchType;
  enum spindump_connection_type type;

  int matchIcmpType;
  u_int8_t icmpType;

  int matchIcmpId;
  u_int16_t icmpId;

  enum spindump_connection_searchcriteria_srcdst matchAddresses;
  spindump_address side1address;
  spindump_address side2address;
  
  enum spindump_connection_searchcriteria_srcdst matchPorts;
  spindump_port side1port;
  spindump_port side2port;
  
  enum spindump_connection_searchcriteria_srcdst matchQuicCids;
  struct spindump_quic_connectionid side1connectionId;
  struct spindump_quic_connectionid side2connectionId;
  
  int matchPartialDestinationCid;
  const unsigned char* partialDestinationCid;
  
  int matchPartialSourceCid;
  const unsigned char* partialSourceCid;
};

#endif // SPINDUMP_CONNECTIONS_STRUCTS_H
