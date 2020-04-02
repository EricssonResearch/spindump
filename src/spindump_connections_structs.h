
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
#include "spindump_tags.h"
#include "spindump_sctp_tsn.h"
#include "spindump_bandwidth.h"
#include "spindump_spin_structs.h"
#include "spindump_titalia_rtloss_structs.h"
#include "spindump_titalia_qrloss_structs.h"
#include "spindump_orange_qlloss_structs.h"

//
// Parameters ---------------------------------------------------------------------------------
//

#define spindump_connection_max_handlers 32         // should be equivalent to spindump_analyze_max_handlers

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
  spindump_connection_transport_sctp,
  spindump_connection_aggregate_hostpair,
  spindump_connection_aggregate_hostnetwork,
  spindump_connection_aggregate_networknetwork,
  spindump_connection_aggregate_multicastgroup,
  spindump_connection_aggregate_hostmultinet,
  spindump_connection_aggregate_networkmultinet
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
#define spindump_connection_quic_cid_maxlen                     18

struct spindump_quic_connectionid {
  unsigned int len;
  unsigned char id[spindump_connection_quic_cid_maxlen];
  unsigned char padding[2]; // unused padding, to align the structure size properly
};

struct spindump_connection_set {
  unsigned int nConnections;
  unsigned int maxNConnections;
  struct spindump_connection** set;
};

typedef uint64_t spindump_handler_mask;

struct spindump_connection {

  unsigned int id;                                  // sequentially allocated descriptive id for the connection
  enum spindump_connection_type type;               // the type of the connection (tcp, icmp, aggregate, etc)
  enum spindump_connection_state state;             // current state (establishing/established/etc)
  int manuallyCreated;                              // was this entry created by management action or dynamically?
  int remote;                                       // was this entry created by a remote Spindump instance?
  int deleted;                                      // is the connection closed/deleted (but not yet removed)?
  spindump_tags tags;                               // tags associated with the connection
  uint8_t padding[4];                               // unused padding to align the next field properly
  struct timeval creationTime;                      // when did we see the first packet?
  struct timeval latestPacketFromSide1;             // when did we see the last packet from side 1?
  struct timeval latestPacketFromSide2;             // when did we see the last packet from side 2?
  spindump_counter_64bit packetsFromSide1;          // packet counts
  spindump_counter_64bit packetsFromSide2;          // packet counts
  struct spindump_bandwidth bytesFromSide1;         // byte counts
  struct spindump_bandwidth bytesFromSide2;         // byte counts
  spindump_counter_64bit ect0FromInitiator;         // ECN ECT(0) counts
  spindump_counter_64bit ect0FromResponder;         // ECN ECT(0) counts
  spindump_counter_64bit ect1FromInitiator;         // ECN ECT(1) counts
  spindump_counter_64bit ect1FromResponder;         // ECN ECT(1) counts
  spindump_counter_64bit ceFromInitiator;           // ECN CE counts
  spindump_counter_64bit ceFromResponder;           // ECN CE counts
  struct spindump_rtloss rtLossesFrom1to2;          // RT lossrate measured in UL
  struct spindump_rtloss rtLossesFrom2to1;          // RT lossrate measured in DL
  float qLossesFrom1to2;                            // Square bit lossrate measured in UL
  float qLossesFrom2to1;                            // Square bit lossrate measured in DL
  float rLossesFrom1to2;                            // Retransmit bit lossrate measured in UL
  float rLossesFrom2to1;                            // Retransmit bit lossrate measured in DL
  struct spindump_rtt leftRTT;                      // left-side (side 1) RTT calculations
  struct spindump_rtt rightRTT;                     // right-side (side 2) RTT calculations
  struct spindump_rtt respToInitFullRTT;            // end-to-end RTT calculations observed from responder
  struct spindump_rtt initToRespFullRTT;            // end-to-end RTT calculations observed from initiator
  struct spindump_connection_set aggregates;        // aggregate connection sets where this connection belongs to
  spindump_handler_mask handlerMask;                // handler bit mask for connection-specific handlers
  void* handlerConnectionDatas
        [spindump_connection_max_handlers];         // data store for registered handlers to add data to a connection

  union {

    struct {
      spindump_address side1peerAddress;            // source address for the initial packet
      spindump_address side2peerAddress;            // destination address for the initial packet
      spindump_port side1peerPort;                  // source port for the initial packe
      spindump_port side2peerPort;                  // destination port for the initial packet
      uint8_t padding[4];                           // unused
      struct spindump_seqtracker side1Seqs;         // when did we see sequence numbers from side1?
      struct spindump_seqtracker side2Seqs;         // when did we see sequence numbers from side2?
      int finFromSide1;                             // seen a FIN from side1?
      int finFromSide2;                             // seen a FIN from side2?
    } tcp;

    struct {
      spindump_address side1peerAddress;            // source address for the initial packet
      spindump_address side2peerAddress;            // destination address for the initial packet
      spindump_port side1peerPort;                  // source port for the initial packe
      spindump_port side2peerPort;                  // destination port for the initial packet
      uint32_t side1Vtag;                           // Vtag of association for side1
      uint32_t side2Vtag;                           // Vtag of association for side2
      struct spindump_tsntracker side1Seqs;         // when did we see sequence numbers from side1?
      struct spindump_tsntracker side2Seqs;         // when did we see sequence numbers from side2?
      //uint8_t padding[4];                           // unused
      uint8_t side1HbCnt;                           // Number of HBs inflight seen from side 1
      struct timeval side1hbTime;                   // the time of the last HB seen from side 1
      uint8_t side2HbCnt;                           // Number of HBs inflight seen from side 2
      struct timeval side2hbTime;                   // the time of the last HB seen from side 2
    } sctp;

    struct {
      spindump_address side1peerAddress;            // source address for the initial packet
      spindump_address side2peerAddress;            // destination address for the initial packet
      spindump_port side1peerPort;                  // source port for the initial packe
      spindump_port side2peerPort;                  // destination port for the initial packet
      uint8_t padding[4];                           // unused padding to align the structure size properly
    } udp;

    struct {
      spindump_address side1peerAddress;            // source address for the initial packet
      spindump_address side2peerAddress;            // destination address for the initial packet
      spindump_port side1peerPort;                  // source port for the initial packe
      spindump_port side2peerPort;                  // destination port for the initial packet
      uint8_t padding[4];                           // unused padding to align the next field properly
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
      uint8_t padding[6];                           // unused padding to align the next field properly
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
      int attempted0Rtt;                            // whether connection attempted to use 0-RTT setup
      struct timeval side1initialPacket;            // the time of the initial packet from side 1
      struct timeval side2initialResponsePacket;    // the time of the initial response packet from side 2
      unsigned long initialRightRTT;                // initial packet exchange RTT in us
      unsigned long initialLeftRTT;                 // initial packet exchange RTT in us (only available sometimes)
      struct spindump_spintracker spinFromPeer1to2; // tracking spin bit flips from side 1 to 2
      struct spindump_spintracker spinFromPeer2to1; // tracking spin bit flips from side 2 to 1
      struct spindump_rtloss1tracker rtloss1FromPeer1to2;  // tracking round trip loss (1 bit) from side 1 to 2
      struct spindump_rtloss1tracker rtloss1FromPeer2to1;  // tracking round trip loss (1 bit) from side 2 to 1
      struct spindump_rtloss2tracker rtloss2FromPeer1to2;  // tracking round trip loss (2 bits) from side 1 to 2
      struct spindump_rtloss2tracker rtloss2FromPeer2to1;  // tracking round trip loss (2 bits) from side 2 to 1
      struct spindump_qrlosstracker qrFromPeer1to2;        // tracking T.Italia QR from side 1 to 2
      struct spindump_qrlosstracker qrFromPeer2to1;        // tracking T.Italia QR from side 2 to 1
      struct spindump_qllosstracker qlFromPeer1to2;        // tracking Orange QL from side 1 to 2
      struct spindump_qllosstracker qlFromPeer2to1;        // tracking Orange QL from side 2 to 1
      struct spindump_qrloss qrLossesFrom1to2;        // T.Italia QR lossrate measured from side 1 to 2
      struct spindump_qrloss qrLossesFrom2to1;        // T.Italia QR lossrate measured from side 2 to 1
      //uint8_t padding2[8];                          // unused padding to align the structure size properly
    } quic;

    struct {
      spindump_address side1peerAddress;            // source address for the initial packet
      spindump_address side2peerAddress;            // destination address for the initial packet
      uint8_t side1peerType;                        // the ICMP type used in a request from side 1
      uint8_t padding1;                             // unused padding to align the next field properly
      uint16_t side1peerId;                         // the ICMP id used in a request from side 1
      struct spindump_messageidtracker side1Seqs;   // latest sequence numbers from side1
      uint8_t padding2[2];                          // unused padding to align the size of the structure properly
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
      int defaultMatch;                             // match only if no other aggregates match
    } aggregatenetworknetwork;

    struct {
      spindump_address group;                       // multicast group address
      struct spindump_connection_set connections;   // what actual connections fall under this aggregate
    } aggregatemulticastgroup;

    struct {
      spindump_address side1peerAddress;            // address of host on side 1
      struct spindump_connection_set connections;   // what actual connections fall under this aggregate
    } aggregatehostmultinet;

    struct {
      spindump_network side1Network;                // network address on side 1
      struct spindump_connection_set connections;   // what actual connections fall under this aggregate
    } aggregatenetworkmultinet;

  } u;

};

struct spindump_connection_network {
     spindump_network side2Network;                 // network address on side 2
     struct spindump_connection *connection;        // what aggregate connection this network belongs to
};

enum spindump_connection_searchcriteria_srcdst {
  spindump_connection_searchcriteria_srcdst_none = 0,
  spindump_connection_searchcriteria_srcdst_sourceonly = 1,
  spindump_connection_searchcriteria_srcdst_destinationonly = 2,
  spindump_connection_searchcriteria_srcdst_both = 3,
  spindump_connection_searchcriteria_srcdst_both_allowreverse = 4,
  spindump_connection_searchcriteria_srcdst_both_hostnetwork = 5,
  spindump_connection_searchcriteria_srcdst_both_networknetwork = 6
};

struct spindump_connection_searchcriteria {

  int matchType;
  enum spindump_connection_type type;

  int matchIcmpType;
  uint8_t icmpType;
  uint8_t padding1[3]; // unused padding to align the next field properly

  int matchIcmpId;
  uint16_t icmpId;
  uint8_t padding2[2]; // unused padding to align the next field properly

  enum spindump_connection_searchcriteria_srcdst matchAddresses;
  uint8_t padding3[4]; // unused padding to align the next field properly
  spindump_address side1address;
  spindump_address side2address;
  spindump_network side1network;
  spindump_network side2network;

  enum spindump_connection_searchcriteria_srcdst matchPorts;
  spindump_port side1port;
  spindump_port side2port;

  enum spindump_connection_searchcriteria_srcdst matchQuicCids;
  struct spindump_quic_connectionid side1connectionId;
  struct spindump_quic_connectionid side2connectionId;

  int matchPartialDestinationCid;
  const unsigned char* partialDestinationCid;

  int matchPartialSourceCid;
  uint8_t padding4[4]; // unused padding to align the next field properly
  const unsigned char* partialSourceCid;
};

#endif // SPINDUMP_CONNECTIONS_STRUCTS_H
