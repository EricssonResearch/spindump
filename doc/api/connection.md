# Connection  API

The main data structure in Spindump is the connection object. Its usage and examples are described in the [Library API definition](https://github.com/EricssonResearch/spindump/blob/master/Library.md). See also the [Analyzer API](https://github.com/EricssonResearch/spindump/blob/master/doc/api/analyzer.md)

The detailed data structure is as follows:

## API data structure struct spindump_connection

This object represents a single connection observed by the analyzer. The full description of that object needs to be added later, but here are some of the key fields that are relevant:

* connection->type indicates the type of the connection (TCP, ICMP, QUIC, etc)
* connection->creationTime indicates when the first packet for the connection was seen
* connection->packetsFromSide1 counts the number of packets sent from the initiator to the responder 
* connection->packetsFromSide2 counts the number of packets sent from the initiator to the initiator 
* connection->leftRTT is the number of microsends for the RTT part that is between the initiator (client) and the measurement point 
* connection->rightRTT is the number of microsends for the RTT part that is between the responder (server) and the measurement point 

The description is in src/spindump_connections_structs.h and the most relevant pare are reproduced below:

    struct spindump_connection {
      unsigned int id;                                  // sequentially allocated descriptive id for the connection
      enum spindump_connection_type type;               // the type of the connection (tcp, icmp, aggregate, etc)
      enum spindump_connection_state state;             // current state (establishing/established/etc)
      struct timeval creationTime;                      // when did we see the first packet?
      struct timeval latestPacketFromSide1;             // when did we see the last packet from side 1?
      struct timeval latestPacketFromSide2;             // when did we see the last packet from side 2?
      unsigned int packetsFromSide1;                    // packet counts
      unsigned int packetsFromSide2;                    // packet counts
      unsigned int bytesFromSide1;                      // byte counts
      unsigned int bytesFromSide2;                      // byte counts
      unsigned int ect0FromInitiator;                   // ECN ECT(0) counts
      unsigned int ect0FromResponder;                   // ECN ECT(0) counts
      unsigned int ect1FromInitiator;                   // ECN ECT(1) counts
      unsigned int ect1FromResponder;                   // ECN ECT(1) counts
      unsigned int ceFromInitiator;                     // ECN CE counts
      unsigned int ceFromResponder;                     // ECN CE counts
      struct spindump_rtt leftRTT;                      // left-side (side 1) RTT calculations
      struct spindump_rtt rightRTT;                     // right-side (side 2) RTT calculations
      struct spindump_rtt respToInitFullRTT;            // end-to-end RTT calculations observed from responder
      struct spindump_rtt initToRespFullRTT;            // end-to-end RTT calculations observed from initiator
      ...
      union {
    
        struct {
          spindump_address side1peerAddress;            // source address for the initial packet
          spindump_address side2peerAddress;            // destination address for the initial packet
          spindump_port side1peerPort;                  // source port for the initial packe
          spindump_port side2peerPort;                  // destination port for the initial packet
          struct spindump_seqtracker side1Seqs;         // when did we see sequence numbers from side1?
          struct spindump_seqtracker side2Seqs;         // when did we see sequence numbers from side2?
    	  ...
        } tcp;
    
        struct {
          spindump_address side1peerAddress;            // source address for the initial packet
          spindump_address side2peerAddress;            // destination address for the initial packet
          spindump_port side1peerPort;                  // source port for the initial packe
          spindump_port side2peerPort;                  // destination port for the initial packet
          ...
        } udp;
    
        struct {
          spindump_address side1peerAddress;            // source address for the initial packet
          spindump_address side2peerAddress;            // destination address for the initial packet
          spindump_port side1peerPort;                  // source port for the initial packe
          spindump_port side2peerPort;                  // destination port for the initial packet
          struct spindump_messageidtracker side1MIDs;   // when did we see message IDs from side1?
          struct spindump_messageidtracker side2MIDs;   // when did we see message IDs from side2?
          ...
        } dns;
    
        struct {
          spindump_address side1peerAddress;            // source address for the initial packet
          spindump_address side2peerAddress;            // destination address for the initial packet
          spindump_port side1peerPort;                  // source port for the initial packe
          spindump_port side2peerPort;                  // destination port for the initial packet
          struct spindump_messageidtracker side1MIDs;   // when did we see message IDs from side1?
          struct spindump_messageidtracker side2MIDs;   // when did we see message IDs from side2?
    	  ...
        } coap;
    
        struct {
          uint32_t version;                             // QUIC version
          struct
          spindump_quic_connectionid peer1ConnectionID; // source connection id of the initial packet
          struct
          spindump_quic_connectionid peer2ConnectionID; // source connection id of the initial response packet
          spindump_address side1peerAddress;            // source address for the initial packet
          spindump_address side2peerAddress;            // destination address for the initial packet
          spindump_port side1peerPort;                  // source port for the initial packe
          spindump_port side2peerPort;                  // destination port for the initial packet
          unsigned long initialRightRTT;                // initial packet exchange RTT in us
          unsigned long initialLeftRTT;                 // initial packet exchange RTT in us (only available sometimes)
          ... 
        } quic;
    
        struct {
          spindump_address side1peerAddress;            // source address for the initial packet
          spindump_address side2peerAddress;            // destination address for the initial packet
    	  ... 
        } icmp;
    
        struct {
          spindump_address side1peerAddress;            // address of host on side 1
          spindump_address side2peerAddress;            // address of host on side 2
    	  ... 
        } aggregatehostpair;
    
        struct {
          spindump_address side1peerAddress;            // address of host on side 1
          spindump_network side2Network;                // network address on side 2
    	  ... 
        } aggregatehostnetwork;
    
        struct {
          spindump_network side1Network;                // network address on side 1
          spindump_network side2Network;                // network address on side 2
          ...
        } aggregatenetworknetwork;
    
        struct {
          spindump_address group;                       // multicast group address
    	  ... 
        } aggregatemulticastgroup;
    
      } u;
    
    };
