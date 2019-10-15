# Analyzer API

The main API in Spindump is the analyzer library. Its usage and examples are described in the [Library API definition](https://github.com/EricssonResearch/spindump/blob/master/Library.md). See also the [connection object API](https://github.com/EricssonResearch/spindump/blob/master/doc/api/connection.md).

The detailed API functions are as follows:

# Functions

 The following is a detailed description of the library functionality.

## API function spindump_analyze_initialize

This function creates an object to represent an analyzer. It allocates memory as needed. It returns a non-NULL object pointer if the creation was successful, and NULL otherwise.

The prototype:

    struct spindump_analyze*
    spindump_analyze_initialize(void);

## API function spindump_analyze_uninitialize

Destroy the analyzer resources and memory object.

The prototype:

    void
    spindump_analyze_uninitialize(struct spindump_analyze* state);

## API function spindump_analyze_registerhandler

This function should be called to register a handler as discussed above. 

The prototype: 

    void
    spindump_analyze_registerhandler(struct spindump_analyze* state,
    				 spindump_analyze_event eventmask,
    				 struct spindump_connection* connection,
    				 spindump_analyze_handler handler,
    				 void* handlerData);

## API function spindump_analyze_unregisterhandler

This function should be called to de-register a handler that was previously registered.

The prototype: 

    void
    spindump_analyze_unregisterhandler(struct spindump_analyze* state,
    				   spindump_analyze_event eventmask,
    				   struct spindump_connection* connection,
    				   spindump_analyze_handler handler,
    				   void* handlerData);

## API handler callback interface

The user's function gets called when the relevant event happens. The interface is:

    void myhandler(struct spindump_analyze* state,
                   void* handlerData,
                   void** handlerConnectionData,
                   spindump_analyze_event event,
                   struct spindump_packet* packet,
                   struct spindump_connection* connection);

Here "myhandler" is the user's function and it will get as parameters the analyzer object, the handler data pointer supplied upon registration, a pointer to a pointer that the handler can use to store some information relating to this handler for the specific connection in question, the event, a pointer to the packet, and a pointer to the connection object.

Note that the packet may be 0, in case the callback is being made when the packet is not locally available, such as when the update is due to a remotely delivered event.

## Events

The currently defined events that can be caught are:

    #define spindump_analyze_event_newconnection                         1
    #define spindump_analyze_event_changeconnection                      2
    #define spindump_analyze_event_connectiondelete                      4
    #define spindump_analyze_event_newleftrttmeasurement                 8
    #define spindump_analyze_event_newrightrttmeasurement               16
    #define spindump_analyze_event_newinitrespfullrttmeasurement        32
    #define spindump_analyze_event_newrespinitfullrttmeasurement        64
    #define spindump_analyze_event_initiatorspinflip                   128
    #define spindump_analyze_event_responderspinflip                   256
    #define spindump_analyze_event_initiatorspinvalue                  512
    #define spindump_analyze_event_responderspinvalue                 1024
    #define spindump_analyze_event_newpacket                          2048
    #define spindump_analyze_event_firstresponsepacket                4096
    #define spindump_analyze_event_statechange                        8192
    #define spindump_analyze_event_initiatorecnce                    16384
    #define spindump_analyze_event_responderecnce                    32768
    #define spindump_analyze_event_initiatorrtloss1measurement       65536
    #define spindump_analyze_event_responderrtloss1measurement      131072
    #define spindump_analyze_event_initiatorqrlossmeasurement       262144
    #define spindump_analyze_event_responderqrlossmeasurement       524288

These can be mixed together in one handler by ORing them together. The pseudo-event "spindump_analyze_event_alllegal" represents all of the events.

The events are as follows:

### spindump_analyze_event_newconnection

Called when there's a new connection.

### spindump_analyze_event_changeconnection

Called when the 5-tuple or other session identifiers of a connection change.

### spindump_analyze_event_connectiondelete

Called when a connection is terminated explicitly or when it is cleaned up by the analyzer due to lack of activity.

### spindump_analyze_event_newleftrttmeasurement

Called when there's a new RTT measurement between the measurement point and the initiator (client) of a connection. 

### spindump_analyze_event_newrightrttmeasurement

Called when there's a new RTT measurement between the measurement point and the responder (server) of a connection. 

### spindump_analyze_event_newinitrespfullrttmeasurement

Called when there's a new RTT measurement for a QUIC connection, a full roundtrip RTT value is as measured from spin bit flips coming from the initiator (client). 

### spindump_analyze_event_newrespinitfullrttmeasurement

Called when there's a new RTT measurement for a QUIC connection, a full roundtrip RTT value is as measured from spin bit flips coming from the responder (server).

### spindump_analyze_event_initiatorspinflip

Called when there's a spin bit flip coming from the responder (server). 

### spindump_analyze_event_responderspinflip

Called when there's a spin bit flip coming from the initiator (client). 

### spindump_analyze_event_initiatorspinvalue

Called whenever there's a spin bit value in a QUIC connection from the initiator (client).

### spindump_analyze_event_responderspinvalue

Called whenever there's a spin bit value in a QUIC connection from the responder (server).

### spindump_analyze_event_newpacket

Called whenever there's a new packet.

### spindump_analyze_event_firstresponsepacket

Called when a connection attempt has seen the first response packet from the responder.

### spindump_analyze_event_statechange

Called when the state of a connection changes, typically from ESTABLISHING to ESTABLISHED. 

### spindump_analyze_event_initiatorecnce

Called when there's an ECN congestion event from the initiator (client) of a connection. 

### spindump_analyze_event_responderecnce

Called when there's an ECN congestion event from the responder (server) of a connection. 

## Memory allocation

The library allocates memory as needed using malloc and free, and upon calling the analyzer uninitialization function, no allocated memory remains.

Some of the allocation sizes can be changed in the relevant header files or through -D flag settings in the makefiles. For instance, the default number of sequence numbers stored for tracking TCP ACKs and COAP requests is 50, as defined in src/spindump_seq.h:

    #ifndef spindump_seqtracker_nstored
    #define spindump_seqtracker_nstored		50
    #endif

A command line option for the compiler could set this to, say 10:

     -Dspindump_seqtracker_nstored=10

and this would affect the memory consumption for a connection object.

A listing of what parameters can be modified is a currently listed feature request (issue #81), as is some kind of parametrization to allow library user to specify what allocation/free functions to use (issue #82).

