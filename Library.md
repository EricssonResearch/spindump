# Spindump Library

## Introduction

The Spindump software builds on the Spindump Library, a simple but extensibile packet analysis package. The makefile builds a library, libspindump.a that can be linked to a program, used to provide the same statistics as the spindump command does, or even extended to build more advanced functionality. The Spindump command itself is built using this library.

The library can also be used in other ways, e.g., by integrating it to other tools or network devices, to collect some information that is necessary to optimize the device or the network in some fashion, for instance.

![Tool output](https://raw.githubusercontent.com/EricssonResearch/spindump/master/images/architecture2s.jpg)

The library has a number of functions, and can be used to build complex functionality, for instance to send measurement data to a central collection point. But the basics of the library are very simple, feeding packets to a packet analyzer which recognise new sessions and calculates statistics for each session. Additional functions can be called to produce aggregate statistics (such as average RTT values) or to further process or communicate the information output from the analyzer.

## Library Usage Example

The API definition for this library can be found from spindump_analyze.h. But the main function are analyzer initialization, handing a packet to it, and de-initialization. First, you need to initialize the analyzer, like this:

    struct spindump_analyze* analyzer = spindump_analyze_initialize(10000000);
    if (analyzer == 0) { /* ... handle error */ }

Here the "1000000" is a configuration argument to the analyzer, telling it to measure bandwidth numbers in a period of 1s (a million microseconds).

Then, you probably want to feed packets to the analyzer in some kind of loop. The analyzer needs to know the actual Ethernet message frame  received as an octet string, but also a timestamp of when it was received, the length of the frame, and how much of the message was captured if the frame is not stored in its entirety. Here's an example implementation of a packet reception loop that feeds the analyzer:

    while (... /* some condition */) {
      struct spindump_packet packet;
      memset(&packet,0,sizeof(packet));
      packet.timestamp = ...; /* when did the packet arrive? */
      packet.contents = ...;  /* pointer to the beginning of a packet, starting from Ethernet frame */
      packet.etherlen = ...;  /* length of that entire frame */
      packet.caplen = ...;    /* how much of the frame was captured */
      struct spindump_connection* connection = 0;
      spindump_analyze_process(analyzer,&packet,&connection);
      if (connection != 0) { /* ... look inside connection for statistics, etc */ }
    }

Finally, you need to clean up the resources used by the analyzer. Like this:

    spindump_analyze_uninitialize(analyzer);

That's the basic usage of the analyzer, using the built-in functions of looking at TCP, QUIC, ICMP, UDP, DNS, and SCTP connections and their roundtrips.

The software does not communicate the results in any fashion at this point; any use of the collected information about connections would be up to the program that calls the analyzer; the information is merely collected in an in-memory data structure about current connections. A simple use of the collected information would be to store the data for later statistical analysis, or to summarize in in some fashion, e.g., by looking at average round-trip times to popular destinations.

The analyzer can be integrated to any equipment or other software quite easily.

But beyond this basic functionality, the analyzer is also extensible. You can register a handler:

    spindump_analyze_register(analyzer,
                              // what event(s) to trigger on (OR the event bits together):
                              spindump_analyze_event_newrightrttmeasurement,
                              // whether this handler is specific for a particular connection or all (0):
                              0,
                              // function to call for this event:
                              myhandler,
                              // pass 0 as private data to myhandler later:
                              0);

This registration registers the function "myhandler" to be called when there's a new RTT measurement. Handlers can be added and removed dynamically, and even be registered for specific connections.

But in the end, when a handler has been registered, if the noted event occurs then a user-specified function gets called. In the case of our new RTT measurement handler, the function to be called can be implemented, for instance, like this:

    void myhandler(struct spindump_analyze* state,
                   void* handlerData,
                   void** handlerConnectionData,
                   spindump_analyze_event event,
                   int fromResponder,
                   unsigned int ipPacketLength,
                   struct spindump_packet* packet,
                   struct spindump_connection* connection) {
       
       if (connection->type == spindump_connection_transport_quic &&
           event == spindump_analyze_event_newrightrttmeasurement) {
       
           /* ... */
       
       }
       
    }

In the first part of the code above, a handler is registered to be called upon seeing a new RTT measurement being registered. The second part of the code is the implementation of that handler function. In this case, once a measurement has been made, the function "myhandler" is called. The packet that triggered the event (if any) is given by "packet" and the connection it is associated with is "connection". For the connection delete events (as they can come due to timeouts), the packet structure is otherwise empty except for the timestamp (packet->timestamp) of the deletion.

All RTT measurements and other data that may be useful is stored in the connection object. See spindump_connections_struct.h for more information. For instance, the type of the connection (TCP, UDP, QUIC, DNS, ICMP, SCTP) can be determined by looking at the connection->type field.

The RTT data can be accessed also via the connection object. For instance, in the above "myhandler" function one could print an RTT measurement as follows:

    printf("observed last RTT is %.2f milliseconds",
           connection->rightRTT.lastRTT / 1000.0);

The function "myhandler" gets as argument the original data it passed to spindump_analyze_register (here simply "0").

If the handler function needs to store some information on a per-connection basis, it can also do so by using the "handlerConnectionData" pointer. This is a pointer to variable inside the connection object that is dedicated for this handler and this specific connection.

By setting and reading that variable, the handler could (for instance) store its own calculations, e.g., a smoothed RTT value if that's what the handler is there to do.

Typically, for such usage of connection-specific variables, one would likely use the field for a pointer to some new data structure that holds the necessary data. The void* for the connection-specific data is always initialized to zero upon the creation of a new connection, so this can be used to determine when the data structure needs to be allocated. E.g.,

    struct my_datastructure* perConnectionData =
       (struct my_datastructure*)*handlerConnectionData;
    
    if (perConnectionData == 0) {
      
      perConnectionData = (struct my_datastructure*)malloc(sizeof(struct my_datastructure));
      *handlerConnectionData = (void*)perConnectionData;
      
    }
    
    /* ... use the perConnectionData for whatever purpose is necessary ... */

Note that if the handlers allocate memory on a per-connection basis, they also need to de-allocate it. One way of doing this is to use the deletion events as triggers for that de-allocation.

## Library API

See the API functions in the [Analyzer API definition](https://github.com/EricssonResearch/spindump/blob/master/doc/api/analyzer.md):

* spindump_analyze_initialize -- This function creates an object to represent an analyzer.
* spindump_analyze_uninitialize  -- Destroy the analyzer resources and memory object.
* spindump_analyze_registerhandler -- This function should be called to register a handler for events.
* spindump_analyze_unregisterhandler -- This function should be called to de-register a handler that was previously registered.
* callback interface -- The user's function gets called when the relevant event happens.

## API data structure struct spindump_connection

This object represents a single connection observed by the analyzer. The full description of that object needs to be added later, but here are some of the key fields that are relevant:

* connection->type indicates the type of the connection (TCP, ICMP, QUIC, SCTP, etc)
* connection->creationTime indicates when the first packet for the connection was seen
* connection->packetsFromSide1 counts the number of packets sent from the initiator to the responder 
* connection->packetsFromSide2 counts the number of packets sent from the initiator to the initiator 
* connection->leftRTT is the number of microsends for the RTT part that is between the initiator (client) and the measurement point 
* connection->rightRTT is the number of microsends for the RTT part that is between the responder (server) and the measurement point 

The full description can be found from the [Connection API definition](https://github.com/EricssonResearch/spindump/blob/master/doc/api/connection.md):

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
    #define spindump_analyze_event_initiatorrtlossmeasurement        65536
    #define spindump_analyze_event_responderrtlossmeasurement       131072
    #define spindump_analyze_event_initiatorqrlossmeasurement       262144
    #define spindump_analyze_event_responderqrlossmeasurement       524288
    #define spindump_analyze_event_initiatorqllossmeasurement      1048576
    #define spindump_analyze_event_responderqllossmeasurement      2097152

These can be mixed together in one handler by ORing them together. The pseudo-event "spindump_analyze_event_alllegal" represents all of the events.

For more information see again the [Analyzer API definition](https://github.com/EricssonResearch/spindump/blob/master/doc/api/analyzer.md).

## Memory allocation

The library allocates memory as needed using malloc and free, and upon calling the analyzer uninitialization function, no allocated memory remains. For more information and ways to tailor the allocation system, see again the [Analyzer API definition](https://github.com/EricssonResearch/spindump/blob/master/doc/api/analyzer.md).
