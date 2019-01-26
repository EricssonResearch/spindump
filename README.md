# Spindump

## A latency measurement tool

The "Spindump" tool is a Unix command-line ulitity that can be used for latency monitoring in traffic passing through an interface. The tool performs passive, in-network monitoring. It is not a tool to monitor traffic content or metadata of individual connections, and indeed that is not possible in the Internet as most connections are encrypted.

The tool looks at the characteristics of transport protocols, such as the QUIC Spin Bit, and attempts to derive information about round-trip times for individual connections or for the aggregate or average values. The tool supports TCP, QUIC, COAP, DNS, and ICMP traffic. There's also an easy way to anonymize connection information so that the resulting statistics cannot be used to infer anything about specific connections or users.

The software is under development, and subject to research on best algorithms.

![Tool output](https://raw.githubusercontent.com/EricssonResearch/spindump/master/images/screenshot1.jpg)

The tool builds on the Spindump Library, which is a small, simple, and extensible packet analysis tool. It can be integrated into various systems, from routers to tools like the Spindump utility.

# Use Cases

Spindump can be used to observe latency in ongoing connections for debugging purposes, as shown in the below figure:

![Tool output](https://raw.githubusercontent.com/EricssonResearch/spindump/master/images/architecture1.jpg)

But Spindump could also be used to record information from experiments related to Spin Bit. And the Spin Bit being new in the QUIC design, hopefully it will also help in debugging this new feature.

Spindump can also be used to measure latencies on a more ongoing basis. It can feed information to management and other systems, and could for instance enable alarms to be raised when the circumstances demand that, configurations to be optimized, and so on. 

# Spindump Command Usage

The software is packaged as the "spindump" utility, and simply typing

    # spindump

should show the most active sessions and their current round-trip times (RTTs). The top of the screen shows some status information, while the rest is dedicated to showing connections and their RTTs. You can exit from the tool by pressing Control-C or "Q". In addition, you can use "C" to toggle whether to show closed connections, "U" to whether to show UDP connections, or "A" to show either individual connections or aggregated connections. Pressing "H" shows help information and pressing "S" enables you to set the screen update frequency.

The full command syntax is

    spindump [options] [filter]

If no options or filter is specified, Spindump will look at all packets on the default interface. The filter specification is as specified in other PCAP-based tools such as tcpdump. For instance, the expression "icmp" tracks only ICMP packets, and the expression "tcp and host www.example.com" tracks TCP packets where www.example.com appears either as a source or destination address. See the man page for pcap-filter(7) for more details.

The options are as follows:

    --silent
    --textual
    --visual

Sets the tool to be quiet as it measures (--silent), listing RTT measurements as they become available (--textual) or continuously update the shell window with information about the current sessions (--visual). The default is --visual. The --silent option also sets the tool to publish information about connections it sees on a local port (5040) that can be connected to by other instances of Spindump.

    --format text
    --format json

For the textual mode, the output format is selectable as either readable text or JSON. Each event comes out as one JSON record in the latter case.

    --anonymize-left
    --not-anonymize-left
    --anonymize-right
    --not-anonymize-right
    --anonymize
	--not-anonymize

These options are used to control the amount of anonymization that spindump does. Anonymization can be turned on or off either for hosts whose traffic is displayed, or for hosts on the "left" or "right" side of the in-network measurement point. "Left" side is defined as the traffic coming in on the designated measurement interface. And the "right" side is defined as the traffic going out.

    --names
    --addresses

Sets the tool to use always addresses (--addresses) or when possible, DNS names (--names) in its output. The use of names is the default.

    --report-spins
    --not-report-spins
    --report-spin-flips
    --not-report-spin-flips

Sets the tool to either report or not report individual spin bit values or spin bit value flips for QUIC connections, when using the --textual mode. The default is to not report either the spin values (as there is one per each packet) or spin value flips.

    --debug
    --no-debug

Sets the debugging output on/off. Note that in the visual or textual output modes, all debugging information goes to the file spindump.debug in the current working directory.

    --deepdebug
    --no-deepdebug

Sets the extensive internal debugging output on/off.

    --no-stats
    --stats

The option --stats makes spindump provide various levels of final statistics once the process completes. The default is --no-stats.

    --aggregate pattern1 pattern2

Track the aggregate traffic statistics from host or network identified by pattern1 to host or network identified by pattern2. These can be individual host addresses such as 198.51.100.1 or networks such as 192.0.2.0/24. Both IPv4 and IPv6 addresses are supported. An easy way to specify any connection to a network is to use a 0-length prefix. For instance, to track all connections to 192.0.2.0/24, use the option setting "--aggregate 0.0.0.0/0 192.0.2.0/24".

    --max-receive n

Sets a limit of how many packets the tool accepts before finishing. The default is 0, which stands for no limit.

    --interface i
    --input-file f
    --remote h 

The --interface option sets the local interface to listen on. The default is whatever is the default interface on the given system. The --input-file option sets the packets to be read from a PCAP-format file. PCAP-format files can be stored, e.g., with the tcpdump option "-w". The --remote option sets software to listen to connection information collected by other spindump instances running elsewhere in silent mode. The machine where the other instance runs in is specified by the address h. Currently, only one instance can run in one machine, using port 5040. However, a given Spindump instance can connect to multiple other instances when multiple -remote options are used.

    --help

Outputs information about the command usage and options.

    --version

Outputs the version number

# Installation

The easiest installation method is to retrieve the software from GitHub. Start with this:

  git clone https://github.com/EricssonResearch/spindump

Make sure you have the necessary tools to compile; you'll need the gmake, gcc, and libpcap packages at least. On a Mac OS X, you can install these with the

    sudo port install gmake gcc libpcap ncurses

command. And on linux, do:

    sudo apt-get install make gcc libpcap-dev libncurses5-dev

Then do:

    cd spindump
    make
    sudo make install

# Spindump Library

The Spindump software builds on the Spindump Library, a simple but extensibile packet analysis package. The makefile builds a library, libspindump.a that can be linked to a program, used to provide the same statistics as the spindump command does, or even extended to build more advanced functionality. The Spindump command itself is built using this library.

![Tool output](https://raw.githubusercontent.com/EricssonResearch/spindump/master/images/architecture2s.jpg)

The API definition for this library can be found from spindump_analyze.h. But the main function are analyzer initialization, handing a packet to it, and de-initialization. First, you need to initialize the analyzer, like this:

    struct spindump_analyze* analyzer = spindump_analyze_initialize();
    if (analyzer == 0) { /* ... handle error */ }

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

That's the basic usage of the analyzer, using the built-in functions of looking at TCP, QUIC, ICMP, UDP, and DNS connections and their roundtrips.

The software does not communicate the results in any fashion at this point; any use of the collected information about connections would be up to the program that calls the analyzer; the information is merely collected in an in-memory data structure about current connections. A simple use of the collected information would be to store the data for later statistical analysis, or to summarize in in some fashion, e.g., by looking at average round-trip times to popular destinations.

The analyzer can be integrated to any equipment or other software quite easily.

But beyond this basic functionality, the analyzer is also extensible. You can register a handler:

    spindump_analyze_register(analyzer,
    
                             /* what event(s) to trigger on (OR the event bits together): */
                             spindump_analyze_event_newrightrttmeasurement,
    
                             /* function to call for this event: */
                             myhandler,
    
                             /* pass 0 as private data to myhandler later: */
                             0);

This registration registers the function "myhandler" to be called when there's a new RTT measurement. This function could be implemented, for instance, like this:

    void myhandler(struct spindump_analyze* state,
                   void* handlerData,
                   void** handlerConnectionData,
                   spindump_analyze_event event,
                   struct spindump_packet* packet,
                   struct spindump_connection* connection) {
       
       if (connection->type == spindump_connection_transport_quic &&
           event == spindump_analyze_event_newrightrttmeasurement) {
       
           /* ... */
       
       }
       
    }

In the first part of the code above, a handler is registered to be called upon seeing a new RTT measurement being registered. The second part of the code is the implementation of that handler function. In this case, once a measurement has been made, the function "myhandler" is called. The packet that triggered the event (if any) is given by "packet" and the connection it is associated with is "connection".

All RTT measurements and other data that may be useful is stored in the connection object. See spindump_connections_struct.h for more information. For instance, the type of the connection (TCP, UDP, QUIC, DNS, ICMP) can be determined by looking at the connection->type field.

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

The currently defined events that can be caught are:

    #define spindump_analyze_event_newconnection                 1
    #define spindump_analyze_event_connectiondelete              2
    #define spindump_analyze_event_newleftrttmeasurement         4
    #define spindump_analyze_event_newrightrttmeasurement        8
    #define spindump_analyze_event_initiatorspinflip            16
    #define spindump_analyze_event_responderspinflip            32
    #define spindump_analyze_event_initiatorspinvalue           64
    #define spindump_analyze_event_responderspinvalue          128
    #define spindump_analyze_event_newpacket                   256
    #define spindump_analyze_event_firstresponsepacket     512
    #define spindump_analyze_event_statechange            1024

These can be mixed together in one handler by ORing them together. The pseudo-event "spindump_analyze_event_alllegal" represents all of the events.

# Things to do

The software is being worked on, and as of yet seems to be working but definitely needs more testing. IP packet fragmentation is not yet supported. Also, the remote connection mode is not yet implemented. The beginnings of connection data anonymization are in the software, but more work is needed on that front as well.
