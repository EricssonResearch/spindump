# Spindump data formats

## Introduction

This description specifies what measurement data Spindump produces to describe the connections it detects. The measurement data is either output directly from the Spindump tool when used in the --textual mode or sent to a remote Spindump instance or other collection point when the --remote option is used.

## Protocol for sending data

The Spindump protocol for transmitting measurement data is web-based; data is sent around over HTTP or HTTPS connections. Data transmission is push-based, i.e., initiated by whoever has the data attempting to submit it to the designated data collector. Data collectors can be other Spindump instances, but there's nothing that requires this. A standard web server will be able to receive data sent by Spindump. A website owner could setup a server to record all data submissions for later analysis, for instance.

Each data submission is a HTTP POST to an URL. By default, in Spindump those URLs have the host, port 5040, and no path, but command line arguments in Spindump can be used to control these settings.

Each data submission comes with a HTTP body part, formatted in a given way. Two formats are currently supported, application/text for the textual format and application/json for the JSON format. These are described in the next sections.

### Starting Spindump in distributed mode

To send data from a Spindump instance to a web server, give the command like this:

    spindump --remote-block-size 0 --silent --format json --remote http://localhost:5040/data/1

if you have a Spindump instance listening in on these posts in the same machine. On the other end, where these messages will be received, start Spindump as follows:

    spindump --collector

## Textual format

The textual format is simply a human-readable, textual (ASCII) format. It is used by default, or when the --format text option has been specified.

Example:

    ICMP 10.30.0.167 <-> 195.140.195.198 60457 at 12:45:11.497002 new connection
    ICMP 10.30.0.167 <-> 195.140.195.198 60457 at 12:45:11.518750 left n/a right 21.7 ms

## JSON format

The JSON format is a machine-readable, but easily processable format. It is used when the --format json option has been specified.

Example:

    [
    { "Event": "new", "Type": "ICMP", "Addrs": ["31.133.128.152","212.16.98.51"], "Session": "45845", "Ts": 1553373707781246 }
    { "Event": "measurement", "Type": "ICMP", "Addrs": ["31.133.128.152","212.16.98.51"], "Session": "45845", "Ts": 1553373707818571, "Left_rtt": "37325" }
    ]

In more detail, the JSON format consists of a bracketed sequence of records in braces. Each record has the following fields:

   * The "Event" field specifies what kind of event is being reported. This field can take on the following values: "new" for newly seen connections, "change" when the connection's identifying parameters such as port numbers of QUIC connection identifiers change, "delete" for connections deleted, "spinflip" for a flip of the QUIC spin bit in a connection, "spin" for any value of a spin bit in a QUIC connection, "measurement" for new RTT measurements, and "ecnce" for ECN-related events. In  addition, the "packet" signals any other update of the counters.
   * The "Type" field specifies the type of a connection. This field can take on the following basic values: "UDP", "TCP", "QUIC", "DNS", "COAP", "ICMP" and "SCTP". In addition, it is possible to specify aggregate connections; these take on the following types: "HOSTS" for a host-to-host aggregate, "H2NET" for a host-to-network aggregate, "NET2NET" for a network-to-network aggregate, "H2MUL" for a host to multiple networks aggregate, NET2MUL for a network to multiple networks aggregate and "MCAST" for a multicast group aggregate.
   * The "Addrs" field specifies addresses associated with the connection or aggregate. In the case of an H2MUL or NET2MUL connection, the right hand address is always zero.
   * The "Session" field specifies the session identifiers associated with the connection, if any. For TCP and UDP connections these are the port numbers, for QUIC the connection IDs, for ICMP the identifier field and for SCTP the verification tags and the port numbers.
   * The "Ts" is the timestamp, number of microseconds since the start of January 1, 1970. Note that the number is represented as an integer, given that the 53 bits of integer precision in JSON integers is sufficient. About 20 bits are needed for the microseconds part, which leaves 43 bits for the integer seconds parts; enough until year 280892.
   * The "State" field is the state of the connection, either "Starting", "Up", "Closing", or "Closed".

The other fields depend on the type of an event and connection. These fields can be provided:

   * The field "tags" is a set of user-specified tags that may have been specified when Spindump was started. This can be used by the receiver to more easily determine what connection is being measured. If there are more than one tag value, they tag values are separated by commas.
   * The field "Left_rtt" specifies a measurement of a portion of the RTT between the measurement point and the initiator/client of a connection. The time is represented as a number of microseconds.
   * Similarly, the "Right_rtt" specifies the measurement portion towards the responder/server of a connection.
   * The field "Full_rtt_initiator" specifies the full RTT as meassured from a QUIC spin bit flips from packets from the client/initiator of a connection.
   * The field "Full_rtt_responder" specifies the full RTT as meassured from a QUIC spin bit flips from packets from the server/responder of a connection.
   * Similarly, the fields "Avg_left_rtt", "Avg_right_rtt", "Avg_full_rtt_initiator", and "Avg_full_rtt_responder" represent the above RTT values but calculated as moving averages.
   * Again similarly, the fields "Dev_left_rtt", "Dev_right_rtt", "Dev_full_rtt_initiator", and "Dev_full_rtt_responder" represent the standard deviation of the above RTT values.
   * The fields "Filt_avg_left_rtt", "Filt_avg_right_rtt", "Filt_avg_full_rtt_initiator", and "Filt_avg_full_rtt_responder" represent the moving average values, but with exceptional values filtered out before they are used in the average calculation.
   * The field "Value" specifies the value of the spin bit.
   * The field "Transition" specifies the spin bit transition, which is either "0-1" or "1-0". 
   * The field "Who" specifies from which direction did the information come from, "initiator" or "responder".
   * The fields "Packets1" and "Packets2" specify the number of packets (in initiator and responder direction) that have been seen on this connection. 
   * The fields "Bytes1" and "Bytes2" specify the number of packets (in initiator and responder direction) that have been seen on this connection.
   * The field "Bandwidth1" and "Bandwidth2" specify the bandwidth of a connection (in initiator and responder direction) as calculated periodically for each second. The number represents number of bytes per second.
   * The fields "Ect0", "ect1" and "ce" specify ECN event counters for ECN(0), ECN(1), and CE events.
   * The field "Length" specifies the length of the IP packet for "packet" events. 
   * The field "Dir" specifies the direction of the packet for "packet" events, with the values being "initiator" and "responder" depending on who sent the packet that caused the event.

## Binary format

A binary format for Spindump measurement data is being designed. Stay tuned!


