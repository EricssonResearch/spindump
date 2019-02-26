# Spindump data formats

## Introduction

This description specifies what measurement data Spindump produces to describe the connections it detects. The measurement data is either output directly from the Spindump tool when used in the --textual mode or sent to a remote Spindump instance or other collection point when the --remote option is used.

## Protocol for sending data

The Spindump protocol for transmitting measurement data is web-based; data is sent around over HTTP or HTTPS connections. Data transmission is push-based, i.e., initiated by whoever has the data attempting to submit it to the designated data collector. Data collectors can be other Spindump instances, but there's nothing that requires this. A standard web server will be able to receive data sent by Spindump. A website owner could setup a server to record all data submissions for later analysis, for instance.

Each data submission is a HTTP POST to an URL. By default, in Spindump those URLs have the host, port 5040, and no path, but command line arguments in Spindump can be used to control these settings.

Each data submission comes with a HTTP body part, formatted in a given way. Two formats are currently supported, application/text for the textual format and application/json for the JSON format. These are described in the next sections.

## Textual format

The textual format is simply a human-readable, textual (ASCII) format. It is used by default, or when the --format text option has been specified.

Example:

    ICMP 10.30.0.167 <-> 195.140.195.198 60457 at 12:45:11.497002 new connection
    ICMP 10.30.0.167 <-> 195.140.195.198 60457 at 12:45:11.518750 left n/a right 21.7 ms

## JSON format

The JSON format is a machine-readable, but easily processable format. It is used when the --format json option has been specified.

Example:

    [
    { "type": "ICMP", "addrs": "10.30.0.167 <-> 195.140.195.198", "session": "60459", "ts": 1550918762743483,"event": "new", "packets": 0, "ECT(0)": 0, "ECT(1)": 0, "CE": 0 }
    { "type": "ICMP", "addrs": "10.30.0.167 <-> 195.140.195.198", "session": "60459", "ts": 1550918762765733, "right_rtt": 22250, "packets": 1, "ECT(0)": 0, "ECT(1)": 0, "CE": 0 }
	]

In more detail, the JSON format consists of a bracketed sequence of records in braces. Each record has the following fields:

   * The "type" field specifies the type of a connection. This field can take on the following basic values: "UDP", "TCP", "QUIC", "DNS", "COAP", and "ICMP". In addition, it is possible to specify aggregate connections; these take on the following types: "HOSTS" for a host-to-host aggregate, "H2NET" for a host-to-network aggregate, "NET2NET" for a network-to-network aggregate, and "MCAST" for a multicast group aggregate.
   * The "event" field specifies what kind of event is being reported. This field can take on the following values: "new" for newly seen connections, "delete" for connections deleted, "spinflip" for a flip of the QUIC spin bit in a connection, "spin" for any value of a spin bit in a QUIC connection, "measurement" for new RTT measurements, and "ECN CE initiator"/"ECN CE responder" for ECN-related events.
   * The "addrs" field specifies addresses associated with the connection or aggregate.
   * The "session" field specifies the session identifiers associated with the connection, if any. For TCP and UDP connections these are the port numbers, for QUIC the connection IDs, and for ICMP the identifier field.
   * The "ts" is the timestamp, number of microseconds since the start of January 1, 1970.

The other fields depend on the type of an event and connection. These fields can be provided:

   * The field "left_rtt" specifies a measurement of a portion of the RTT between the measurement point and the initiator/client of a connection. The time is represented as a number of microseconds.
   * Similarly, the "right_rtt" specifies the measurement portion towards the responder/server of a connection.
   * The field "sum_rtt" specifies the calculated full RTT as calculated as a sum of the left and the right RTT portions.
   * The field "full_rtt_initiator" specifies the full RTT as meassured from a QUIC spin bit flips from packets from the client/initiator of a connection.
   * The field "full_rtt_responder" specifies the full RTT as meassured from a QUIC spin bit flips from packets from the server/responder of a connection.

## Binary format

A binary format for Spindump measurement data is being designed. Stay tuned!


