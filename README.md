# Spindump

## A latency measurement tool

The "Spindump" tool is a Unix command-line utility that can be used for latency monitoring in traffic passing through an interface. The tool performs passive, in-network monitoring. It is not a tool to monitor traffic content or metadata of individual connections, and indeed that is not possible in the Internet as most connections are encrypted.

The tool looks at the characteristics of transport protocols, such as the QUIC Spin Bit, and attempts to derive information about round-trip times for individual connections or for the aggregate or average values. The tool supports TCP, QUIC, COAP, DNS, and ICMP traffic. There's also an easy way to anonymize connection information so that the resulting statistics cannot be used to infer anything about specific connections or users.

The software is under development, and subject to research on best algorithms.

![Tool output](https://raw.githubusercontent.com/EricssonResearch/spindump/master/images/screenshot1.jpg)

The tool builds on the Spindump Library, which is a small, simple, and extensible packet analysis tool. It can be integrated into various systems, from routers to tools like the Spindump utility.

## News!!!

Spindump code now uses spaces, not tabs for indents. Please configure your editor appropriately! Spindump now supports Google QUIC as implemented in Chrome, has improved documentation, and its security has improved with a privilege downgrade on Linux. Spindump is also now able to send collected information to a selected web server or another Spindump instance. 

See the [news](https://github.com/EricssonResearch/spindump/blob/master/News.md) page for more details!

# Use Cases

Spindump can be used to observe latency in ongoing connections for debugging purposes, as shown in the below figure:

![Tool output](https://raw.githubusercontent.com/EricssonResearch/spindump/master/images/architecture1.jpg)

But Spindump could also be used to record information from experiments related to Spin Bit. And the Spin Bit being new in the QUIC design, hopefully it will also help in debugging this new feature.

Spindump can also be used to measure latencies on a more ongoing basis. It can feed information to management and other systems, and could for instance enable alarms to be raised when the circumstances demand that, configurations to be optimized, and so on. 

## Spindump Command Usage

The software is packaged as the "spindump" utility, and simply typing

    # spindump
 
should show the most active sessions and their current round-trip times (RTTs). The top of the screen shows some status information, while the rest is dedicated to showing connections and their RTTs. You can exit from the tool by pressing Control-C or "Q". In addition, you can use "C" to toggle whether to show closed connections, "U" to whether to show UDP connections, or "A" to show either individual connections or aggregated connections. Pressing "H" shows help information and pressing "S" enables you to set the screen update frequency.

The full command syntax is

    spindump [options] [filter]

If no options or filter is specified, Spindump will look at all packets on the default interface. The filter specification is as specified in other PCAP-based tools such as tcpdump. See the man page for pcap-filter(7) for more details.

To simply start the Spindump tool on the default user interface is enough for most cases:

    # spindump 

To look at specific connections, you can enter a filter specification. For instance, the expression "icmp" tracks only ICMP packets, and the expression "tcp and host www.example.com" tracks TCP packets where www.example.com appears either as a source or destination address. So, for instance:

    # spindump udp and port 443

would only look udp port 443 traffic (likely QUIC).

See the [usage description](https://github.com/EricssonResearch/spindump/blob/master/Usage.md) for the full description of all options!

## Installation

The easiest installation method is to retrieve the software from GitHub. Start with this:

  git clone https://github.com/EricssonResearch/spindump

Make sure you have the necessary tools to compile; you'll need the gmake, gcc, and libpcap packages at least. On a Mac OS X, you can install these with the

    sudo port install cmake gmake gcc libpcap ncurses curl libmicrohttpd

command. And on linux, do:

    sudo apt-get install pkg-config cmake make gcc libpcap-dev libncurses5-dev libcurl4-openssl-dev libmicrohttpd-dev

Then do:

    cd spindump
    cmake .
    make
    sudo make install

## Spindump Library

The Spindump software builds on the Spindump Library, a simple but extensibile packet analysis package. The makefile builds a library, libspindump.a that can be linked to a program, used to provide the same statistics as the spindump command does, or even extended to build more advanced functionality. The Spindump command itself is built using this library.

The library can also be used in other ways, e.g., by integrating it to other tools or network devices, to collect some information that is necessary to optimize the device or the network in some fashion, for inst.ance.

![Tool output](https://raw.githubusercontent.com/EricssonResearch/spindump/master/images/architecture2s.jpg)

See the [library API definition](https://github.com/EricssonResearch/spindump/blob/master/Library.md) page for all the details.

## Dependencies 

The Spindump command depends on the basic OS libraries (such as libc) as well as libpcap, ncurses, curl, and microhttpd. The Spindump library depends only on libc, unless you use the features that would require libpcap or other libraries.

## Things to do

The software is being worked on, and as of yet seems to be working but definitely needs more testing. IP packet fragmentation is recognised but no packet reassembly is performed; an optional reassembly process would be a useful new feature. The beginnings of connection data anonymization are in the software, but more work is needed on that front as well.

The full list of known bugs and new feature requests can be found from [GitHub](https://github.com/EricssonResearch/spindump/issues).

## Full documentation

The full documentation of Spindump consists of the following:

* [README](https://github.com/EricssonResearch/spindump/blob/master/README.md) (this file) contains the introduction and installation instructions.
* The command [usage description](https://github.com/EricssonResearch/spindump/blob/master/Usage.md) describes how to use the Spindump command-line tool.
* The [format description](https://github.com/EricssonResearch/spindump/blob/master/Format.md) explains what format Spindump measurement data can be carried in, if it is sent to a collection point rather than shown visually to the user.
* [Library API definition](https://github.com/EricssonResearch/spindump/blob/master/Library.md) contains the definition of the Spindump library API, and an explanation of how and when to use the library
* [News](https://github.com/EricssonResearch/spindump/blob/master/News.md) describes recent additions.
