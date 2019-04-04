# Spindump

## A latency measurement tool

The "Spindump" tool is a Unix command-line utility that can be used for latency monitoring in traffic passing through an interface. The tool performs passive, in-network monitoring. It is not a tool to monitor traffic content or metadata of individual connections, and indeed that is not possible in the Internet as most connections are encrypted.

The tool looks at the characteristics of transport protocols, such as the QUIC Spin Bit, and attempts to derive information about round-trip times for individual connections or for the aggregate or average values. The tool supports TCP, QUIC, COAP, DNS, and ICMP traffic. There's also an easy way to anonymize connection information so that the resulting statistics cannot be used to infer anything about specific connections or users.

The software is under development, and subject to research on best algorithms.

![Tool output](https://raw.githubusercontent.com/EricssonResearch/spindump/master/images/screenshot1.jpg)

The tool builds on the Spindump Library, which is a small, simple, and extensible packet analysis tool. It can be integrated into various systems, from routers to tools like the Spindump utility.

# News!!!

Spindump now supports Google QUIC as implemented in Chrome, has improved documentation, and its security has improved with a privilege downgrade on Linux. Spindump is also now able to send collected information to a selected web server or another Spindump instance. And finally, Spindump transitioned to the use of cmake with the help of Lars Eggert.

See the [news](https://github.com/EricssonResearch/spindump/blob/master/Format.md) page for more details!

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

These options are used to control the amount of anonymization that spindump does. Anonymization can be turned on or off either for hosts whose traffic is displayed, or for hosts on the "left" or "right" side of the in-network measurement point. "Left" side is defined as the traffic initiating the connection. And the "right" side is defined as the traffic from the responder.

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
    --deepdebug
    --no-deepdebug
    --deepdeepdebug
    --no-deepdeepdebug

The first pair sets the debugging output on/off. Note that in the visual or textual output modes, all debugging information goes to the file spindump.debug in the current working directory. The second and third sets the extensive or very extensive internal debugging output on/off.

    --no-stats
    --stats

The option --stats makes spindump provide various levels of final statistics once the process completes. The default is --no-stats.

    --aggregate pattern1 pattern2

Track the aggregate traffic statistics from host or network identified by pattern1 to host or network identified by pattern2. These can be individual host addresses such as 198.51.100.1 or networks such as 192.0.2.0/24. Both IPv4 and IPv6 addresses are supported. An easy way to specify any connection to a network is to use a 0-length prefix. For instance, to track all connections to 192.0.2.0/24, use the option setting "--aggregate 0.0.0.0/0 192.0.2.0/24".

    --max-receive n

Sets a limit of how many packets the tool accepts before finishing. The default is 0, which stands for no limit.

    --interface i
    --input-file f
    --remote u
	--remote-block-size n
	--collector-port p
	--collector 
	--no-collector 

The --interface option sets the local interface to listen on. The default is whatever is the default interface on the given system. The --input-file option sets the packets to be read from a PCAP-format file. PCAP-format files can be stored, e.g., with the tcpdump option "-w".

The --remote option sets software to submit connection information it collects to another spindump instance running elsewhere with the --collector option specified. The machine where the other instance runs in is specified by the URL u, e.g., "http://example.com:5040/data/1". By default, Spindump uses the port 5040, which is reflected in the URL. The path component "data" is required when submitting data to another Spindump instance, and the path component "1" is simply an identifier that distinguishes different submitters from each other.

As noted, the collector is turned on by using the --collector option. On the collector side the port can be changed with the --collector-port option. Also, a given Spindump instance running as a collector can accept connections from multiple other instances. The Spindump instance that is running as a collector will not listen to the local interfaces at all, only the collector port.

Finally, the --remote-block-size option sets the approximate size of submissions, expressed in kilobytes per submission. Multiple individal records are typicallly pooled in one update, but if the block size is set to 0, there will be no pooling. The format of the submissions is governed by the --format option.  Note that only the machine readable formats are actually processed by the Spindump instance running as a collector; --format text will be ignored by the collector. The formats are specified in the [data format description](https://github.com/EricssonResearch/spindump/blob/master/Format.md)

    --help

Outputs information about the command usage and options.

    --version

Outputs the version number

# Installation

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

# Spindump Library

The Spindump software builds on the Spindump Library, a simple but extensibile packet analysis package. The makefile builds a library, libspindump.a that can be linked to a program, used to provide the same statistics as the spindump command does, or even extended to build more advanced functionality. The Spindump command itself is built using this library.

The library can also be used in other ways, e.g., by integrating it to other tools or network devices, to collect some information that is necessary to optimize the device or the network in some fashion, for instance.

![Tool output](https://raw.githubusercontent.com/EricssonResearch/spindump/master/images/architecture2s.jpg)

# Dependencies 

The Spindump command depends on the basic OS libraries (such as libc) as well as libpcap, ncurses, curl, and microhttpd. The Spindump library depends only on libc, unless you use the features that would require libpcap or other libraries.

# Things to do

The software is being worked on, and as of yet seems to be working but definitely needs more testing. IP packet fragmentation is recognised but no packet reassembly is performed; an optional reassembly process would be a useful new feature. The beginnings of connection data anonymization are in the software, but more work is needed on that front as well.

The full list of known bugs and new feature requests can be found from [GitHub](https://github.com/EricssonResearch/spindump/issues).
