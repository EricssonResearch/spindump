#!/bin/bash

srcdir=`dirname $0`
testdir=$srcdir/../test
spindump=$srcdir/spindump

#
# All test cases are listed below. For each test file there needs to
# be a .pcap file, as well as a description (.txt) file and expected
# results from spindump (.expected). There may also be special options
# file (.options).
#

traces="trace_icmpv4_short trace_icmpv6_short trace_tcp_short trace_tcp_short_json trace_dns trace_quic_v18_short_spin trace_quic_v18_short_spin_all trace_quic_v18_long_spin trace_quic_v18_long_spin_all trace_quic_v19_short_quant trace_quic_google trace_quic_bug_ls trace_tunnel_interface_ping trace_tcp_medium_snap80 trace_tcp_large_snap80"

#
# Loop through test cases
#

unset CPUPROFILE

for trace in $traces
do
    
    echo "Test case $trace... "

    #
    # Determine the parameters (PCAP files, options etc) of the test case
    #
    
    pcap=$testdir/$trace.pcap
    descr=$testdir/$trace.txt
    out=$testdir/$trace.out
    corr=$testdir/$trace.expected
    optsfile=$testdir/$trace.options
    perfoptsfile=$testdir/$trace.optionsperf
    profilefile=$testdir/$trace.perf
    opts=""
    if [ -f $optsfile ]
    then
	opts=`cat $optsfile`
    fi

    #
    # Now run it!
    #
    
    if $spindump --input-file $pcap --textual --format text $opts > $out
    then
	echo "  run ok..."
    else
	echo "**run failed -- exit"
	exit 1
    fi

    #
    # Check results
    #
    
    if [ -f $corr ]
    then
	nop=nop
    else
	echo "**expected results file $corr does not exist -- exit"
	exit 1
    fi
    
    if diff $out $corr > /dev/null
    then
	echo "  results correct"
    else
	echo "**results incorrect -- exit"
	exit 1
    fi
    
    if [ -f $descr ]
    then
	nop=nop
    else
	echo "**test description file $descr does not exist -- exit"
	exit 1
    fi

    #
    # Should we also do performance measurements? Yes if there's a <testcase>.optionsperf file
    #
    
    if [ -f $perfoptsfile ]
    then
	CPUPROFILE=$profilefile
	export CPUPROFILE
	echo "  running performance tests..."
        if $spindump --input-file $pcap --silent $opts > /dev/null
        then
	    echo "  run ok..."
	else
	    echo "**run failed -- exit"
	    exit 1
	fi
	unset CPUPROFILE
    fi
done
