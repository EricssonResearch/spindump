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

traces="trace_icmpv4_short trace_icmpv6_short trace_tcp_short trace_tcp_short_json trace_dns trace_quic_v18_short_spin trace_quic_v18_short_spin_all trace_quic_v18_long_spin trace_quic_v18_long_spin_all trace_quic_google trace_quic_bug_ls"

#
# Loop through test cases
#

for trace in $traces
do
    
    echo "Test case $trace... "
    pcap=$testdir/$trace.pcap
    descr=$testdir/$trace.txt
    out=$testdir/$trace.out
    corr=$testdir/$trace.expected
    optsfile=$testdir/$trace.options
    opts=""
    if [ -f $optsfile ]
    then
	opts=`cat $optsfile`
    fi
    if $spindump --input-file $pcap --textual --format text $opts > $out
    then
	echo "  run ok..."
    else
	echo "**run failed -- exit"
	exit 1
    fi
    
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
    
done
