#!/bin/bash

###
###
###  ######################################################################
###  #######                                                      #########
###  ####      SSS   PPPP   I  N    N  DDDD   U   U  M   M  PPPP       ####
###  #        S      P   P  I  NN   N  D   D  U   U  MM MM  P   P         #
###  #         SSS   PPPP   I  N NN N  D   D  U   U  M M M  PPPP          #
###  #            S  P      I  N   NN  D   D  U   U  M   M  P             #
###  ####      SSS   P      I  N    N  DDDD    UUU   M   M  P          ####
###  #######                                                      #########
###  ######################################################################
###
###  SPINDUMP (C) 2018-2019 BY ERICSSON RESEARCH
###  AUTHOR: JARI ARKKO
###
###

srcdir=`dirname $0`
testdir=$srcdir/../test
spindump=$srcdir/spindump

#
# All test cases are listed below. For each test file there needs to
# be a .pcap file, as well as a description (.txt) file and expected
# results from spindump (.expected). There may also be special options
# file (.options).
#

traces="trace_icmpv4_short
        trace_icmpv6_short
        trace_ping_aggregate_average
        trace_tcp_short
        trace_tcp_short_json trace_dns
        trace_quic_v18_short_spin
        trace_quic_v18_short_spin_all
        trace_quic_v18_long_spin
        trace_quic_v18_long_spin_all
        trace_quic_v19_short_quant
        trace_quic_v20_medium_quant
        trace_quic_v20_no0rtt_quant
        trace_quic_v20_0rtt_quant  
        trace_quic_v22_quant_short
        trace_quic_v22_quant_long
        trace_quic_v22_picoquic_short
        trace_quic_v22_picoquic_long
        trace_quic_v22_picoquic_h3
        trace_quic_fail1_quant
        trace_quic_fail2_quant 
        trace_quic_google
        trace_quic_pandora
        trace_quic_apple
        trace_quic_bug_ls 
        trace_tunnel_interface_ping
        trace_tcp_medium_snap80
        trace_tcp_large_snap80"

#
# Loop through test cases
#

RESULT=0
FAILCTR=0
unset CPUPROFILE

for trace in $traces
do
    
    echo "Test case $trace... "

    #
    # Determine the parameters (PCAP files, options etc) of the test case
    #
    
    pcap=$testdir/$trace.pcap
    descr=$testdir/$trace.txt
    outpre=$testdir/$trace.out.pre
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
    
    if $spindump --input-file $pcap --textual --format text $opts > $outpre
    then
        echo "  run ok..."
    else
        echo "**run failed"
        RESULT=1
        FAILCTR=`expr $FAILCTR + 1`
    fi

    #
    # Filter results to ensure timestamps in some events do not vary
    # from test run to test run.
    #

    awk '
      /Event.: .delete./ { gsub(/ .Ts.: [0-9]+,/,""); print $0; next; }
      /Event.: .new.*H2NET.*/ { gsub(/ .Ts.: [0-9]+,/,""); print $0; next; }
      /.*/ { print $0; next; }
    ' < $outpre > $out
    
    #
    # Check results
    #
    
    if [ -f $corr ]
    then
        nop=nop
    else
        echo "**expected results file $corr does not exist"
        RESULT=1
        FAILCTR=`expr $FAILCTR + 1`
    fi
    
    if diff $out $corr > /dev/null
    then
        echo "  results correct"
    else
        echo "**results incorrect"
        RESULT=1
        FAILCTR=`expr $FAILCTR + 1`
    fi
    
    if [ -f $descr ]
    then
        nop=nop
    else
        echo "**test description file $descr does not exist"
        RESULT=1
        FAILCTR=`expr $FAILCTR + 1`
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
            echo "**run failed"
            RESULT=1
            FAILCTR=`expr $FAILCTR + 1`
        fi
        unset CPUPROFILE
    fi
done

#
# Done. Exit with 1 if there was an error
#

echo ''
if [ $RESULT = 1 ]
then
    echo '**** some tests failed'
else
    echo 'all tests ok'
fi

exit $RESULT
