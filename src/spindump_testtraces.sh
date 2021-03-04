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
###  SPINDUMP (C) 2018-2020 BY ERICSSON RESEARCH
###  AUTHOR: JARI ARKKO
###
###

srcdir=`dirname $0`
testdir=$srcdir/../test
tmpdir=/tmp
debugfile=$tmpdir/spindump.testtraces.dbg
spindump=$srcdir/spindump
rm -f $debugfile
(echo "cwd:";
 pwd;
 echo "srcdir:";
 echo $srcdir;
 echo "testdir:";
 echo $testdir) | tee -a $debugfile

#
# All test cases are listed below. For each test file there needs to
# be a .pcap file, as well as a description (.txt) file and expected
# results from spindump (.expected). There may also be special options
# file (.options).
#

traces="trace_icmpv4_short
        trace_icmpv6_short
        trace_dns_simple
        trace_dns
        trace_ping_aggregate_average
        trace_ping_aggregate_average_text
        trace_ping_aggregate_average_filt
        trace_ping_aggregate_average_filt_max
        trace_ping_aggregate_average_filt_text
        trace_ping_bandwidthperiods1
        trace_ping_bandwidthperiods2
        trace_ping_bandwidthperiods3
        trace_ping_bandwidthperiods4
        trace_ping_bandwidthperiods5
        trace_cmd_jsonfile_notexist
        trace_cmd_jsonfile_syntaxerror
        trace_cmd_jsonfile_empty
        trace_cmd_jsonfile_simple
        trace_cmd_tags_default
        trace_cmd_tags_aggregate
        trace_cmd_aggregate_regular
        trace_cmd_aggregate_default
        trace_cmd_aggregate_multinet
        trace_tcp_short
        trace_tcp_short_qlog
        trace_tcp_short_json trace_dns
        trace_tcp_short_sack
        trace_tcp_tiny1
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
        trace_quic_v23_quant_2k
        trace_quic_v23_picoquic_1k_versneg
        trace_quic_v23_picoquic_5k
        trace_quic_v23_picoquic_25k
        trace_quic_v23_picoquic_25k_noh3
        trace_quic_v23_picoquic_25k_keyupd
        trace_quic_v23_picoquic_25k_cidchange
        trace_quic_v23_picoquicquant_10k_versneg
        trace_quic_v23_picoquicquant_10k_0rtt
        trace_quic_v23_lsquic_simple
        trace_quic_v23_lsquic_complex
        trace_quic_v23_lsquic_fine
        trace_quic_v23_aiortc
        trace_quic_v23_aiortc_spin
        trace_quic_v23_apple
        trace_quic_v23_ats
        trace_quic_v23_ats_retry
        trace_quic_v23_ats_readdr
        trace_quic_v23_msquic
        trace_quic_v23_msquic_h3
        trace_quic_v23_mvfst_h3
        trace_quic_v23_ngtcp2
        trace_quic_v23_cf
        trace_quic_v23_pandora
        trace_quic_v23_quiche
        trace_quic_v23_quicly
        trace_quic_v23_gquic
        trace_quic_v23_quinn
        trace_quic_v23_f5
        trace_quic_v25_quant_short
        trace_quic_v25_quant_long
        trace_quic_v25_quant_long_qrloss
        trace_quic_v25_quant_h3
        trace_quic_v25_quant_0rtt
        trace_quic_v25_quant_quantum
        trace_quic_v25_quant_update
        trace_quic_v25_picoquic
        trace_quic_v25_aiortc
        trace_quic_v25_ogre
        trace_quic_v25_f5
        trace_quic_v25_haskell
        trace_quic_v25_lsquic
        trace_quic_v25_msquic
        trace_quic_v25_mvfst
        trace_quic_v25_ngtcp2
        trace_quic_v25_ngx
        trace_quic_v25_quiche
        trace_quic_v25_quicly
        trace_quic_v25_apple
        trace_quic_v27_mvfst
        trace_quic_v32_quant
        trace_quic_v32_quant_longer
        trace_quic_v33_quant
        trace_quic_v34_quant_short
        trace_quic_rfc_quant_basic
        trace_quic_rfc_quant_long
        trace_quic_rfc_quant_long_qlog
        trace_quic_fail1_quant
        trace_quic_fail2_quant 
        trace_quic_google
        trace_quic_pandora
        trace_quic_apple
        trace_quic_bug_ls
        trace_quic_titalia_delaybit
        trace_quic_titalia_qrloss
        trace_quic_mvfst_d24
        trace_quic_mvfst 
        trace_tunnel_interface_ping
        trace_tcp_medium_snap80
        trace_tcp_large_snap80
        trace_ping_tooold
        trace_icmp_allpackets
        trace_empty
        trace_sctp_short_lo
        trace_sctp_medium
        trace_sctp_snap128
        trace_sctp_two_addr
        trace_sctp_snap128"
        

#
# Check options
#

debugopts=

while [ $# -gt 0 ]
do
    case "x$1" in
        x--debug) debugopts="--debug";
                  shift;;
        x--deepdebug) debugopts="--deepdebug";
                      shift;;
        x--deepdeepdebug) debugopts="--deepdeepdebug";
                          shift;;
        x--help) echo "Usage: spindump_testtraces.sh [options] [testcases]";
                 exit 0;;
        *) traces=`echo $traces | tr " " "\\n" | fgrep -e $1`;
           shift;;
    esac
done

#
# Loop through test cases
#

RESULT=0
FAILCTR=0
FAILED=""
unset CPUPROFILE

for trace in $traces
do
    
    echo "Test case $trace... "

    #
    # Determine the parameters (PCAP files, options etc) of the test case
    #
    
    pcap=$testdir/$trace.pcap
    pcapng=$testdir/$trace.pcapng
    descr=$testdir/$trace.txt
    outpre=$testdir/$trace.out.pre
    out=$testdir/$trace.out
    outerr=$testdir/$trace.out.err
    cmd=$testdir/$trace.cmd
    corr=$testdir/$trace.expected
    noinputfile=$testdir/$trace.noinput
    exitcodefile=$testdir/$trace.exitcode
    optsfile=$testdir/$trace.options
    perfoptsfile=$testdir/$trace.optionsperf
    profilefile=$testdir/$trace.perf
    opts=""
    if [ -f $optsfile ]
    then
        opts=`cat $optsfile | sed 's@ test/@ '$testdir'/@'`
        opts=`eval echo $opts`
    fi
    if [ -f $pcapng ]
    then
        pcap=$pcapng
    fi
    if [ -f $noinputfile ]
    then
        inputfiles=""
    else
        inputfiles="--input-file $pcap"
    fi
    
    #
    # Now run it!
    #

    allopts="$inputfiles --textual --format text --not-report-notes $opts $debugopts"
    echo $spindump $allopts > $cmd
    cat $cmd >> $debugfile
    if $spindump $allopts 2> $outerr > $outpre
     then
        if [ -f $exitcodefile ]
        then
            echo "**run failed by not failing per expectation" | tee -a $debugfile
            RESULT=1
            FAILCTR=`expr $FAILCTR + 1`
            if [ "x$FAILED" = "x" ]; then FAILED=$trace; else FAILED=$FAILED" "$trace; fi
        else
            echo "  run ok..." | tee -a $debugfile
        fi
    else
        if [ -f $exitcodefile ]
        then
            echo "  run ok (expected failure)..." | tee -a $debugfile
        else
            echo "**run failed" | tee -a $debugfile
            RESULT=1
            FAILCTR=`expr $FAILCTR + 1`
            if [ "x$FAILED" = "x" ]; then FAILED=$trace; else FAILED=$FAILED" "$trace; fi
        fi
    fi

    #
    # Filter results to ensure timestamps in some events do not vary
    # from test run to test run.
    #

    cat $outerr $outpre |
    sed 's/ at .* delete / at delete /g' |
    sed 's/ JSON file .*trace_/ JSON file trace_/g' |
    awk '
      /Event.: .delete./ { gsub(/ .Ts.: [0-9]+,/,""); print $0; next; }
      /Event.: .new.*NET2NET.*/ { gsub(/ .Ts.: [0-9]+,/,""); print $0; next; }
      /Event.: .new.*H2NET.*/ { gsub(/ .Ts.: [0-9]+,/,""); print $0; next; }
      /Event.: .new.*NET2MUL.*/ { gsub(/ .Ts.: [0-9]+,/,""); print $0; next; }
      /Event.: .new.*H2MUL.*/ { gsub(/ .Ts.: [0-9]+,/,""); print $0; next; }
      /Event.: .new.*HOSTS.*/ { gsub(/ .Ts.: [0-9]+,/,""); print $0; next; }
      /^H2NET.* new .*/ { gsub(/ at [0-9]+ /," "); print $0; next; }
      /^HOSTS.* new .*/ { gsub(/ at [0-9]+ /," "); print $0; next; }
      /.*/ { print $0; next; }
    ' > $out
    
    #
    # Check results
    #
    
    if [ -f $corr ]
    then
        nop=nop
    else
        echo "**expected results file $corr does not exist" | tee -a $debugfile
        RESULT=1
        FAILCTR=`expr $FAILCTR + 1`
        if [ "x$FAILED" = "x" ]; then FAILED=$trace; else FAILED=$FAILED" "$trace; fi
    fi
    
    if diff $out $corr > /dev/null
    then
        echo "  results correct" | tee -a $debugfile
    else
        echo "**results incorrect" | tee -a $debugfile
        RESULT=1
        FAILCTR=`expr $FAILCTR + 1`
        if [ "x$FAILED" = "x" ]; then FAILED=$trace; else FAILED=$FAILED" "$trace; fi
    fi
    
    if [ -f $descr ]
    then
        nop=nop
    else
        echo "**test description file $descr does not exist" | tee -a $debugfile
        RESULT=1
        FAILCTR=`expr $FAILCTR + 1`
        if [ "x$FAILED" = "x" ]; then FAILED=$trace; else FAILED=$FAILED" "$trace; fi
    fi

    #
    # Should we also do performance measurements? Yes if there's a <testcase>.optionsperf file
    #
    
    if [ -f $perfoptsfile ]
    then
        CPUPROFILE=$profilefile
        export CPUPROFILE
        echo "  running performance tests..."
        if $spindump --input-file $pcap --silent --not-report-notes $opts > /dev/null
        then
            echo "  run ok..."
        else
            echo "**run failed"
            RESULT=1
            FAILCTR=`expr $FAILCTR + 1`
            if [ "x$FAILED" = "x" ]; then FAILED=$trace; else FAILED=$FAILED" "$trace; fi
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
    echo '**** some tests ('$FAILCTR', '$FAILED') failed' | tee -a $debugfile
else
    echo 'all tests ok' | tee -a $debugfile
fi

exit $RESULT
