#!/bin/sh

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

PROG=$1

if [ -f $PROG ]
then
       nop=ok
else
    echo no file src/spindump, running in wrong directory or make not executed yet
    exit 1
fi

BASE=`basename $PROG`

if [ "x$BASE" = xspindump ]
then
    nop=ok
else
    echo unexpected argument
    exit 1
fi

if [ `uname` = "Linux" ]
then
    if chown root:root $PROG
    then
	nop=ok
    else
	echo cannot chown
	exit 1
    fi
    if chmod 04755 $PROG
    then
	nop=ok
    else
	echo cannot chmod
	exit 1
    fi
else
    if chmod 0755 $PROG
    then
	nop=ok
    else
	echo cannot chmod
	exit 1
    fi
fi

exit 0
