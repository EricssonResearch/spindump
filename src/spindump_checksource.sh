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

#
# Redirect output to stderr.
#

exec 1>&2

#
# What files do we have?
#

files=`find . -name 'spindump_*.*'|grep -v CMakeFiles|grep -v checksource`

#
# search for tabs
#

if fgrep -l "	" /dev/null $files > /dev/null
then
  (echo spindump: error: files contain tab characters, please use spaces instead:
   fgrep -l "	" /dev/null $files) | tee /tmp/checksource.err
  exit 1
else
  exit 0
fi

