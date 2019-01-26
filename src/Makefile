
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

SPINDUMP_LIB_HEADERS	=	spindump_util.h \
				spindump_packet.h \
				spindump_protocols.h \
				spindump_capture.h \
				spindump_connections_structs.h \
				spindump_connections.h \
				spindump_connections_set.h \
				spindump_connections_set_iterator.h \
				spindump_table_structs.h \
				spindump_table.h \
				spindump_test.h \
				spindump_analyze.h \
				spindump_analyze_icmp.h \
				spindump_analyze_tcp.h \
				spindump_analyze_udp.h \
				spindump_analyze_dns.h \
				spindump_analyze_coap.h \
				spindump_analyze_tls_parser.h \
				spindump_analyze_quic.h \
				spindump_analyze_quic_parser.h \
				spindump_analyze_aggregate.h \
				spindump_reversedns.h \
				spindump_rtt.h \
				spindump_mid.h \
				spindump_seq.h \
				spindump_spin.h \
				spindump_spin_structs.h \
				spindump_stats.h \
				spindump_remote.h \
				spindump_report.h \
				spindump_main.h
SPINDUMP_LIB_SOURCES	=	spindump_util.c \
				spindump_capture.c \
				spindump_connections.c \
				spindump_connections_print.c \
				spindump_connections_new.c \
				spindump_connections_search.c \
				spindump_connections_set.c \
				spindump_connections_set_iterator.c \
				spindump_packet.c \
				spindump_protocols.c \
				spindump_table.c \
				spindump_analyze.c \
				spindump_analyze_icmp.c \
				spindump_analyze_tcp.c \
				spindump_analyze_udp.c \
				spindump_analyze_dns.c \
				spindump_analyze_coap.c \
				spindump_analyze_tls_parser.c \
				spindump_analyze_quic.c \
				spindump_analyze_quic_parser.c \
				spindump_analyze_aggregate.c \
				spindump_reversedns.c \
				spindump_rtt.c \
				spindump_mid.c \
				spindump_seq.c \
				spindump_spin.c \
				spindump_stats.c \
				spindump_remote.c \
				spindump_report.c
SPINDUMP_LIB_OBJECTS	=	spindump_util.o \
				spindump_connections.o \
				spindump_connections_print.o \
				spindump_connections_new.o \
				spindump_connections_search.o \
				spindump_connections_set.o \
				spindump_connections_set_iterator.o \
				spindump_packet.o \
				spindump_protocols.o \
				spindump_table.o \
				spindump_analyze.o \
				spindump_analyze_icmp.o \
				spindump_analyze_tcp.o \
				spindump_analyze_udp.o \
				spindump_analyze_dns.o \
				spindump_analyze_coap.o \
				spindump_analyze_tls_parser.o \
				spindump_analyze_quic.o \
				spindump_analyze_quic_parser.o \
				spindump_analyze_aggregate.o \
				spindump_rtt.o \
				spindump_mid.o \
				spindump_seq.o \
				spindump_spin.o \
				spindump_stats.o \
				spindump_reversedns.o
SPINDUMP_CMD_SOURCES	=	spindump_main.c
SPINDUMP_CMD_OBJECTS	=	spindump_main.o
SPINDUMP_CMDLIB_OBJECTS	=	spindump_capture.o \
				spindump_remote.o \
				spindump_report.o
SPINDUMP_TST_SOURCES	=	spindump_test.c
SPINDUMP_TST_OBJECTS	=	spindump_test.o
SPINDUMP_LIB		=	spindump.a
SPINDUMP_CMDLIB		=	spindumpcmd.a
SPINDUMP_CMD		=	spindump
SPINDUMP_TST		=	spindump_test
SPINDUMP_TAR		=	spindump.tar.gz
SPINDUMP_OTHER_SOURCES	=	Makefile \
				../Makefile
SPINDUMP_OTHER_FILES	=	../README.md \
				../images/architecture1.jpg \
				../images/architecture2.jpg \
				../images/architecture2s.jpg \
				../images/screenshot1.jpg \
				../images/screenshot1.png
SPINDUMP_ALL_SOURCES	=	$(SPINDUMP_LIB_HEADERS) \
				$(SPINDUMP_LIB_SOURCES) \
				$(SPINDUMP_CMD_SOURCES) \
				$(SPINDUMP_TST_SOURCES) \
				$(SPINDUMP_OTHER_SOURCES)
CFLAGS			=	-Wall --pedantic $(OPTFLAGS)
#OPTFLAGS		=	-O3
OPTFLAGS		=	-g -DSPINDUMP_DEBUG
LDFLAGS			=	-lpthread -lpcap -lncurses -lm
CC			=	gcc
LD			=	$(CC)
AR			=	ar

all:	$(SPINDUMP_LIB) \
	$(SPINDUMP_LIB) \
	$(SPINDUMP_CMD) \
	$(SPINDUMP_TST) \
	$(SPINDUMP_TAR)

$(SPINDUMP_CMD):	$(SPINDUMP_CMD_OBJECTS) \
			$(SPINDUMP_CMDLIB) \
			$(SPINDUMP_LIB)
	$(LD) -o $(SPINDUMP_CMD) $(SPINDUMP_CMD_OBJECTS) $(SPINDUMP_CMDLIB) $(SPINDUMP_LIB) $(LDFLAGS)

$(SPINDUMP_TST):	$(SPINDUMP_TST_OBJECTS) \
			$(SPINDUMP_LIB)
	$(LD) -o $(SPINDUMP_TST) $(SPINDUMP_TST_OBJECTS) $(SPINDUMP_LIB) $(LDFLAGS)
	./$(SPINDUMP_TST)

$(SPINDUMP_LIB_OBJECTS):	$(SPINDUMP_LIB_HEADERS) \
				$(SPINDUMP_OTHER_SOURCES)

$(SPINDUMP_CMD_OBJECTS):	$(SPINDUMP_LIB_HEADERS) \
				$(SPINDUMP_OTHER_SOURCES)

$(SPINDUMP_CMDLIB_OBJECTS):	$(SPINDUMP_LIB_HEADERS) \
				$(SPINDUMP_OTHER_SOURCES)

$(SPINDUMP_LIB):	$(SPINDUMP_LIB_OBJECTS)
	$(AR) -crv $(SPINDUMP_LIB) $(SPINDUMP_LIB_OBJECTS)

$(SPINDUMP_CMDLIB):	$(SPINDUMP_CMDLIB_OBJECTS)
	$(AR) -crv $(SPINDUMP_CMDLIB) $(SPINDUMP_CMDLIB_OBJECTS)

.c.o:
	$(CC) -c $(CFLAGS) $<

$(SPINDUMP_TAR):	$(SPINDUMP_ALL_SOURCES) \
			$(SPINDUMP_OTHER_FILES)
	-rm -f $(SPINDUMP_TAR)
	tar czf $(SPINDUMP_TAR) $(SPINDUMP_ALL_SOURCES) $(SPINDUMP_OTHER_FILES)

test:	$(SPINDUMP_TST)

install:	$(SPINDUMP_CMD)
	cp -f $(SPINDUMP_CMD) /usr/local/bin/$(SPINDUMP_CMD)

uninstall:
	rm -f /usr/local/bin/$(SPINDUMP_CMD)

wc:
	wc	$(SPINDUMP_ALL_SOURCES)

clean:
	-rm -f $(SPINDUMP_TAR)
	-rm -f $(SPINDUMP_LIB)
	-rm -f $(SPINDUMP_CMDLIB)
	-rm -f $(SPINDUMP_LIB_OBJECTS) $(SPINDUMP_CMDLIB_OBJECTS) $(SPINDUMP_CMD_OBJECTS) $(SPINDUMP_TST_OBJECTS)
	-rm -f $(SPINDUMP_CMD) $(SPINDUMP_TST)
	-rm -f spindump.debug

