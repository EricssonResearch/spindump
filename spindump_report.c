
//
//
//  ////////////////////////////////////////////////////////////////////////////////////
//  /////////                                                                ///////////
//  //////       SSS    PPPP    I   N    N   DDDD    U   U   M   M   PPPP         //////
//  //          S       P   P   I   NN   N   D   D   U   U   MM MM   P   P            //
//  /            SSS    PPPP    I   N NN N   D   D   U   U   M M M   PPPP              /
//  //              S   P       I   N   NN   D   D   U   U   M   M   P                //
//  ////         SSS    P       I   N    N   DDDD     UUU    M   M   P            //////
//  /////////                                                                ///////////
//  ////////////////////////////////////////////////////////////////////////////////////
//
//  SPINDUMP (C) 2018-2019 BY ERICSSON RESEARCH
//  AUTHOR: JARI ARKKO
//
// 

//
// Includes -----------------------------------------------------------------------------------
//

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <locale.h>
#include <curses.h>
#include "spindump_util.h"
#include "spindump_report.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static void
spindump_report_cursesinit();
static void
spindump_report_cursesfinish();
static int
spindump_report_update_comparetwoconnections(const void* data1,
					     const void* data2);

//
// Actual code --------------------------------------------------------------------------------
//

static void
spindump_report_cursesinit() {
  
  setlocale(LC_ALL, "");
  initscr();
  cbreak();
  noecho();
  nonl();
  intrflush(stdscr, FALSE);
  keypad(stdscr, TRUE);
  nodelay(stdscr, TRUE);
  
}

static void
spindump_report_cursesfinish() {
  
  nodelay(stdscr, FALSE);
  keypad(stdscr, FALSE);
  intrflush(stdscr, TRUE);
  nl();
  echo();
  nocbreak();
  refresh();
  endwin();
  
}

struct spindump_report_state*
spindump_report_initialize_quiet() {

  //
  // Calculate size and allocate state
  // 
  
  unsigned int size = sizeof(struct spindump_report_state);
  struct spindump_report_state* reporter = (struct spindump_report_state*)malloc(size);
  if (reporter == 0) {
    spindump_fatalf("cannot allocate reporter state of %u bytes", size);
    return(0);
  }

  //
  // Initialize state
  // 
  
  reporter->destination = spindump_report_destination_quiet;
  reporter->querier = spindump_reverse_dns_initialize_noop();
  
  //
  // Done. Return state.
  // 
  
  return(reporter);
}

struct spindump_report_state*
spindump_report_initialize_terminal(struct spindump_reverse_dns* querier) {

  //
  // Checks
  // 
  
  spindump_assert(querier != 0);
  
  //
  // Calculate size and allocate state
  // 
      
  unsigned int size = sizeof(struct spindump_report_state);
  struct spindump_report_state* reporter = (struct spindump_report_state*)malloc(size);
  if (reporter == 0) {
    spindump_fatalf("cannot allocate reporter state of %u bytes", size);
    return(0);
  }
  
  //
  // Initialize state
  // 

  reporter->destination = spindump_report_destination_terminal;
  reporter->querier = querier;
  
  //
  // Initialize screen settings
  // 
  
  spindump_report_cursesinit();
  reporter->inputlineposition = 0;
  
  //
  // Done. Return state.
  // 
  
  return(reporter);
}

static int
spindump_report_update_comparetwoconnections(const void* data1,
					     const void* data2) {
  const struct spindump_connection** elem1 = (const struct spindump_connection**)data1;
  const struct spindump_connection** elem2 = (const struct spindump_connection**)data2;
  //spindump_deepdebugf("elem1 = %lx", elem1);
  //spindump_deepdebugf("elem2 = %lx", elem2);
  const struct spindump_connection* connection1 = *elem1;
  const struct spindump_connection* connection2 = *elem2;
  //spindump_deepdebugf("connection1 = %lx", connection1);
  //spindump_deepdebugf("connection2 = %lx", connection2);
  unsigned long packets1 = connection1->packetsFromSide1 + connection1->packetsFromSide2;
  unsigned long packets2 = connection2->packetsFromSide1 + connection2->packetsFromSide2;
  //spindump_deepdebugf("comparetwoconnections %u (%lu) vs. %u (%lu)", connection1->id, packets1, connection2->id, packets2);
  if (packets1 < packets2) return(1);
  else if (packets1 > packets2) return(-1);
  else return(0);
}

void
spindump_report_update(struct spindump_report_state* reporter,
		       int average,
		       int aggregate,
		       int closed,
		       int udp,
		       struct spindump_connectionstable* table,
		       struct spindump_stats* stats) {
  
  spindump_assert(reporter != 0);
  spindump_assert(average == 0 || average == 1);
  spindump_assert(aggregate == 0 || aggregate == 1);
  spindump_assert(closed == 0 || closed == 1);
  spindump_assert(udp == 0 || udp == 1);
  spindump_assert(table != 0);
  spindump_assert(stats != 0);

  if (reporter->destination == spindump_report_destination_terminal) {

    char connectionsstatus[300];
    unsigned int y = 0;
    unsigned int i;
    
    snprintf(connectionsstatus,sizeof(connectionsstatus)-1,"%u connections %s packets %s bytes",
	     table->nConnections,
	     spindump_meganumber_tostring(stats->receivedIp + stats->receivedIpv6),
	     spindump_meganumberll_tostring(stats->receivedIpBytes + stats->receivedIpv6Bytes));
    snprintf(connectionsstatus+strlen(connectionsstatus),
	     sizeof(connectionsstatus)-strlen(connectionsstatus)-1,
	     " (showing %s%s%s%s)",
	     average ? "avg RTTs" : "latest RTTs",
	     aggregate ? ", aggregated connections" : "",
	     udp ? "" : ", not showing UDP",
	     closed ? "" : (udp ? ", not showing closed" : " or closed"));
    
    clear();
    
    spindump_deepdebugf("report start done");
    if (LINES < 7 || COLS < spindump_connection_report_brief_fixedsize(LINES) + 5) {
      
      mvaddstr(y++, 0, "TOO SMALL");
      
    } else {
      
      mvaddstr(y++, 0, "SPINDUMP   ");
      mvaddstr(y++, 0, "           ");
      mvaddstr(y++, 0, connectionsstatus);
      reporter->inputlineposition = y;
      mvaddstr(y++, 0, "           ");
      char columnsbuf[200];
      unsigned int addrsiz = spindump_connection_report_brief_variablesize(COLS);
      unsigned int maxsessionlen = spindump_connection_report_brief_sessionsize(COLS);
      snprintf(columnsbuf,sizeof(columnsbuf)-1,
	       "%-7s %-*s %-*s %8s %6s %10s %10s",
	       "TYPE",addrsiz,"ADDRESSES",maxsessionlen,"SESSION","STATE","PAKS","LEFT RTT","RIGHT RTT");
      if (spindump_connection_report_brief_isnotefield(COLS)) {
	snprintf(columnsbuf+strlen(columnsbuf),sizeof(columnsbuf)-1-strlen(columnsbuf),"  %-*s",
		 spindump_connection_report_brief_notefieldval_length(),
		 "NOTE");
      }
      mvaddstr(y++, 0, columnsbuf);
      mvaddstr(y++, 0, "");
      
      //
      // Create a second table with the active connections that we
      // want to display (but keep them at maximum so that we can fit
      // one connection for each line in the screen).
      // 

      unsigned int actualConnections = 0;
#     define maxActualConnections 200
      struct spindump_connection* actualTable[maxActualConnections];
      
      spindump_deepdebugf("report gathering");
      for (i = 0;
	   (i < table->nConnections &&
	    actualConnections < maxActualConnections &&
	    actualConnections < LINES - y);
	   i++) {
	struct spindump_connection* connection = table->connections[i];
	if (connection != 0 &&
	    ((connection->type != spindump_connection_transport_udp &&
	      connection->type != spindump_connection_transport_dns) ||
	     udp) &&
	    (!spindump_connections_isclosed(connection) || closed) &&
	    spindump_connections_isaggregate(connection) == aggregate) {
	  actualTable[actualConnections++] = connection;
	}
      }
      
      //
      // Sort the gathered connections per largest packet counters
      // 

      spindump_deepdebugf("report sorting");
      qsort(&actualTable[0],
	    actualConnections,
	    sizeof(struct spindump_connection*),
	    spindump_report_update_comparetwoconnections);
	
      //
      // Now display the resulting table
      // 
      
      spindump_deepdebugf("report displaying");
      for (i = 0; i < actualConnections; i++) {
	char connectionbuf[300];
	spindump_connection_report_brief(actualTable[i],
					 connectionbuf,
					 sizeof(connectionbuf),
					 average,
					 COLS,
					 reporter->querier);
	mvaddstr(y++, 0, connectionbuf);
	
      }
    }

    spindump_deepdebugf("report refreshing");
    refresh();
   
  }
  
}

static
void spindump_report_putcurrentinputonscreen(struct spindump_report_state* reporter,
					     const char* string,
					     const char* value) {
  for (unsigned int i = 0; i < COLS; i++) mvaddstr(reporter->inputlineposition, i, " ");
  mvaddstr(reporter->inputlineposition, 0, string);
  mvaddstr(reporter->inputlineposition, strlen(string), value);
  refresh();
}

static
void spindump_report_puterroronscreen(struct spindump_report_state* reporter,
				      const char* string) {
  spindump_report_putcurrentinputonscreen(reporter,"Error: ",string);
}

static
int
spindump_report_checkinput_updateinterval(struct spindump_report_state* reporter,
					  double* p_argument) {
  spindump_report_putcurrentinputonscreen(reporter,"interval: ","");
  unsigned int ch;
  char buf[20];
  memset(buf,0,sizeof(buf));
  while ((ch = getch()) != '\n' && ch != '\r' && strlen(buf) < sizeof(buf)-1) {
    if (ch != ERR) {
      buf[strlen(buf)] = (char)ch;
      spindump_report_putcurrentinputonscreen(reporter,"interval: ",buf);
      spindump_deepdebugf("spindump_report_checkinput_updateinterval current interval string is %s", buf);
    }
  }
  spindump_report_putcurrentinputonscreen(reporter,"","");
  double interval = atof(buf);
  if (interval == 0.0) {
    spindump_report_puterroronscreen(reporter,"invalid interval, must be a floating point number");
    return(0);
  } else if (interval < 0.0) {
    spindump_report_puterroronscreen(reporter,"invalid interval, must be positive");
    return(0);
  } else if (interval < 0.1) {
    spindump_report_puterroronscreen(reporter,"invalid interval, must be at least 0.1s");
    return(0);
  } else {
    *p_argument = interval;
    spindump_deepdebugf("spindump_report_checkinput_updateinterval interval is %f", interval);
    return(1);
  }
}

enum spindump_report_command
spindump_report_checkinput(struct spindump_report_state* reporter,
			   double* p_argument) {
  
    unsigned int ch;
    
    if ((ch = getch()) == ERR) {
      
      return(spindump_report_command_none);
      
    } else {
      
      char c = tolower((char)ch);
      switch (c) {
      case 'q': return(spindump_report_command_quit);
      case 'h': return(spindump_report_command_help);
      case 'g': return(spindump_report_command_toggle_average);
      case 'a': return(spindump_report_command_toggle_aggregate);
      case 'c': return(spindump_report_command_toggle_closed);
      case 'u': return(spindump_report_command_toggle_udp);
      case 's':
	if (spindump_report_checkinput_updateinterval(reporter,p_argument)) {
	  return(spindump_report_command_update_interval);
	} else {
	  return(spindump_report_command_none);
	}
	
      default: return(spindump_report_command_none);
      }
      
    }
    
}

void
spindump_report_showhelp(struct spindump_report_state* reporter) {
  
  unsigned int y = 0;
  int ch;
  
  clear();

  if (LINES < 10 || COLS < 40) {
    
    mvaddstr(y++, 0, "TOO SMALL");
    
  } else {
    
    mvaddstr(y++, 0, "SPINDUMP   ");
    mvaddstr(y++, 0, "");
    mvaddstr(y++, 0, "USAGE:");
    mvaddstr(y++, 0, "");
    mvaddstr(y++, 0, "The tool shows active sessions. Screen updates");
    mvaddstr(y++, 0, "automatically as packets pass by.");
    mvaddstr(y++, 0, "");
    mvaddstr(y++, 0, "You can also use these keys:");
    mvaddstr(y++, 0, "");
    mvaddstr(y++, 0, "    G     Toggle average RTT mode, showing either the");
    mvaddstr(y++, 0, "          latest RTT measurements or a moving average.");
    mvaddstr(y++, 0, "    A     Toggle aggregate mode, showing either");
    mvaddstr(y++, 0, "          connections or host pairs.");
    mvaddstr(y++, 0, "    C     Toggle showing of closed connections");
    mvaddstr(y++, 0, "    U     Toggle showing of UDP connections");
    mvaddstr(y++, 0, "    S     Set the update period");
    mvaddstr(y++, 0, "    H     Display a help screen");
    mvaddstr(y++, 0, "    Q     Quit");
    mvaddstr(y++, 0, "");
    mvaddstr(y++, 0, "");
    mvaddstr(y++, 0, "Press any key to continue");
    mvaddstr(y++, 0, "");
    
  }
  
  refresh();
  while ((ch = getch()) == ERR);
}

void
spindump_report_uninitialize(struct spindump_report_state* reporter) {

  //
  // Checks
  // 
  
  spindump_assert(reporter != 0);
  spindump_assert(reporter->querier != 0);

  //
  // Deallocate querier, if we allocated it ourselves
  // 
  
  if (reporter->destination == spindump_report_destination_quiet) {
    spindump_reverse_dns_uninitialize(reporter->querier);
  }
  
  //
  // Restore terminal state if needed
  // 
  
  switch (reporter->destination) {
  case spindump_report_destination_quiet:
    break;
  case spindump_report_destination_terminal:
    spindump_report_cursesfinish();
    break;
  default:
    spindump_fatalf("invalid reporter destination");
    break;
  }
  
  //
  // Make memory contents improper (to catch possible later references
  // to this area), and free the memory.
  // 
  
  memset(reporter,0xFF,sizeof(*reporter));
  free(reporter);
}
