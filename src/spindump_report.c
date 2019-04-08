
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
spindump_report_cursesinit(void);
static void
spindump_report_cursesfinish(void);
static int
spindump_report_update_comparetwoconnections(const void* data1,
					     const void* data2);

//
// Actual code --------------------------------------------------------------------------------
//

//
// Initialize curses. This is used by the --visual mode of Spindump,
// to reset the screen as it starts.
//

static void
spindump_report_cursesinit(void) {
  
  setlocale(LC_ALL, "");
  initscr();
  cbreak();
  noecho();
  nonl();
  intrflush(stdscr, FALSE);
  keypad(stdscr, TRUE);
  nodelay(stdscr, TRUE);
  
}

//
// Uninitialize curses. This is used by the --visual mode of Spindump,
// to set the screen back to normal as it finishes.
//

static void
spindump_report_cursesfinish(void) {
  
  nodelay(stdscr, FALSE);
  keypad(stdscr, FALSE);
  intrflush(stdscr, TRUE);
  nl();
  echo();
  nocbreak();
  refresh();
  endwin();
  
}

//
// Initialize the reporter function in a way that no reports will be made.
//

struct spindump_report_state*
spindump_report_initialize_quiet(void) {

  //
  // Calculate size and allocate state
  // 
  
  unsigned int size = sizeof(struct spindump_report_state);
  struct spindump_report_state* reporter = (struct spindump_report_state*)spindump_malloc(size);
  if (reporter == 0) {
    spindump_errorf("cannot allocate reporter state of %u bytes", size);
    return(0);
  }

  //
  // Initialize state
  // 
  
  reporter->destination = spindump_report_destination_quiet;
  reporter->anonymizeLeft = 0;
  reporter->anonymizeRight = 0;
  reporter->querier = spindump_reverse_dns_initialize_noop();
  
  //
  // Done. Return state.
  // 
  
  return(reporter);
}

//
// Initialize the reporting function so that reports will be made to
// screen. This is used by the --visual mode of Spindump.
//

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
  struct spindump_report_state* reporter = (struct spindump_report_state*)spindump_malloc(size);
  if (reporter == 0) {
    spindump_errorf("cannot allocate reporter state of %u bytes", size);
    return(0);
  }
  
  //
  // Initialize state
  // 

  reporter->destination = spindump_report_destination_terminal;
  reporter->anonymizeLeft = 0;
  reporter->anonymizeRight = 0;
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

//
// Specify whether the hosts on either side of the measurement point
// should be anonymized or not
//

void
spindump_report_setanonymization(struct spindump_report_state* reporter,
				 int anonymizeLeft,
				 int anonymizeRight) {
  spindump_assert(reporter != 0);
  spindump_assert(spindump_isbool(anonymizeLeft));
  spindump_assert(spindump_isbool(anonymizeRight));
  reporter->anonymizeLeft = anonymizeLeft;
  reporter->anonymizeRight = anonymizeRight;
}

//
// Check which of two connections should be displayed higher in the
// --visual mode of Spindump. The highest connections are the ones
// with most packets.
//

typedef const struct spindump_connection* spindump_connection_constptr;
static int
spindump_report_update_comparetwoconnections(const void* data1,
					     const void* data2) {
  const spindump_connection_constptr* elem1 = (const spindump_connection_constptr*)data1;
  const spindump_connection_constptr* elem2 = (const spindump_connection_constptr*)data2;
  const struct spindump_connection* connection1 = *elem1;
  const struct spindump_connection* connection2 = *elem2;
  unsigned long packets1 = connection1->packetsFromSide1 + connection1->packetsFromSide2;
  unsigned long packets2 = connection2->packetsFromSide1 + connection2->packetsFromSide2;
  //spindump_deepdebugf("comparetwoconnections %u (%lu) vs. %u (%lu)", connection1->id, packets1, connection2->id, packets2);
  if (packets1 < packets2) {
    return(1);
  } else if (packets1 > packets2) {
    return(-1);
  } else {
    return(0);
  }
}

//
// Update the screen
//

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
    int y = 0;
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
    if (LINES < 7 || ((unsigned int)COLS) < spindump_connection_report_brief_fixedsize((unsigned int)LINES) + 5) {
      
      mvaddstr(y++, 0, "TOO SMALL");
      
    } else {
      
      mvaddstr(y++, 0, "SPINDUMP   ");
      mvaddstr(y++, 0, "           ");
      mvaddstr(y++, 0, connectionsstatus);
      reporter->inputlineposition = y;
      mvaddstr(y++, 0, "           ");
      char columnsbuf[spindump_report_maxlinelen];
      unsigned int addrsiz = spindump_connection_report_brief_variablesize((unsigned int)COLS);
      unsigned int maxsessionlen = spindump_connection_report_brief_sessionsize((unsigned int)COLS);
      snprintf(columnsbuf,sizeof(columnsbuf)-1,
	       "%-7s %-*s %-*s %8s %6s %10s %10s",
	       "TYPE",addrsiz,"ADDRESSES",maxsessionlen,"SESSION","STATE","PAKS","LEFT RTT","RIGHT RTT");
      if (spindump_connection_report_brief_isnotefield((unsigned int)COLS)) {
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

      int actualConnections = 0;
#     define maxActualConnections 200
      struct spindump_connection* actualTable[maxActualConnections];
      
      spindump_deepdebugf("report gathering");
      for (i = 0;
	   (i < table->nConnections &&
	    actualConnections < maxActualConnections &&
	    actualConnections < (LINES - y));
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
	    (size_t)actualConnections,
	    sizeof(struct spindump_connection*),
	    spindump_report_update_comparetwoconnections);
	
      //
      // Now display the resulting table
      // 
      
      spindump_deepdebugf("report displaying");
      int j;
      for (j = 0; j < actualConnections; j++) {
	char connectionbuf[spindump_report_maxlinelen];
	spindump_assert(actualTable[j] != 0);
	spindump_deepdebugf("report displaying connection %u", actualTable[j]->id);
	spindump_connection_report_brief(actualTable[j],
					 connectionbuf,
					 sizeof(connectionbuf),
					 average,
					 (unsigned int)COLS,
					 reporter->anonymizeLeft,
					 reporter->anonymizeRight,
					 reporter->querier);
	mvaddstr(y++, 0, connectionbuf);
	
      }
    }

    spindump_deepdebugf("report refreshing");
    refresh();
   
  }
  
}

//
// Put current input to a keyboard command (e.g., "s") to the screen
//

static
void spindump_report_putcurrentinputonscreen(struct spindump_report_state* reporter,
					     const char* string,
					     const char* value) {
  for (int i = 0;
       i < COLS;
       i++) {
    mvaddstr(reporter->inputlineposition, i, " ");
  }
  mvaddstr(reporter->inputlineposition, 0, string);
  mvaddstr(reporter->inputlineposition, (int)(strlen(string)), value);
  refresh();
}

//
// Display an error on the screen
//

static
void spindump_report_puterroronscreen(struct spindump_report_state* reporter,
				      const char* string) {
  spindump_report_putcurrentinputonscreen(reporter,"Error: ",string);
}

//
// Implement the "s" command, to change the update interval of the screen
//

static
int
spindump_report_checkinput_updateinterval(struct spindump_report_state* reporter,
					  double* p_argument) {
  spindump_report_putcurrentinputonscreen(reporter,"interval: ","");
  int ch;
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

//
// Check if there's any input from user. This function returns the
// abstract command given by the user, or spindump_report_command_none
// otherwise.
//
// Some commands may take a numeric input parameter. Such a parameter
// is stored in the output parameter p_argument.
//

enum spindump_report_command
spindump_report_checkinput(struct spindump_report_state* reporter,
			   double* p_argument) {
  
    int ch;
    
    if ((ch = getch()) == ERR) {
      
      return(spindump_report_command_none);
      
    } else {
      
      char c = (char)(tolower((char)ch));
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

//
// Show help in the visual mode
//

void
spindump_report_showhelp(struct spindump_report_state* reporter) {
  
  int y = 0;
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

//
// Uninitialize the reporter object, and reset the screen back to
// normal if we used the screen UI (--visual mode of Spindump).
//

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
    spindump_errorf("invalid reporter destination");
    break;
  }
  
  //
  // Make memory contents improper (to catch possible later references
  // to this area), and free the memory.
  // 
  
  memset(reporter,0xFF,sizeof(*reporter));
  spindump_free(reporter);
}
