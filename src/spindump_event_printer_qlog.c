
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
//  SPINDUMP (C) 2018-2021 BY ERICSSON RESEARCH
//  AUTHOR: JARI ARKKO
//
// 

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "spindump_util.h"
#include "spindump_event.h"
#include "spindump_event_printer_qlog.h"
#include "spindump_connections.h"
#include "spindump_json.h"
#include "spindump_json_value.h"

//
// Variables ----------------------------------------------------------------------------------
//

// Table of CRCs of all 8-bit messages. Taken from RFC 1952.
static unsigned long crc_table[256];

// Flag: has the table been computed? Initially false. Taken from RFC 1952.
static int crc_table_computed = 0;

//
// Function Prototypes ------------------------------------------------------------------------
//

static void spindump_event_printer_qlog_print_basicinfo(const struct spindump_event* event,
                                                        char* buffer,
                                                        size_t length);
static uint16_t spindump_event_printer_qlog_getsport(const char* session);
static uint16_t spindump_event_printer_qlog_getdport(const char* session);
static void spindump_event_printer_qlog_getscid(const char* session,
                                                char* buffer,
                                                size_t length);
static void spindump_event_printer_qlog_getdcid(const char* session,
                                                char* buffer,
                                                size_t length);
static void spindump_event_printer_qlog_print_measurements(const struct spindump_event* event,
                                                           char* buffer,
                                                           size_t length);
static void spindump_event_printer_qlog_print_type_specific_measurements(const struct spindump_event* event,
                                                                         char* buffer,
                                                                         size_t length);
static unsigned long spindump_event_printer_qlog_generate_groupid(const struct spindump_event* event);
static void spindump_event_printer_qlog_make_crc_table(void);
static unsigned long spindump_event_printer_qlog_update_crc(unsigned long crc,
                                                            const unsigned char *buf,
                                                            size_t len);
static unsigned long spindump_event_printer_qlog_crc(const unsigned char *buf,
                                                     size_t len);

//
// Functions ----------------------------------------------------------------------------------
//

//
// Take an event description in the input parameter "event", and print
// it out as a JSON-formatted Qlog event. The printed version will
// be placed in the buffer "buffer" whose length is at most "length".
//
// If successful, in other words, if there was enough space in the
// buffer, return 1, otherwise 0. Set the output parameter "consumed" to
// the number of consumed bytes.
//

int
spindump_event_printer_qlog_print(const struct spindump_event* event,
                                  char* buffer,
                                  size_t length,
                                  size_t* consumed) {

  //
  // Sanity checks
  //

  spindump_assert(event != 0);
  spindump_assert(buffer != 0);
  spindump_assert(consumed != 0);
  spindump_deepdeepdebugf("printing a qlog event, buffer size = %u", length);
  
  //
  // Check length
  //
  
  if (length < 2) return(0);
  memset(buffer,0,length);

  //
  // Some utilities to put strings onto the buffer
  //
  
#define addtobuffer1(x)     snprintf(buffer + strlen(buffer),length - 1 - strlen(buffer),x)
#define addtobuffer2(x,y)   snprintf(buffer + strlen(buffer),length - 1 - strlen(buffer),x,y)
#define addtobuffer3(x,y,z) snprintf(buffer + strlen(buffer),length - 1 - strlen(buffer),x,y,z)

  addtobuffer1("     {");
  addtobuffer2("\"time\": %llu, ", event->timestamp);
  addtobuffer2("\"protocol_type\": %s, ", spindump_connection_type_to_string(event->connectionType));
  addtobuffer2("\"group_id\": \"sd-%lu\", ", spindump_event_printer_qlog_generate_groupid(event));
  addtobuffer1("\"event\": \"");
  int reportbasic = 0;
  switch (event->eventType) {
  case spindump_event_type_new_connection: addtobuffer1("connection_started"); reportbasic = 1; break;
  case spindump_event_type_connection_delete: addtobuffer1("connection_closed"); break;
  case spindump_event_type_change_connection:
  case spindump_event_type_new_rtt_measurement:
  case spindump_event_type_spin_flip:
  case spindump_event_type_spin_value:
  case spindump_event_type_ecn_congestion_event:
  case spindump_event_type_rtloss_measurement:
  case spindump_event_type_qrloss_measurement:
  case spindump_event_type_qlloss_measurement:
  case spindump_event_type_periodic:
  case spindump_event_type_packet:
  default: addtobuffer1("measurement"); break;
  }
  addtobuffer1("\", ");
  if (reportbasic) {
    spindump_event_printer_qlog_print_basicinfo(event,buffer,length);
  }
  addtobuffer1("\n      \"data\": {");
  spindump_event_printer_qlog_print_measurements(event,buffer,length);
  addtobuffer1("}}");
  
  //
  // Done.
  //
  
  *consumed = strlen(buffer);
  spindump_deepdeepdebugf("printed a qlog event, %s", buffer);
  return(strlen(buffer) < length - 1);
}

//
// Print basic address, port etc information about a connection.
//

static void
spindump_event_printer_qlog_print_basicinfo(const struct spindump_event* event,
                                            char* buffer,
                                            size_t length) {
  unsigned int version = spindump_network_version(&event->initiatorAddress);
  addtobuffer2("\n      \"ip_version\": \"ipv%u\", ",version);
  const char* srcaddr = spindump_network_tostringoraddr(&event->initiatorAddress);
  addtobuffer2("\"src_ip\": \"%s\", ",srcaddr);
  const char* dstaddr = spindump_network_tostringoraddr(&event->responderAddress);
  addtobuffer2("\"dst_ip\": \"%s\", ",dstaddr);
  if (spindump_connection_typehasports(event->connectionType)) {
    uint16_t sport = spindump_event_printer_qlog_getsport(event->session);
    uint16_t dport = spindump_event_printer_qlog_getdport(event->session);
    addtobuffer2("\"src_port\": \"%u\", ",sport);
    addtobuffer2("\"dst_port\": \"%u\", ",dport);
  }
  if (event->connectionType == spindump_connection_transport_quic) {
    char scid[2*spindump_connection_quic_cid_maxlen+1];
    char dcid[2*spindump_connection_quic_cid_maxlen+1];
    spindump_event_printer_qlog_getscid(event->session,scid,sizeof(scid));
    spindump_event_printer_qlog_getdcid(event->session,dcid,sizeof(dcid));
    addtobuffer2("\"src_cid\": \"%s\", ",scid);
    addtobuffer2("\"dst_cid\": \"%s\", ",dcid);
  }
}

//
// Get source port from a Spindump session string. Session strings are
// of the form "045e0cc8-04d9d79f (64002:4433)" for QUIC and
// "59223:80" for other protocols. The source and destination ports
// are the two numbers separated by colon, in order.
//

static uint16_t
spindump_event_printer_qlog_getsport(const char* session) {
  const char* para = index(session,'(');
  if (para != 0) {
    session = para + 1;
  }
  if (!isdigit(*session)) return(0);
  return((uint16_t)atoi(session));
}

//
// Get destination port from a Spindump session string. Session
// strings are of the form "045e0cc8-04d9d79f (64002:4433)" for QUIC
// and "59223:80" for other protocols. The source and destination
// ports are the two numbers separated by colon, in order.
//

static uint16_t
spindump_event_printer_qlog_getdport(const char* session) {
  while (*session != ':') {
    if  (*session == 0) return(0);
    session++;
  }
  session++;
  if (!isdigit(*session)) return(0);
  return((uint16_t)atoi(session));
}

//
// Get QUIC source CID from a Spindump session string. Session strings
// are of the form "045e0cc8-04d9d79f (64002:4433)" for QUIC.  The
// source and destination CIDs are the two hex strings separated by a
// dash, in that order.
//

static void
spindump_event_printer_qlog_getscid(const char* session,
                                    char* buffer,
                                    size_t length) {
  memset(buffer,0,length);
  if (index(session,'-') == 0 || index(session,'(') == 0) return;
  while (*session != '-' && length > 0) {
    (*(buffer++)) = *(session++);
  }
}

//
// Get QUIC source CID from a Spindump session string. Session strings
// are of the form "045e0cc8-04d9d79f (64002:4433)" for QUIC.  The
// source and destination CIDs are the two hex strings separated by a
// dash, in that order.
//

static void
spindump_event_printer_qlog_getdcid(const char* session,
                                    char* buffer,
                                    size_t length) {
  memset(buffer,0,length);
  if (index(session,'-') == 0 || index(session,'(') == 0) return;
  while (*session != '-') session++;
  session++;
  while (*session != ' ' && length > 0) {
    (*(buffer++)) = *(session++);
  }
}

//
// Print the measurements part of the Qlog event
//

static void
spindump_event_printer_qlog_print_measurements(const struct spindump_event* event,
                                               char* buffer,
                                               size_t length) {
  addtobuffer2("\"packets1\": %llu",
               event->packetsFromSide1);
  addtobuffer2(", \"packets2\": %llu",
               event->packetsFromSide2);
  addtobuffer2(", \"bytes1\": %llu",
               event->bytesFromSide1);
  addtobuffer2(", \"bytes2\": %llu",
               event->bytesFromSide2);
  if (event->bandwidthFromSide1 > 0 ||
      event->bandwidthFromSide2 > 0) {
    addtobuffer2(", \"bandwidth1\": %llu",
                 event->bandwidthFromSide1);
    addtobuffer2(", \"bandwidth2\": %llu",
                 event->bandwidthFromSide2);
  }
  spindump_event_printer_qlog_print_type_specific_measurements(event,buffer,length);
}

//
// Print measurements that are dependent on the specific event type.
//

static void
spindump_event_printer_qlog_print_type_specific_measurements(const struct spindump_event* event,
                                                             char* buffer,
                                                             size_t length) {
  switch (event->eventType) {
    
  case spindump_event_type_new_connection:
    break;
    
  case spindump_event_type_change_connection:
    break;
    
  case spindump_event_type_connection_delete:
    break;
    
  case spindump_event_type_new_rtt_measurement:
    if (event->u.newRttMeasurement.measurement == spindump_measurement_type_bidirectional) {
      if (event->u.newRttMeasurement.direction == spindump_direction_frominitiator) {
        addtobuffer2(", \"left_rtt\": %lu", event->u.newRttMeasurement.rtt);
        if (event->u.newRttMeasurement.avgRtt > 0) {
          addtobuffer2(", \"avg_left_rtt\": %lu", event->u.newRttMeasurement.avgRtt);
          addtobuffer2(", \"dev_left_rtt\": %lu", event->u.newRttMeasurement.devRtt);
        }
        if (event->u.newRttMeasurement.filtAvgRtt > 0) {
          addtobuffer2(", \"filt_avg_left_rtt\": %lu", event->u.newRttMeasurement.filtAvgRtt);
        }
       if (event->u.newRttMeasurement.minRtt > 0) {
          addtobuffer2(", \"min_left_rtt\": %lu", event->u.newRttMeasurement.minRtt);
       }
      } else {
        addtobuffer2(", \"right_rtt\": %lu", event->u.newRttMeasurement.rtt);
        if (event->u.newRttMeasurement.avgRtt > 0) {
          addtobuffer2(", \"avg_right_rtt\": %lu", event->u.newRttMeasurement.avgRtt);
          addtobuffer2(", \"dev_right_rtt\": %lu", event->u.newRttMeasurement.devRtt);
        }
        if (event->u.newRttMeasurement.filtAvgRtt > 0) {
          addtobuffer2(", \"filt_avg_right_rtt\": %lu", event->u.newRttMeasurement.filtAvgRtt);
        }
       if (event->u.newRttMeasurement.minRtt > 0) {
          addtobuffer2(", \"min_right_rtt\": %lu", event->u.newRttMeasurement.minRtt);
       }

      }
    } else {
      if (event->u.newRttMeasurement.direction == spindump_direction_frominitiator) {
        addtobuffer2(", \"full_rtt_initiator\": %lu", event->u.newRttMeasurement.rtt);
        if (event->u.newRttMeasurement.avgRtt > 0) {
          addtobuffer2(", \"avg_full_rtt_initiator\": %lu", event->u.newRttMeasurement.avgRtt);
          addtobuffer2(", \"dev_full_rtt_initiator\": %lu", event->u.newRttMeasurement.devRtt);
        }
        if (event->u.newRttMeasurement.filtAvgRtt > 0) {
          addtobuffer2(", \"filt_avg_full_rtt_initiator\": %lu", event->u.newRttMeasurement.filtAvgRtt);
        }
       if (event->u.newRttMeasurement.minRtt > 0) {
          addtobuffer2(", \"min_full_rtt_initiator\": %lu", event->u.newRttMeasurement.minRtt);
       }
      } else {
        addtobuffer2(", \"full_rtt_responder\": %lu", event->u.newRttMeasurement.rtt);
        if (event->u.newRttMeasurement.avgRtt > 0) {
          addtobuffer2(", \"avg_full_rtt_responder\": %lu", event->u.newRttMeasurement.avgRtt);
          addtobuffer2(", \"dev_full_rtt_responder\": %lu", event->u.newRttMeasurement.devRtt);
        }
        if (event->u.newRttMeasurement.filtAvgRtt > 0) {
          addtobuffer2(", \"filt_avg_full_rtt_responder\": %lu", event->u.newRttMeasurement.filtAvgRtt);
        }
       if (event->u.newRttMeasurement.minRtt > 0) {
          addtobuffer2(", \"min_full_rtt_responder\": %lu", event->u.newRttMeasurement.minRtt);
       }
      }
    }
    break;
    
  case spindump_event_type_periodic:
    if (event->u.periodic.rttRight != spindump_rtt_infinite) {
      addtobuffer2(", \"right_rtt\": %lu", event->u.periodic.rttRight);
      if (event->u.periodic.avgRttRight > 0) {
        addtobuffer2(", \"avg_right_rtt\": %lu", event->u.periodic.avgRttRight);
        addtobuffer2(", \"dev_right_rtt\": %lu", event->u.periodic.devRttRight);
      }
    }
    break;
    
  case spindump_event_type_spin_flip:
    addtobuffer3(", \"transition\": \"%s\", \"Who\": \"%s\"",
                 event->u.spinFlip.spin0to1 ? "0-1" : "1-0",
                 event->u.spinFlip.direction == spindump_direction_frominitiator ? "initiator" : "responder");
    break;
    
  case spindump_event_type_spin_value:
    addtobuffer3(", \"value\": %u, \"Who\": \"%s\"",
                 event->u.spinValue.value,
                 event->u.spinValue.direction == spindump_direction_frominitiator ? "initiator" : "responder");
    break;
    
  case spindump_event_type_ecn_congestion_event:
    addtobuffer2(", \"who\": \"%s\"",
                 event->u.ecnCongestionEvent.direction == spindump_direction_frominitiator ? "initiator" : "responder");
    addtobuffer2(", \"ecn0\": \"%llu\"", event->u.ecnCongestionEvent.ecn0);
    addtobuffer2(", \"ecn1\": \"%llu\"", event->u.ecnCongestionEvent.ecn1);
    addtobuffer2(", \"ce\": \"%llu\"", event->u.ecnCongestionEvent.ce);
    break;

  case spindump_event_type_rtloss_measurement:
    addtobuffer2(", \"who\": \"%s\"",
                 event->u.ecnCongestionEvent.direction == spindump_direction_frominitiator ? "initiator" : "responder");  
    addtobuffer2(", \"avg_loss\": \"%s\"", event->u.rtlossMeasurement.avgLoss);
    addtobuffer2(", \"tot_loss\": \"%s\"", event->u.rtlossMeasurement.totLoss);
    break;

  case spindump_event_type_qrloss_measurement:
    addtobuffer2(", \"who\": \"%s\"",
                 event->u.ecnCongestionEvent.direction == spindump_direction_frominitiator ? "initiator" : "responder");
    addtobuffer2(", \"avg_loss\": \"%s\"", event->u.qrlossMeasurement.avgLoss);
    addtobuffer2(", \"tot_loss\": \"%s\"", event->u.qrlossMeasurement.totLoss);
    break;

  case spindump_event_type_qlloss_measurement:
    addtobuffer2(", \"Who\": \"%s\"",
                 event->u.ecnCongestionEvent.direction == spindump_direction_frominitiator ? "initiator" : "responder");  
    addtobuffer2(", \"Q_loss\": \"%s\"", event->u.qllossMeasurement.qLoss);
    addtobuffer2(", \"R_loss\": \"%s\"", event->u.qllossMeasurement.lLoss);
    break;
    
  case spindump_event_type_packet:
    addtobuffer2(", \"Dir\": \"%s\"",
                 event->u.packet.direction == spindump_direction_frominitiator ? "initiator" : "responder");
    addtobuffer2(", \"Length\": %lu", event->u.packet.length);
    break;
    
  default:
    spindump_errorf("invalid event type");
  }
}

//
// Determine a unique "group_id" for Qlog, based on the address and
// session information in the event. The group id is used to match
// different fragments of traces for a single connection together.
//

static unsigned long
spindump_event_printer_qlog_generate_groupid(const struct spindump_event* event) {
  unsigned int asize;
  const uint8_t* abytes = spindump_address_getrawbytes(&event->initiatorAddress.address,&asize);
  unsigned long crc = spindump_event_printer_qlog_crc(abytes,asize);
  abytes = spindump_address_getrawbytes(&event->responderAddress.address,&asize);
  crc = spindump_event_printer_qlog_update_crc(crc,abytes,asize);
  crc = spindump_event_printer_qlog_update_crc(crc,(const unsigned char*)&event->session[0],strlen(event->session));
  crc = spindump_event_printer_qlog_update_crc(crc,(const unsigned char*)&event->connectionType,sizeof(event->connectionType));
  return(crc % 1048576);
}

//
// Make the table for a fast CRC. Taken from RFC 1952.
//

static void
spindump_event_printer_qlog_make_crc_table(void) {
  unsigned long c;
  
  int n, k;
  for (n = 0; n < 256; n++) {
    c = (unsigned long) n;
    for (k = 0; k < 8; k++) {
      if (c & 1) {
        c = 0xedb88320L ^ (c >> 1);
      } else {
        c = c >> 1;
      }
    }
    crc_table[n] = c;
  }
  crc_table_computed = 1;
}

//
// Update a running crc with the bytes buf[0..len-1] and return
// the updated crc. The crc should be initialized to zero. Pre- and
// post-conditioning (one's complement) is performed within this
// function so it shouldn't be done by the caller. Usage example:
//
//     unsigned long crc = 0L;
//
//     while (read_buffer(buffer, length) != EOF) {
//       crc = qlog_update_crc(crc, buffer, length);
//     }
//     if (crc != original_crc) error();
//
// Code taken from RFC 1952.
//

static unsigned long
spindump_event_printer_qlog_update_crc(unsigned long crc,
                                       const unsigned char *buf,
                                       size_t len) {
  
  unsigned long c = crc ^ 0xffffffffL;
  
  if (!crc_table_computed) {
    spindump_event_printer_qlog_make_crc_table();
  }
  
  for (unsigned int n = 0; n < len; n++) {
    c = crc_table[(c ^ buf[n]) & 0xff] ^ (c >> 8);
  }
  
  return(c ^ 0xffffffffL);
}

//
// Return the CRC of the bytes buf[0..len-1]. Code taken from RFC 1952.
//

static unsigned long
spindump_event_printer_qlog_crc(const unsigned char *buf,
                                size_t len) {
  return(spindump_event_printer_qlog_update_crc(0L, buf, len));
}
