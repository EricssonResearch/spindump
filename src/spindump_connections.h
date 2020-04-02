
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
//  SPINDUMP (C) 2018-2020 BY ERICSSON RESEARCH
//  AUTHOR: JARI ARKKO
//
//

#ifndef SPINDUMP_CONNECTIONS_H
#define SPINDUMP_CONNECTIONS_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/in.h>
#include "spindump_util.h"
#include "spindump_rtt.h"
#include "spindump_seq.h"
#include "spindump_stats.h"
#include "spindump_connections_structs.h"
#include "spindump_table_structs.h"
#include "spindump_reversedns.h"
#include "spindump_analyze.h"

//
// Forward declarations of types --------------------------------------------------------------
//

struct spindump_connection_set;

//
// External API interface to this module ------------------------------------------------------
//

void
spindump_connections_markconnectiondeleted(struct spindump_connection* connection);
void
spindump_connections_changeidentifiers(struct spindump_analyze* state,
                                       struct spindump_packet* packet,
                                       const struct timeval* timestamp,
                                       struct spindump_connection* connection);
void
spindump_connections_changestate(struct spindump_analyze* state,
                                 struct spindump_packet* packet,
                                 const struct timeval* timestamp,
                                 struct spindump_connection* connection,
                                 enum spindump_connection_state newState);
void
spindump_connections_delete(struct spindump_connection* connection);
struct spindump_connection*
spindump_connections_newconnection(struct spindump_connectionstable* table,
                                   enum spindump_connection_type type,
                                   const struct timeval* when,
                                   int manuallyCreated);
struct spindump_connection*
spindump_connections_newconnection_icmp(const spindump_address* side1address,
                                        const spindump_address* side2address,
                                        u_int8_t side1peerType,
                                        u_int16_t side1peerId,
                                        const struct timeval* when,
                                        struct spindump_connectionstable* table);
struct spindump_connection*
spindump_connections_newconnection_tcp(const spindump_address* side1address,
                                       const spindump_address* side2address,
                                       spindump_port side1port,
                                       spindump_port side2port,
                                       const struct timeval* when,
                                       struct spindump_connectionstable* table);
struct spindump_connection*
spindump_connections_newconnection_sctp(const spindump_address* side1address,
                                        const spindump_address* side2address,
                                        spindump_port side1port,
                                        spindump_port side2port,
                                        uint32_t side1Vtag,
                                        const struct timeval* when,
                                        struct spindump_connectionstable* table);
struct spindump_connection*
spindump_connections_newconnection_udp(const spindump_address* side1address,
                                       const spindump_address* side2address,
                                       spindump_port side1port,
                                       spindump_port side2port,
                                       const struct timeval* when,
                                       struct spindump_connectionstable* table);
struct spindump_connection*
spindump_connections_newconnection_dns(const spindump_address* side1address,
                                       const spindump_address* side2address,
                                       spindump_port side1port,
                                       spindump_port side2port,
                                       const struct timeval* when,
                                       struct spindump_connectionstable* table);
struct spindump_connection*
spindump_connections_newconnection_coap(const spindump_address* side1address,
                                        const spindump_address* side2address,
                                        spindump_port side1port,
                                        spindump_port side2port,
                                        const struct timeval* when,
                                        struct spindump_connectionstable* table);
struct spindump_connection*
spindump_connections_newconnection_quic_5tuple(const spindump_address* side1address,
                                               const spindump_address* side2address,
                                               spindump_port side1port,
                                               spindump_port side2port,
                                               const struct timeval* when,
                                               struct spindump_connectionstable* table);
struct spindump_connection*
spindump_connections_newconnection_quic_5tupleandcids(const spindump_address* side1address,
                                                      const spindump_address* side2address,
                                                      spindump_port side1port,
                                                      spindump_port side2port,
                                                      struct spindump_quic_connectionid* destinationCid,
                                                      struct spindump_quic_connectionid* sourceCid,
                                                      const struct timeval* when,
                                                      struct spindump_connectionstable* table);
struct spindump_connection*
spindump_connections_newconnection_aggregate_hostpair(const spindump_address* side1address,
                                                      const spindump_address* side2address,
                                                      const struct timeval* when,
                                                      int manuallyCreated,
                                                      struct spindump_connectionstable* table);
struct spindump_connection*
spindump_connections_newconnection_aggregate_hostnetwork(const spindump_address* side1address,
                                                         const spindump_network* side2network,
                                                         const struct timeval* when,
                                                         int manuallyCreated,
                                                         struct spindump_connectionstable* table);
struct spindump_connection*
spindump_connections_newconnection_aggregate_networknetwork(int defaultMatch,
                                                            const spindump_network* side1network,
                                                            const spindump_network* side2network,
                                                            const struct timeval* when,
                                                            int manuallyCreated,
                                                            struct spindump_connectionstable* table);
struct spindump_connection*
spindump_connections_newconnection_aggregate_multicastgroup(const spindump_address* group,
                                                            const struct timeval* when,
                                                            int manuallyCreated,
                                                            struct spindump_connectionstable* table);
struct spindump_connection*
spindump_connections_search(struct spindump_connection_searchcriteria* criteria,
                            struct spindump_connectionstable* table,
                            int* fromResponder);
struct spindump_connection*
spindump_connections_searchconnection_icmp(const spindump_address* side1address,
                                           const spindump_address* side2address,
                                           u_int8_t side1peerType,
                                           u_int16_t side1peerId,
                                           struct spindump_connectionstable* table);
struct spindump_connection*
spindump_connections_searchconnection_tcp(const spindump_address* side1address,
                                          const spindump_address* side2address,
                                          spindump_port side1port,
                                          spindump_port side2port,
                                          struct spindump_connectionstable* table);
struct spindump_connection*
spindump_connections_searchconnection_tcp_either(const spindump_address* side1address,
                                                 const spindump_address* side2address,
                                                 spindump_port side1port,
                                                 spindump_port side2port,
                                                 struct spindump_connectionstable* table,
                                                 int* fromResponder);
struct spindump_connection*
spindump_connections_searchconnection_sctp(const spindump_address* side1address,
                                          const spindump_address* side2address,
                                          spindump_port side1port,
                                          spindump_port side2port,
                                          struct spindump_connectionstable* table);
struct spindump_connection*
spindump_connections_searchconnection_sctp_either(const spindump_address* side1address,
                                                 const spindump_address* side2address,
                                                 spindump_port side1port,
                                                 spindump_port side2port,
                                                 struct spindump_connectionstable* table,
                                                 int* fromResponder);
struct spindump_connection*
spindump_connections_searchconnection_quic_5tuple(const spindump_address* side1address,
                                                  const spindump_address* side2address,
                                                  spindump_port side1port,
                                                  spindump_port side2port,
                                                  struct spindump_connectionstable* table);
struct spindump_connection*
spindump_connections_searchconnection_quic_cids(struct spindump_quic_connectionid* destinationCid,
                                                struct spindump_quic_connectionid* sourceCid,
                                                struct spindump_connectionstable* table);
struct spindump_connection*
spindump_connections_searchconnection_quic_destcid(struct spindump_quic_connectionid* destinationCid,
                                                   struct spindump_connectionstable* table);
struct spindump_connection*
spindump_connections_searchconnection_quic_partialcid(const unsigned char* destinationCid,
                                                      struct spindump_connectionstable* table);
struct spindump_connection*
spindump_connections_searchconnection_quic_partialcid_source(const unsigned char* destinationCid,
                                                             struct spindump_connectionstable* table);
struct spindump_connection*
spindump_connections_searchconnection_quic_5tuple_either(const spindump_address* side1address,
                                                         const spindump_address* side2address,
                                                         spindump_port side1port,
                                                         spindump_port side2port,
                                                         struct spindump_connectionstable* table,
                                                         int* fromResponder);
struct spindump_connection*
spindump_connections_searchconnection_quic_cids_either(struct spindump_quic_connectionid* destinationCid,
                                                       struct spindump_quic_connectionid* sourceCid,
                                                       struct spindump_connectionstable* table,
                                                       int* fromResponder);
struct spindump_connection*
spindump_connections_searchconnection_quic_partialcid_either(const unsigned char* destinationCid,
                                                             struct spindump_connectionstable* table,
                                                             int* fromResponder);
struct spindump_connection*
spindump_connections_searchconnection_udp(const spindump_address* side1address,
                                          const spindump_address* side2address,
                                          spindump_port side1port,
                                          spindump_port side2port,
                                          struct spindump_connectionstable* table);
struct spindump_connection*
spindump_connections_searchconnection_udp_either(const spindump_address* side1address,
                                                 const spindump_address* side2address,
                                                 spindump_port side1port,
                                                 spindump_port side2port,
                                                 struct spindump_connectionstable* table,
                                                 int* fromResponder);
struct spindump_connection*
spindump_connections_searchconnection_dns(const spindump_address* side1address,
                                          const spindump_address* side2address,
                                          spindump_port side1port,
                                          spindump_port side2port,
                                          struct spindump_connectionstable* table);
struct spindump_connection*
spindump_connections_searchconnection_dns_either(const spindump_address* side1address,
                                                 const spindump_address* side2address,
                                                 spindump_port side1port,
                                                 spindump_port side2port,
                                                 struct spindump_connectionstable* table,
                                                 int* fromResponder);
struct spindump_connection*
spindump_connections_searchconnection_coap(const spindump_address* side1address,
                                           const spindump_address* side2address,
                                           spindump_port side1port,
                                           spindump_port side2port,
                                           struct spindump_connectionstable* table);
struct spindump_connection*
spindump_connections_searchconnection_coap_either(const spindump_address* side1address,
                                                  const spindump_address* side2address,
                                                  spindump_port side1port,
                                                  spindump_port side2port,
                                                  struct spindump_connectionstable* table,
                                                  int* fromResponder);
struct spindump_connection*
spindump_connections_searchconnection_aggregate_hostpair(const spindump_address* side1address,
                                                         const spindump_address* side2address,
                                                         struct spindump_connectionstable* table);
struct spindump_connection*
spindump_connections_searchconnection_aggregate_hostnetwork(const spindump_address* side1address,
                                                            const spindump_network* side2network,
                                                            struct spindump_connectionstable* table);
struct spindump_connection*
spindump_connections_searchconnection_aggregate_networknetwork(const spindump_network* side1network,
                                                               const spindump_network* side2network,
                                                               struct spindump_connectionstable* table);
struct spindump_connection*
spindump_connections_searchconnection_aggregate_multicastgroup(const spindump_address* address,
                                                               struct spindump_connectionstable* table);
unsigned long
spindump_connections_newrttmeasurement(struct spindump_analyze* state,
                                       struct spindump_packet* packet,
                                       struct spindump_connection* connection,
                                       unsigned int ipPacketLength,
                                       const int right,
                                       const int unidirectional,
                                       const struct timeval* sent,
                                       const struct timeval* rcvd,
                                       const char* why);
void
spindump_connections_getaddresses(struct spindump_connection* connection,
                                  spindump_address** p_side1address,
                                  spindump_address** p_side2address);
void
spindump_connections_getnetworks(struct spindump_connection* connection,
                                 spindump_network* p_side1network,
                                 spindump_network* p_side2network);
void
spindump_connections_getports(struct spindump_connection* connection,
                              spindump_port* p_side1port,
                              spindump_port* p_side2port);
const char*
spindump_connection_type_to_string(enum spindump_connection_type type);
int
spindump_connection_string_to_connectiontype(const char* string,
                                             enum spindump_connection_type* type);
int
spindump_connection_statestring_to_state(const char* string,
                                         enum spindump_connection_state* state);
int
spindump_connections_isaggregate(const struct spindump_connection* connection);
const struct spindump_connection_set*
spindump_connections_aggregateset(const struct spindump_connection* connection);
int
spindump_connections_isclosed(const struct spindump_connection* connection);
int
spindump_connections_isestablishing(const struct spindump_connection* connection);
int
spindump_connections_matches_aggregate_connection(int seenMatch,
                                                  struct spindump_connection* connection,
                                                  struct spindump_connection* aggregate);
int
spindump_connections_matches_aggregate_srcdst(const spindump_address* source,
                                              const spindump_address* destination,
                                              struct spindump_connection* aggregate);
void
spindump_connection_report(struct spindump_connection* connection,
                           FILE* file,
                           int anonymize,
                           struct spindump_reverse_dns* querier);
void
spindump_connection_report_brief(struct spindump_connection* connection,
                                 char* buf,
                                 unsigned int bufsiz,
                                 int avg,
                                 unsigned int linelen,
                                 int anonymizeLeft,
                                 int anonymizeRight,
                                 struct spindump_reverse_dns* querier);
void
spindump_connection_sessionstring(struct spindump_connection* connection,
                                  char* buffer,
                                  size_t maxlen);
const char*
spindump_connection_quicconnectionid_tostring(struct spindump_quic_connectionid* id,
                                              char* output,
                                              size_t outputLength);
const char*
spindump_connection_statestring(struct spindump_connection* connection);
const char*
spindump_connection_statestring_plain(enum spindump_connection_state state);
const char*
spindump_connection_addresses(struct spindump_connection* connection,
                              unsigned int maxlen,
                              int anonymizeLeft,
                              int anonymizeRight,
                              int json,
                              struct spindump_reverse_dns* querier);
unsigned int
spindump_connection_report_brief_fixedsize(unsigned int linelen);
int
spindump_connection_report_brief_isnotefield(unsigned int linelen);
unsigned int
spindump_connection_report_brief_notefieldval_length(void);
unsigned int
spindump_connection_report_brief_sessionsize(unsigned int linelen);
unsigned int
spindump_connection_report_brief_variablesize(unsigned int linelen);
void
spindump_connection_report_brief_notefieldval(struct spindump_connection* connection,
                                              unsigned bufsiz,
                                              char* buf);
void
spindump_connection_periodicreport(struct spindump_connection* connection,
                                   struct spindump_connectionstable* table,
                                   const struct timeval* now,
                                   struct spindump_analyze* analyzer);
unsigned long long
spindump_connections_lastaction(struct spindump_connection* connection,
                                const struct timeval* now);

#endif // SPINDUMP_CONNECTIONS_H
