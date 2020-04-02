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
//  SPINDUMP (C) 2019-2020 BY ERICSSON RESEARCH
//  AUTHOR: ALEXANDRE FERRIEUX AND MARCUS IHLAR
//
//

#ifndef SPINDUMP_ORANGE_QLLOSS_H
#define SPINDUMP_ORANGE_QLLOSS_H

//
// Includes -----------------------------------------------------------------------------------
//

#include "spindump_orange_qlloss_structs.h"
#include "spindump_connections_structs.h"

struct spindump_analyze;
struct spindump_packet;

//
// External API interface to this module ------------------------------------------------------
//

void
spindump_qllosstracker_observeandcalculateloss(struct spindump_analyze* state,
                                               struct spindump_packet* packet,
                                               struct spindump_connection* connection,
                                               struct timeval* ts,
                                               int fromResponder,
                                               unsigned int ipPacketLength,
                                               int ql);
void
spindump_qllosstracker_initialize(struct spindump_qllosstracker* tracker);
void
spindump_qllosstracker_uninitialize(struct spindump_qllosstracker* tracker);

#endif
