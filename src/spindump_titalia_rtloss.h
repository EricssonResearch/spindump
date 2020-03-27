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
//  SPINDUMP (C) 2019 BY ERICSSON RESEARCH
//  AUTHOR: MARCUS IHLAR AND FABIO BULGARELLA
//
//

#ifndef SPINDUMP_RTLOSS_H
#define SPINDUMP_RTLOSS_H

//
// Includes -----------------------------------------------------------------------------------
//

#include "spindump_titalia_rtloss_structs.h"
#include "spindump_connections_structs.h"

struct spindump_analyze;
struct spindump_packet;

//
// External API interface to this module ------------------------------------------------------
//

void
spindump_rtloss1tracker_observeandcalculateloss(struct spindump_analyze* state,
                                                struct spindump_packet* packet,
                                                struct spindump_connection* connection,
                                                struct timeval* ts,
                                                int fromResponder,
                                                unsigned int ipPacketLength,
                                                int lossbit,
                                                int isFlip);
void
spindump_rtloss2tracker_observeandcalculateloss(struct spindump_analyze* state,
                                                struct spindump_packet* packet,
                                                struct spindump_connection* connection,
                                                struct timeval* ts,
                                                int fromResponder,
                                                unsigned int ipPacketLength,
                                                int lossbits);
void
spindump_rtloss1tracker_initialize(struct spindump_rtloss1tracker* tracker);
void
spindump_rtloss2tracker_initialize(struct spindump_rtloss2tracker* tracker);
void
spindump_rtloss1tracker_uninitialize(struct spindump_rtloss1tracker* tracker);
void
spindump_rtloss2tracker_uninitialize(struct spindump_rtloss2tracker* tracker);

#endif
