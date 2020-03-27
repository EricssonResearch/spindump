
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
//  AUTHOR: JARI ARKKO AND MARCUS IHLAR
//
// 

#ifndef SPINDUMP_SPIN_H
#define SPINDUMP_SPIN_H

//
// Includes -----------------------------------------------------------------------------------
//

#include "spindump_spin_structs.h"
#include "spindump_connections_structs.h"

struct spindump_analyze;
struct spindump_packet;

//
// External API interface to this module ------------------------------------------------------
//

void
spindump_spintracker_initialize(struct spindump_spintracker* tracker);
void
spindump_spintracker_add(struct spindump_spintracker* tracker,
                         struct timeval* ts,
                         int spin0to1);
void
spindump_spintracker_observespinandcalculatertt(struct spindump_analyze* state,
                                                struct spindump_packet* packet,
                                                struct spindump_connection* connection,
                                                struct spindump_spintracker* tracker,
                                                struct spindump_spintracker* otherDirectionTracker,
                                                struct timeval* ts,
                                                int spin,
                                                int fromResponder,
                                                unsigned int ipPacketLength,
                                                int *isFlip);
void
spindump_spintracker_uninitialize(struct spindump_spintracker* tracker);

#endif // SPINDUMP_SPIN_H
