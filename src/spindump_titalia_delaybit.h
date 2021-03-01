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
//  SPINDUMP (C) 2021 BY ERICSSON RESEARCH
//  AUTHOR: FABIO BULGARELLA
//
//

#ifndef SPINDUMP_TITALIA_DELAYBIT_H
#define SPINDUMP_TITALIA_DELAYBIT_H

//
// Includes -----------------------------------------------------------------------------------
//

#include "spindump_titalia_delaybit_structs.h"
#include "spindump_connections_structs.h"
#include "spindump_extrameas.h"

struct spindump_analyze;
struct spindump_packet;

//
// External API interface to this module ------------------------------------------------------
//

void
spindump_delaybittracker_observeandcalculatertt(struct spindump_analyze* state,
                                                struct spindump_packet* packet,
                                                struct spindump_connection* connection,
                                                struct timeval* ts,
                                                int fromResponder,
                                                unsigned int ipPacketLength,
                                                spindump_extrameas_int extrameasbits);
void
spindump_delaybittracker_initialize(struct spindump_delaybittracker* tracker);
void
spindump_delaybittracker_uninitialize(struct spindump_delaybittracker* tracker);

#endif //SPINDUMP_SPINDUMP_DELAYBIT_H
