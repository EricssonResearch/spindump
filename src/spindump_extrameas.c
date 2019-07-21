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
//  AUTHOR: SZILVESZTER NADAS
//
//

#include <stdlib.h>
#include "spindump_extrameas.h"



int
spindump_analyze_quic_parser_reserved1(uint32_t version,
                                       uint8_t headerByte,
                                       int* p_reserved1){
  *p_reserved1 = ((headerByte & spindump_quic_byte_reserved1) != 0);
  return(1);
}

int
spindump_analyze_quic_parser_reserved2(uint32_t version,
                                       uint8_t headerByte,
                                       int* p_reserved2){
  *p_reserved2 = ((headerByte & spindump_quic_byte_reserved2) != 0);
  return(1);
}

void
spindump_extrameas_init(struct spindump_extrameas* p_extrameas){
  p_extrameas->extrameasbits =0;
  p_extrameas->isvalid=0;
}

