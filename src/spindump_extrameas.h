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
//  AUTHOR: SZILVESZTER NADAS
//
//

#ifndef SPINDUMP_EXTRAMEAS_H_
#define SPINDUMP_EXTRAMEAS_H_

#include <stdint.h>

#define spindump_extrameas_rtloss1      0x01 // Telecom Italia rt loss measurement single bit version
#define spindump_extrameas_rtloss2_bit1 0x10 // Telecom Italia rt loss measurement two bits version (bit1)
#define spindump_extrameas_rtloss2_bit2 0x08 // Telecom Italia rt loss measurement two bits version (bit2)
#define spindump_extrameas_qrloss_qbit  0x40 // Telecom Italia qr loss measurement bit1
#define spindump_extrameas_qrloss_rbit  0x20 // Telecom Italia qr loss measurement bit2

#define spindump_extrameas_qlloss_bit1 0x02 // Orange loss measurement bit1
#define spindump_extrameas_qlloss_bit2 0x04 // Orange loss measurement bit2

#define spindump_quic_byte_reserved1    0x10
#define spindump_quic_byte_reserved2    0x08


typedef uint8_t spindump_extrameas_int;

struct spindump_extrameas {
  spindump_extrameas_int extrameasbits;  //extra measurement bits, e.g. different loss bits
  spindump_extrameas_int isvalid;        //telling whether a given extra bit is present
};

void
spindump_extrameas_init(struct spindump_extrameas* p_extrameas);

int
spindump_analyze_quic_parser_reserved1(uint32_t version,
                                       uint8_t headerByte,
                                       int* p_reserved1);

int
spindump_analyze_quic_parser_reserved2(uint32_t version,
                                       uint8_t headerByte,
                                       int* p_reserved2);



#endif /* SPINDUMP_EXTRAMEAS_H_ */
