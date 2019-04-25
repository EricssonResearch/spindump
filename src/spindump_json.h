
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

#ifndef SPINDUMP_JSON_H
#define SPINDUMP_JSON_H

//
// Parameters ---------------------------------------------------------------------------------
//

#define spindump_json_maxfields 20

//
// Data types ---------------------------------------------------------------------------------
//

struct spindump_json_typedef;

typedef void (*spindump_json_callback)(struct spindump_json_typedef* type,
                                       void* data);

enum spindump_json_type {
  spindump_json_type_integer,
  spindump_json_type_string,
  spindump_json_type_record,
  spindump_json_type_array,
  spindump_json_type_any
};

//
// Data structures ----------------------------------------------------------------------------
//

struct spindump_json_fielddef {
  int required;
  const char* name;
  struct spindump_json_typedef* type;
};

struct spindump_json_recorddef {
  unsigned int nFields;
  struct spindump_json_fielddef fields[spindump_json_maxfields];
};

struct spindump_json_arraydef {
  struct spindump_json_typedef* type;
};

struct spindump_json_typedef {
  enum spindump_json_type type;
  spindump_json_callback callback;
  union {
    struct spindump_json_arraydef array;
    struct spindump_json_recorddef record;
  } u;
};

//
// External API interface to this module ------------------------------------------------------
//

int
spindump_json_parse(struct spindump_json_typedef* type,
                    const char* input,
                    void* data);

#endif // SPINDUMP_JSON_H
