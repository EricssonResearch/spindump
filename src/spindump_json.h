
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

#ifndef SPINDUMP_JSON_H
#define SPINDUMP_JSON_H

//
// Includes -----------------------------------------------------------------------------------
//

#include "spindump_util.h"
#include "spindump_json_value.h"

//
// Parameters ---------------------------------------------------------------------------------
//

#define spindump_json_maxfields 42

//
// Data types ---------------------------------------------------------------------------------
//

struct spindump_json_schema;
struct spindump_json_value;

typedef void (*spindump_json_callback)(const struct spindump_json_value* value,
                                       const struct spindump_json_schema* type,
                                       void* data);

enum spindump_json_schema_type {
  spindump_json_schema_type_integer = 0,
  spindump_json_schema_type_string = 1,
  spindump_json_schema_type_literal = 2,
  spindump_json_schema_type_record = 3,
  spindump_json_schema_type_array = 4,
  spindump_json_schema_type_recordorarray = 5,
  spindump_json_schema_type_any = 6
};

//
// Data structures ----------------------------------------------------------------------------
//

struct spindump_json_schema_field {
  int required;
  const char* name;
  struct spindump_json_schema* schema;
};

struct spindump_json_schema_record {
  unsigned int nFields;
  struct spindump_json_schema_field fields[spindump_json_maxfields];
};

struct spindump_json_schema_array {
  struct spindump_json_schema* schema;
};

struct spindump_json_schema_arrayorrecord {
  struct spindump_json_schema* array;
  struct spindump_json_schema* record;
};

struct spindump_json_schema {
  enum spindump_json_schema_type type;
  spindump_json_callback callback;
  union {
    struct spindump_json_schema_array array;
    struct spindump_json_schema_record record;
    struct spindump_json_schema_arrayorrecord arrayorrecord;
  } u;
};

//
// External API interface to this module ------------------------------------------------------
//

int
spindump_json_parse(const struct spindump_json_schema* schema,
                    void* data,
                    const char** input);

#endif // SPINDUMP_JSON_H
