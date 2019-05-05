
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

#ifndef SPINDUMP_JSON_VALUE_H
#define SPINDUMP_JSON_VALUE_H

//
// Includes -----------------------------------------------------------------------------------
//

#include "spindump_util.h"

//
// Data types ---------------------------------------------------------------------------------
//

enum spindump_json_value_type {
  spindump_json_value_type_integer = 0,
  spindump_json_value_type_string = 1,
  spindump_json_value_type_record = 2,
  spindump_json_value_type_array = 3
};

//
// Data structures ----------------------------------------------------------------------------
//

struct spindump_json_value_array {
  unsigned int n;
  struct spindump_json_value** elements;
};

struct spindump_json_value_field {
  char* name;
  struct spindump_json_value* value;
};

struct spindump_json_value_record {
  unsigned int nSchemaFields;
  struct spindump_json_value_field* schemaFields;
  unsigned int nOtherFields;
  struct spindump_json_value_field* otherFields;
};

struct spindump_json_value_integer {
  unsigned long long value;
};

struct spindump_json_value_string {
  char* value;
};

struct spindump_json_value {
  enum spindump_json_value_type type;
  union {
    struct spindump_json_value_array array;
    struct spindump_json_value_record record;
    struct spindump_json_value_integer integer;
    struct spindump_json_value_string string;
  } u;
};

//
// External API interface to this module ------------------------------------------------------
//

struct spindump_json_value*
spindump_json_value_new_integer(unsigned long long value);
struct spindump_json_value*
spindump_json_value_new_string(const char* bytes,
                               size_t n);
struct spindump_json_value*
spindump_json_value_new_record(unsigned int nSchemaFields,
                               struct spindump_json_value_field* schemaFields,
                               unsigned int nOtherFields,
                               struct spindump_json_value_field* otherFields);
struct spindump_json_value*
spindump_json_value_new_array(void);
int
spindump_json_value_new_array_element(struct spindump_json_value* array,
                                      struct spindump_json_value* newElement);
struct spindump_json_value*
spindump_json_value_copy(const struct spindump_json_value* value);
void
spindump_json_value_free(struct spindump_json_value* value);
const struct spindump_json_value*
spindump_json_value_getfield(const char* field,
                             const struct spindump_json_value* value);
const struct spindump_json_value*
spindump_json_value_getrequiredfield(const char* field,
                                     const struct spindump_json_value* value);
const struct spindump_json_value*
spindump_json_value_getarrayelem(unsigned int index,
                                 const struct spindump_json_value* value);
unsigned long long
spindump_json_value_getinteger(const struct spindump_json_value* value);
const char*
spindump_json_value_getstring(const struct spindump_json_value* value);
char*
spindump_json_value_tostring(const struct spindump_json_value* value);

#endif // SPINDUMP_JSON_VALUE_H
