
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

//
// Includes -----------------------------------------------------------------------------------
//

#include <string.h>
#include <ctype.h>
#include "spindump_util.h"
#include "spindump_json.h"
#include "spindump_json_value.h"

//
// Parameters ---------------------------------------------------------------------------------
//

#define maxSchemaFields 20
#define maxOtherFields 20

//
// Function prototypes ------------------------------------------------------------------------
//

static void
spindump_json_parse_seekcurrentchar(const char** input);
static struct spindump_json_value*
spindump_json_parse_integer(const char** input);
static struct spindump_json_value*
spindump_json_parse_string(const char** input);
static struct spindump_json_value*
spindump_json_parse_array(const struct spindump_json_schema* schema,
                           void* data,
                           const char** input);
static struct spindump_json_value*
spindump_json_parse_record(const struct spindump_json_schema* schema,
                           void* data,
                           const char** input);
static char*
spindump_json_parse_record_aux_field_name(const char** input);
static const struct spindump_json_schema_field*
spindump_json_parse_record_aux_findfield(const struct spindump_json_schema* schema,
                                         const char* fieldName);
struct spindump_json_value_field*
spindump_json_parse_lookforfield(const char* name,
                                 unsigned int nFields,
                                 struct spindump_json_value_field* fields);
static int
spindump_json_parse_record_aux_field(const struct spindump_json_schema* schema,
                                     void* data,
                                     const char** input,
                                     unsigned int* nSchemaFields,
                                     struct spindump_json_value_field* schemaFields,
                                     unsigned int* nOtherFields,
                                     struct spindump_json_value_field* otherFields);
static void
spindump_json_parse_record_aux_free(unsigned int nSchemaFields,
                                    struct spindump_json_value_field* schemaFields,
                                    unsigned int nOtherFields,
                                    struct spindump_json_value_field* otherFields);
static struct spindump_json_value*
spindump_json_parse_aux(const struct spindump_json_schema* schema,
                        void* data,
                        const char** input);
static struct spindump_json_value*
spindump_json_parse_literal(const char** input);
static struct spindump_json_value*
spindump_json_parse_recordorarray(const struct spindump_json_schema* schema,
                                  void* data,
                                  const char** input);
static struct spindump_json_value*
spindump_json_parse_any(const struct spindump_json_schema* schema,
                        void* data,
                        const char** input);
static int
spindump_json_parse_record_aux_addtofields(char* fieldName,
                                           struct spindump_json_value* value,
                                           unsigned int* nFields,
                                           unsigned int maxNFields,
                                           struct spindump_json_value_field* fields);

//
// Macros -------------------------------------------------------------------------------------
//

#define spindump_json_parse_movetonextchar(x) \
   (*(x))++;

//
// Actual code --------------------------------------------------------------------------------
//

//
// Parse a given input as JSON of a given type. Callbacks in the type
// definition will be called when the input is read correctly, and the
// "data" parqmeter is one of the parameters passed to the callbacks.
//
// This function returns 1 upon successful parsing, and 0 upon
// failure.
//

int
spindump_json_parse(const struct spindump_json_schema* schema,
                    void* data,
                    const char** input) {

  //
  // Sanity checks
  //

  spindump_assert(schema != 0);
  spindump_assert(input != 0);
  spindump_assert(*input != 0);

  //
  // Call the auxiliary function that does the actual work
  //

  struct spindump_json_value* value = spindump_json_parse_aux(schema,data,input);
  if (value == 0) {
    spindump_deepdeepdebugf("spindump_json_parse: failed");
    return(0);
  } else {
    spindump_deepdeepdebugf("spindump_json_parse: succeeded");
    spindump_json_value_free(value);
    spindump_deepdeepdebugf("spindump_json_parse: returning");
    return(1);
  }
}

//
// The internal parsing function, parsing a JSON value per given
// schema, from input given as a string in *input. This function
// advances the input pointer as it consumes the input. The "data"
// parameter is whatever the caller of the spindump_json_parse
// function decided to provide.
//
// Return the JSON value object. The caller is responsible for freeing
// the value object once it is done using it; the object and
// everything it refers to will be freshly allocated by this
// function. And upon an error, this function returns 0 and has
// cancelled all of its own allocations, if any.
//

struct spindump_json_value*
spindump_json_parse_aux(const struct spindump_json_schema* schema,
                        void* data,
                        const char** input) {
  
  //
  // Sanity checks
  //
  
  spindump_assert(schema != 0);
  spindump_assert(input != 0);
  spindump_assert(*input != 0);
  
  //
  // Branch based on what schema expects
  //

  spindump_deepdeepdebugf("JSON parse aux schema type %u, input = %s...",
                          schema->type, *input);
  
  struct spindump_json_value* value;
  switch (schema->type) {
    
  case spindump_json_schema_type_integer:
    value = spindump_json_parse_integer(input);
    break;
    
  case spindump_json_schema_type_string:
    value = spindump_json_parse_string(input);
    break;
    
  case spindump_json_schema_type_literal:
    value = spindump_json_parse_literal(input);
    break;
    
  case spindump_json_schema_type_record:
    value = spindump_json_parse_record(schema,data,input);
    break;
    
  case spindump_json_schema_type_array:
    value = spindump_json_parse_array(schema,data,input);
    break;
    
  case spindump_json_schema_type_recordorarray:
    value = spindump_json_parse_recordorarray(schema,data,input);
    break;
    
  case spindump_json_schema_type_any:
    value = spindump_json_parse_any(schema,data,input);
    break;
    
  default:
    spindump_errorf("invalid JSON schema type %u", schema->type);
    return(0);
  }

  //
  // Bail out if an error
  //

  if (value == 0) {
    return(0);
  }
  
  //
  // Call the callback, if any
  //
  
  if (schema->callback != 0) {
    spindump_deepdeepdebugf("calling callback");
    (*(schema->callback))(value,schema,data);
    spindump_deepdeepdebugf("returned from callback");
  }
  
  //
  // Done
  //
  
  return(value);
}

//
// The internal parsing function, parsing a JSON integer value, from
// input given as a string in *input. This function advances the input
// pointer as it consumes the input. The "data" parameter is whatever
// the caller of the spindump_json_parse function decided to provide.
//
// Return the JSON value object. The caller is responsible for freeing
// the value object once it is done using it; the object and
// everything it refers to will be freshly allocated by this
// function. And upon an error, this function returns 0 and has
// cancelled all of its own allocations, if any.
//

static struct spindump_json_value*
spindump_json_parse_integer(const char** input) {
  spindump_json_parse_seekcurrentchar(input);
  spindump_deepdeepdebugf("spindump_json_parse_integer parsing %s...", *input);
# define maxdigits 40
  char buf[maxdigits+1];
  unsigned int bufChars = 0;
  memset(buf,0,sizeof(buf));
  if (!isdigit(**input)) {
      spindump_errorf("expected a JSON integer");
      return(0);
  }
  while (**input != 0 && isdigit(**input)) {
    if (bufChars >= maxdigits) {
      spindump_errorf("JSON integer number is too long");
      return(0);
    }
    buf[bufChars++] = **input;
    spindump_json_parse_movetonextchar(input);
  }
  unsigned long long value;
  int x = sscanf(buf,"%llu",&value);
  if (x < 1) {
      spindump_errorf("JSON integer number cannot be parsed");
    return(0);
  }
  return(spindump_json_value_new_integer(value));
}

//
// The internal parsing function, parsing a JSON string value, from
// input given as a string in *input. This function advances the input
// pointer as it consumes the input. The "data" parameter is whatever
// the caller of the spindump_json_parse function decided to provide.
//
// Return the JSON value object. The caller is responsible for freeing
// the value object once it is done using it; the object and
// everything it refers to will be freshly allocated by this
// function. And upon an error, this function returns 0 and has
// cancelled all of its own allocations, if any.
//

static struct spindump_json_value*
spindump_json_parse_string(const char** input) {
  spindump_json_parse_seekcurrentchar(input);
  spindump_deepdeepdebugf("spindump_json_parse_string parsing %s...", *input);
  if (**input != '\"') {
    spindump_errorf("cannot parse JSON string: missing opening quote");
    return(0);
  }
  spindump_json_parse_movetonextchar(input);
  char* closing = index(*input,'\"');
  if (closing == 0) {
    spindump_errorf("cannot parse JSON string: missing closing quote");
    return(0);
  }
  long len = closing - (*input);
  struct spindump_json_value* value = spindump_json_value_new_string(*input,(size_t)len);
  *input = closing+1;
  return(value);
}

//
// The internal parsing function, parsing a JSON literal value (a
// number or string), from input given as a string in *input. This
// function advances the input pointer as it consumes the input. The
// "data" parameter is whatever the caller of the spindump_json_parse
// function decided to provide.
//
// Return the JSON value object. The caller is responsible for freeing
// the value object once it is done using it; the object and
// everything it refers to will be freshly allocated by this
// function. And upon an error, this function returns 0 and has
// cancelled all of its own allocations, if any.
//

static struct spindump_json_value*
spindump_json_parse_literal(const char** input) {
  spindump_json_parse_seekcurrentchar(input);
  spindump_deepdeepdebugf("spindump_json_parse_literal parsing %s...", *input);
  if (isdigit(**input)) {
    return(spindump_json_parse_integer(input));
  } else {
    return(spindump_json_parse_string(input));
  }
}

//
// The internal parsing function, parsing a JSON array value per given
// schema, from input given as a string in *input. This function
// advances the input pointer as it consumes the input. The "data"
// parameter is whatever the caller of the spindump_json_parse
// function decided to provide.
//
// Return the JSON value object. The caller is responsible for freeing
// the value object once it is done using it; the object and
// everything it refers to will be freshly allocated by this
// function. And upon an error, this function returns 0 and has
// cancelled all of its own allocations, if any.
//

static struct spindump_json_value*
spindump_json_parse_array(const struct spindump_json_schema* schema,
                          void* data,
                          const char** input) {
  spindump_assert(schema != 0);
  spindump_assert(schema->type == spindump_json_schema_type_array);
  spindump_json_parse_seekcurrentchar(input);
  spindump_deepdeepdebugf("spindump_json_parse_array parsing %s...", *input);
  if (**input != '[') {
    spindump_errorf("cannot parse JSON array: missing opening bracket");
    return(0);
  }
  spindump_json_parse_movetonextchar(input);
  spindump_json_parse_seekcurrentchar(input);
  struct spindump_json_value* value = spindump_json_value_new_array();
  if (value == 0) {
    return(0);
  }
  while (**input != ']') {
    if (**input == 0) {
      spindump_errorf("cannot parse JSON array: missing closing bracket");
      spindump_json_value_free(value);
      return(0);
    }
    struct spindump_json_value* element = spindump_json_parse_aux(schema->u.array.schema,data,input);
    if (element == 0) {
      spindump_json_value_free(value);
      return(0);
    }
    if (!spindump_json_value_new_array_element(value,element)) {
      spindump_json_value_free(value);
      return(0);
    }
    spindump_json_parse_seekcurrentchar(input);
    if (**input == ',') {
      spindump_json_parse_movetonextchar(input);
      spindump_json_parse_seekcurrentchar(input);
      if (**input == ']') {
        spindump_errorf("cannot parse JSON array: closing bracket after comma");
        spindump_json_value_free(value);
        return(0);
      } else {
        continue;
      }
    } else if (**input == ']') {
      break;
    } else {
      spindump_errorf("cannot parse JSON array: syntax error after element");
      spindump_json_value_free(value);
      return(0);
    }
  }
  spindump_assert(**input == ']');
  spindump_json_parse_movetonextchar(input);
  return(value);
}

//
// The function spindump_json_parse_record_aux_free is called upon
// error situations during the parsing of a JSON record value. It will
// go through the tables of fields that were already parsed, and free
// memory associated with them.
//

static void
spindump_json_parse_record_aux_free(unsigned int nSchemaFields,
                                    struct spindump_json_value_field* schemaFields,
                                    unsigned int nOtherFields,
                                    struct spindump_json_value_field* otherFields) {
  for (unsigned int i = 0; i < nSchemaFields; i++) {
    spindump_free(schemaFields[i].name);
    spindump_json_value_free(schemaFields[i].value);
  }
  for (unsigned int j = 0; j < nOtherFields; j++) {
    spindump_free(otherFields[j].name);
    spindump_json_value_free(otherFields[j].value);
  }
}

//
// Parse a record field name "name" in a record "name": value.
//
// Returns the name, allocated as a new string, or 0 upon failure.
//

static char*
spindump_json_parse_record_aux_field_name(const char** input) {
  spindump_json_parse_seekcurrentchar(input);
  spindump_deepdeepdebugf("spindump_json_parse_record_aux_field_name parsing %s...", *input);
  if (**input != '\"') {
    spindump_errorf("cannot parse JSON record field name: missing opening quote");
    return(0);
  }
  spindump_json_parse_movetonextchar(input);
  char* closing = index(*input,'\"');
  if (closing == 0) {
    spindump_errorf("cannot parse JSON record field name: missing closing quote");
    return(0);
  }
  long lenLong = closing - (*input);
  size_t len = (size_t)lenLong;
  char* string = (char*)spindump_malloc(len + 1);
  if (string == 0) {
    spindump_errorf("cannot allocate memory to parse a JSON record field name");
    return(0);
  }
  memcpy(string,*input,len);
  string[len] = 0;
  *input = closing+1;
  return(string);
}

//
// Look for a field in a schema description of a record. Return a
// pointer to the field definition if found, or 0 otherwise.
//

static const struct spindump_json_schema_field*
spindump_json_parse_record_aux_findfield(const struct spindump_json_schema* schema,
                                         const char* fieldName) {
  spindump_assert(schema != 0);
  spindump_deepdeepdebugf("spindump_json_parse_record_aux_findfield schema type %u field %s", schema->type, fieldName);
  spindump_assert(schema->type == spindump_json_schema_type_record);
  spindump_assert(fieldName != 0);
  for (unsigned int i = 0; i < schema->u.record.nFields; i++) {
    const struct spindump_json_schema_field* field = &schema->u.record.fields[i];
    if (strcmp(fieldName,field->name) == 0) {
      return(field);
    }
  }
  return(0);
}

//
// Add an item to a table of fields in a currently-being-parsed JSON
// record value object. Return 0 if the table is full or some other
// error occurs; 1 on success.
//

static int
spindump_json_parse_record_aux_addtofields(char* fieldName,
                                           struct spindump_json_value* value,
                                           unsigned int* nFields,
                                           unsigned int maxNFields,
                                           struct spindump_json_value_field* fields) {

  //
  // Sanity checks
  //
  
  spindump_assert(fields != 0);
  spindump_assert(*nFields <= maxNFields);
  spindump_assert(*nFields <= maxSchemaFields || *nFields <= maxOtherFields);
  spindump_assert(maxNFields == maxSchemaFields || maxNFields == maxOtherFields);
  spindump_deepdeepdebugf("spindump_json_parse_record_aux_addtofields %s (%uth)", fieldName, (*nFields)+1);
  
  //
  // Is the table full yet? If yes, return an error.
  //
  
  if (*nFields == maxNFields) {
    return(0);
  }
    
  //
  // There's still space. Add the field to the table.
  //
  
  fields[*nFields].name = fieldName;
  fields[*nFields].value = value;
  (*nFields)++;
  
  //
  // Done. Return success.
  //
  
  return(1);
}

//
// Helper function to parse a single field in a record. The field
// "name": value is added to one of the two tables (fields in schema
// and other fields).
//
// Returns 0 upon error, 1 on success.
//

static int
spindump_json_parse_record_aux_field(const struct spindump_json_schema* schema,
                                     void* data,
                                     const char** input,
                                     unsigned int* nSchemaFields,
                                     struct spindump_json_value_field* schemaFields,
                                     unsigned int* nOtherFields,
                                     struct spindump_json_value_field* otherFields) {

  //
  // Sanity checks
  //

  spindump_assert(schema != 0);
  spindump_assert(schema->type == spindump_json_schema_type_record);
  spindump_assert(input != 0 && *input != 0);
  spindump_assert(schemaFields != 0);
  spindump_assert(otherFields != 0);
  spindump_deepdeepdebugf("spindump_json_parse_record_aux_field from input %s...", *input);
  
  //
  // Parse the field name
  //
  
  char* fieldName = spindump_json_parse_record_aux_field_name(input);
  if (fieldName == 0) return(0);
  if (strlen(fieldName) == 0) {
    spindump_errorf("cannot parse JSON record: field name cannot be empty string");
    spindump_free(fieldName);
    return(0);
  }

  //
  // Skip the colon
  //
  
  spindump_json_parse_seekcurrentchar(input);
  if (**input != ':') {
    spindump_errorf("cannot parse JSON record: missing colon after field name");
    spindump_free(fieldName);
    return(0);
  }
  spindump_json_parse_movetonextchar(input);

  //
  // Find the possible field definition in the schema, if any
  //
  
  const struct spindump_json_schema_field* field = spindump_json_parse_record_aux_findfield(schema,fieldName);
  const struct spindump_json_schema* subtype = 0;
  struct spindump_json_schema any;
  any.type = spindump_json_schema_type_any;
  any.callback = 0;
  if (field != 0) subtype = field->schema; else subtype = &any;
  spindump_deepdeepdebugf("field %s value parsing, field schema type %u, input %s...",
                          fieldName, subtype->type, *input);
  
  //
  // Parse the field value using the known type (if any)
  //
  
  spindump_assert(subtype != 0);
  struct spindump_json_value* value = spindump_json_parse_aux(subtype,data,input);
  if (value == 0) {
    spindump_deepdeepdebugf("field %s value parsing failed, aborting", fieldName);
    spindump_free(fieldName);
    return(0);
  }
  spindump_deepdeepdebugf("field %s value parsing succeeded", fieldName);
  
  //
  // Add the newly read field to one of the field tables (either ones
  // found in schema or others).
  //
  
  int ans;
  if (field != 0) {
    ans = spindump_json_parse_record_aux_addtofields(fieldName,value,nSchemaFields,maxSchemaFields,schemaFields);
  } else {
    ans = spindump_json_parse_record_aux_addtofields(fieldName,value,nOtherFields,maxOtherFields,otherFields);
  }
  if (ans < 1) {
    spindump_deepdeepdebugf("adding to fields table failed, aborting");
    spindump_free(fieldName);
    return(0);
  }
  spindump_deepdeepdebugf("adding to fields table succeeded");
  
  //
  // Done
  //
  
  return(1);
}

//
// Look for a field with a given name in a table of fields. Return a
// pointer to the field if found, 0 otherwise.
//

struct spindump_json_value_field*
spindump_json_parse_lookforfield(const char* name,
                                 unsigned int nFields,
                                 struct spindump_json_value_field* fields) {
  spindump_assert(name != 0);
  spindump_assert(strlen(name) != 0);
  spindump_assert(fields != 0);
  spindump_deepdeepdebugf("looking for field %s", name);
  for (unsigned int i = 0; i < nFields; i++) {
    if (strcmp(name,fields[i].name) == 0) {
      return(&fields[i]);
    }
  }
  return(0);
}

//
// The internal parsing function, parsing a JSON record value {...}
// per given schema, from input given as a string in *input. This
// function advances the input pointer as it consumes the input. The
// "data" parameter is whatever the caller of the spindump_json_parse
// function decided to provide.
//
// Return the JSON value object. The caller is responsible for freeing
// the value object once it is done using it; the object and
// everything it refers to will be freshly allocated by this
// function. And upon an error, this function returns 0 and has
// cancelled all of its own allocations, if any.
//

static struct spindump_json_value*
spindump_json_parse_record(const struct spindump_json_schema* schema,
                           void* data,
                           const char** input) {

  //
  // Sanity checks
  //
  
  spindump_assert(schema != 0);
  spindump_assert(schema->type == spindump_json_schema_type_record);
  spindump_assert(input != 0);
  spindump_assert(*input != 0);
  
  //
  // Parse the opening brace
  //
  
  spindump_json_parse_seekcurrentchar(input);
  spindump_deepdeepdebugf("spindump_json_parse_record parsing %s...", *input);
  if (**input != '{') {
    spindump_errorf("cannot parse JSON record: missing opening brace");
    return(0);
  }
  spindump_json_parse_movetonextchar(input);
  spindump_json_parse_seekcurrentchar(input);

  //
  // Setup two tables of fields, one with known fields, and the other
  // with unknown (not in schema)
  //
  
  unsigned int nSchemaFields = 0;
  unsigned int nOtherFields = 0;
  struct spindump_json_value_field schemaFields[maxSchemaFields];
  struct spindump_json_value_field otherFields[maxOtherFields];

  //
  // Loop while there are fields and we haven't hit the closing brace
  // yet.
  //
  
  while (**input != '}') {

    spindump_deepdeepdebugf("record parsing loop, input = %s...", *input);
    
    if (**input == 0) {
      spindump_errorf("cannot parse JSON record: missing closing brace");
      spindump_json_parse_record_aux_free(nSchemaFields,schemaFields,nOtherFields,otherFields);
      return(0);
    }
    int ans = spindump_json_parse_record_aux_field(schema,data,input,
                                                   &nSchemaFields,schemaFields,
                                                   &nOtherFields,otherFields);
    if (ans < 1) {
      spindump_deepdeepdebugf("failed to parse a field");
      spindump_json_parse_record_aux_free(nSchemaFields,schemaFields,nOtherFields,otherFields);
      return(0);
    }
    spindump_deepdeepdebugf("succeeded in parsing a field");
    spindump_json_parse_seekcurrentchar(input);
    if (**input == ',') {
      spindump_json_parse_movetonextchar(input);
      spindump_json_parse_seekcurrentchar(input);
      if (**input == '}') {
        spindump_errorf("cannot parse JSON record: closing brace after comma");
        spindump_json_parse_record_aux_free(nSchemaFields,schemaFields,nOtherFields,otherFields);
        return(0);
      } else {
        continue;
      }
    } else if (**input == '}') {
      break;
    } else {
      spindump_errorf("cannot parse JSON record: syntax error on char %c after field", **input);
      spindump_json_parse_record_aux_free(nSchemaFields,schemaFields,nOtherFields,otherFields);
      return(0);
    }
  }

  //
  // Pass the closing brace
  //

  spindump_deepdeepdebugf("done parsing the record body, now expecting closing brace");
  
  spindump_assert(**input == '}');
  spindump_json_parse_movetonextchar(input);
  
  //
  // Check that the record comfors to the schema, i.e., that no
  // mandatory fields are missing.
  //

  spindump_deepdebugf("schema comformance check for the record");
  
  for (unsigned int q = 0; q < schema->u.record.nFields; q++) {
    const struct spindump_json_schema_field* schemaField =
      &schema->u.record.fields[q];
    spindump_assert(schemaField != 0);
    if (schemaField->required && spindump_json_parse_lookforfield(schemaField->name,nSchemaFields,schemaFields) == 0) {
      spindump_errorf("field %s is missing from the JSON record", schemaField->name);
      spindump_json_parse_record_aux_free(nSchemaFields,schemaFields,nOtherFields,otherFields);
      return(0);
    }
  }
  
  //
  // Create a JSON value record object
  //

  struct spindump_json_value* value =
    spindump_json_value_new_record(nSchemaFields,schemaFields,nOtherFields,otherFields);
  if (value == 0) {
      spindump_json_parse_record_aux_free(nSchemaFields,schemaFields,nOtherFields,otherFields);
      return(0);
  }
  
  //
  // Done. Return the created record object.
  //
  
  return(value);
}

//
// Parse either a record or array, depending on what first character
// tells us it is ("[" or "{").
//
// Return the JSON value object. The caller is responsible for freeing
// the value object once it is done using it; the object and
// everything it refers to will be freshly allocated by this
// function. And upon an error, this function returns 0 and has
// cancelled all of its own allocations, if any.
//

static struct spindump_json_value*
spindump_json_parse_recordorarray(const struct spindump_json_schema* schema,
                                  void* data,
                                  const char** input) {

  //
  // Sanity checks
  //
  
  spindump_assert(schema != 0);
  spindump_assert(schema->type == spindump_json_schema_type_recordorarray);
  spindump_assert(input != 0);
  spindump_assert(*input != 0);

  //
  // Get to first non-whitespace char and then decide
  //
  
  spindump_json_parse_seekcurrentchar(input);
  spindump_deepdeepdebugf("spindump_json_parse_recordorarray parsing %s...", *input);
  if (**input == '[') {
    return(spindump_json_parse_array(schema->u.arrayorrecord.array,data,input));
  } else {
    return(spindump_json_parse_record(schema->u.arrayorrecord.record,data,input));
  }
}

//
// Parse either a record or array or a literal, depending on what
// first character tells us it is ("[", "{", "\"", or "0" to "9").
//
// Return the JSON value object. The caller is responsible for freeing
// the value object once it is done using it; the object and
// everything it refers to will be freshly allocated by this
// function. And upon an error, this function returns 0 and has
// cancelled all of its own allocations, if any.
//

static struct spindump_json_value*
spindump_json_parse_any(const struct spindump_json_schema* schema,
                        void* data,
                        const char** input) {

  //
  // Sanity checks
  //

  spindump_assert(schema != 0);
  spindump_assert(schema->type == spindump_json_schema_type_any);
  spindump_assert(input != 0);
  spindump_assert(*input != 0);

  //
  // Get to the first non-whitespace char and then decide
  //
  
  spindump_json_parse_seekcurrentchar(input);
  spindump_deepdeepdebugf("spindump_json_parse_any parsing %s...", *input);

  //
  // Look at the char
  //
  
  if (isdigit(**input)) {
    return(spindump_json_parse_integer(input));
  } else if (**input == '\"') {
    return(spindump_json_parse_string(input));
  } else if (**input == '[') {
    struct spindump_json_schema array;
    struct spindump_json_schema any = *schema;
    array.type = spindump_json_schema_type_array;
    array.callback = 0;
    array.u.array.schema = &any;
    return(spindump_json_parse_array(&array,data,input));
  } else {
    struct spindump_json_schema record;
    record.type = spindump_json_schema_type_record;
    record.callback = 0;
    record.u.record.nFields = 0;
    return(spindump_json_parse_record(&record,data,input));
  }
}

//
// Seek forward in the input (the textual input is in *input, this
// function will move the pointer forward as needed e.g. to skip
// whitespace).
//
 
static void
spindump_json_parse_seekcurrentchar(const char** input) {
  while ((**input) != 0 && isspace(**input)) {
    spindump_json_parse_movetonextchar(input);
  }
}
