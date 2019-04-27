
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

//
// Function prototypes ------------------------------------------------------------------------
//

static void
spindump_json_value_free_field(struct spindump_json_value_field* field);
static int
spindump_json_value_copy_field(struct spindump_json_value_field* field,
                               const struct spindump_json_value_field* value);
static void
spindump_json_value_tostring_aux(const struct spindump_json_value* value,
                                 char** buffer,
                                 size_t* bufferSize,
                                 unsigned int* position);

//
// Actual code --------------------------------------------------------------------------------
//

//
// Copy a field. This function is only used internally.
//
// The return value 1 only if the copying succeeded, otherwise 0.
//

static int
spindump_json_value_copy_field(struct spindump_json_value_field* field,
                               const struct spindump_json_value_field* value) {
  spindump_assert(field != 0);
  spindump_assert(value != 0);
  spindump_assert(field != value);
  field->name = spindump_strdup(value->name);
  if (field->name == 0) {
    return(0);
  }
  field->value = spindump_json_value_copy(value->value);
  if (field->value == 0) {
    spindump_free(field->name);
    return(0);
  }
  return(1);
}

//
// Copy a JSON value structure. This is a deep copy, i.e., it will
// copy all subfields etc as well. No part of the returned value
// shares any memory with the input structure.
//
// If the return value is 0, then allocation failed. Otherwise the
// return value is the newly allocated object.
//

struct spindump_json_value*
spindump_json_value_copy(const struct spindump_json_value* value) {

  //
  // Sanity checks
  //
  
  spindump_assert(value != 0);

  //
  // Allocate the new base value
  //
  
  struct spindump_json_value* newValue =
    (struct spindump_json_value*)spindump_malloc(sizeof(struct spindump_json_value));
  if (newValue == 0) {
    spindump_errorf("cannot allocate a JSON value object when copying");
    return(0);
  }

  //
  // Set the basic values
  //

  newValue->type = value->type;
  
  //
  // Do any type-specific allocation (fields etc) that is needed
  //

  unsigned int i;
  switch (value->type) {
    
  case spindump_json_value_type_integer:
    newValue->u.integer.value = value->u.integer.value;
    break;
    
  case spindump_json_value_type_string:
    newValue->u.string.value = spindump_strdup(value->u.string.value);
    if (newValue->u.string.value == 0) {
      spindump_free(newValue);
      spindump_errorf("cannot allocate a JSON value string when copying");
      return(0);
    }
    break;
    
  case spindump_json_value_type_record:
    spindump_assert(value->u.record.schemaFields != 0);
    spindump_assert(value->u.record.otherFields != 0);
    newValue->u.record.nSchemaFields = value->u.record.nSchemaFields;
    newValue->u.record.schemaFields =
      (struct spindump_json_value_field*)spindump_malloc(spindump_max(1,value->u.record.nSchemaFields) *
                                                         sizeof(struct spindump_json_value_field));
    if (newValue->u.record.schemaFields == 0) {
      spindump_free(newValue);
      spindump_errorf("cannot allocate a JSON value record schema fields when copying");
      return(0);
    }
    newValue->u.record.nOtherFields = value->u.record.nOtherFields;
    newValue->u.record.otherFields =
      (struct spindump_json_value_field*)spindump_malloc(spindump_max(1,value->u.record.nOtherFields) *
                                                         sizeof(struct spindump_json_value_field));
    if (newValue->u.record.otherFields == 0) {
      spindump_free(newValue->u.record.schemaFields);
      spindump_free(newValue);
      spindump_errorf("cannot allocate a JSON value record other fields when copying");
      return(0);
    }
    for (i = 0; i < value->u.record.nSchemaFields; i++) {
      if (!spindump_json_value_copy_field(&newValue->u.record.schemaFields[i],
                                          &value->u.record.schemaFields[i])) {
        for (unsigned int k = 0; k < i; k++) {
          spindump_json_value_free_field(&newValue->u.record.schemaFields[k]);
        }
        spindump_free(newValue->u.record.schemaFields);
        spindump_free(newValue->u.record.otherFields);
        spindump_free(newValue);
        return(0);
      }
    }
    for (i = 0; i < value->u.record.nOtherFields; i++) {
      if (!spindump_json_value_copy_field(&newValue->u.record.otherFields[i],
                                          &value->u.record.otherFields[i])) {
        for (unsigned int p = 0; p < value->u.record.nSchemaFields; p++) {
          spindump_json_value_free_field(&newValue->u.record.schemaFields[p]);
        }
        for (unsigned int q = 0; q < i; q++) {
          spindump_json_value_free_field(&newValue->u.record.otherFields[q]);
        }
        spindump_free(newValue->u.record.schemaFields);
        spindump_free(newValue->u.record.otherFields);
        spindump_free(newValue);
        return(0);
      }
    }
    break;
    
  case spindump_json_value_type_array:
    spindump_assert(value->u.array.elements != 0);
    newValue->u.array.n = value->u.array.n;
    newValue->u.array.elements =
      (struct spindump_json_value**)spindump_malloc(spindump_max(1,value->u.array.n) *
                                                    sizeof(struct spindump_json_value*));
    if (newValue->u.array.elements == 0) {
      spindump_free(newValue);
      spindump_errorf("cannot allocate a JSON value array table");
      return(0);
    }
    for (i = 0; i < value->u.array.n; i++) {
      newValue->u.array.elements[i] =
        spindump_json_value_copy(value->u.array.elements[i]);
      if (newValue->u.array.elements[i] == 0) {
        for (unsigned int j = 0; j < i; j++) {
          spindump_json_value_free(newValue->u.array.elements[j]);
        }
        spindump_free(newValue->u.array.elements);
        spindump_free(newValue);
        return(0);
      }
    }
    break;
    
  default:
    spindump_errorf("invalid internal JSON value type");
  }

  //
  // Done. Return the new value.
  //
  
  return(newValue);
}

//
// Deallocate a field value. This is only used internally.
//

static void
spindump_json_value_free_field(struct spindump_json_value_field* field) {
  spindump_assert(field != 0);
  spindump_assert(field->name != 0);
  spindump_assert(field->value != 0);
  spindump_free(field->name);
  spindump_json_value_free(field->value);
}

//
// Deallocate memory assigned to a JSON value structure (including any
// referred to subcomponents).
//

void
spindump_json_value_free(struct spindump_json_value* value) {

  //
  // Sanity checks
  //
  
  spindump_assert(value != 0);
  spindump_deepdeepdebugf("json_value_free(%u)", value->type);
  
  //
  // Branch off based on type of the value
  //
  
  unsigned int i;
  switch (value->type) {
    
  case spindump_json_value_type_integer:
    break;
    
  case spindump_json_value_type_string:
    spindump_free(value->u.string.value);
    break;
    
  case spindump_json_value_type_record:
    spindump_deepdeepdebugf("case record %u + %u fields",
                            value->u.record.nSchemaFields,
                            value->u.record.nOtherFields);
    spindump_assert(value->u.record.schemaFields != 0);
    spindump_assert(value->u.record.otherFields != 0);
    for (i = 0; i < value->u.record.nSchemaFields; i++) {
      spindump_deepdeepdebugf("spindump_json_value_free freeing up record field %s", value->u.record.schemaFields[i].name);
      spindump_json_value_free_field(&value->u.record.schemaFields[i]);
    }
    for (i = 0; i < value->u.record.nOtherFields; i++) {
      spindump_deepdeepdebugf("spindump_json_value_free freeing up record field %s", value->u.record.otherFields[i].name);
      spindump_json_value_free_field(&value->u.record.otherFields[i]);
    }
    spindump_free(value->u.record.schemaFields);
    spindump_free(value->u.record.otherFields);
    break;
    
  case spindump_json_value_type_array:
    spindump_assert(value->u.array.elements != 0);
    for (i = 0; i < value->u.array.n; i++) {
      spindump_deepdeepdebugf("spindump_json_value_free freeing up array element %u/%u", i, value->u.array.n);
      spindump_json_value_free(value->u.array.elements[i]);
    }
    spindump_free(value->u.array.elements);
    break;
    
  default:
    spindump_errorf("invalid internal JSON value type %u", value->type);
    
  }

  //
  // Free up the actual value object
  //

  spindump_deepdeepdebugf("spindump_json_value_free, freed the contents, now freeing the actual object (type %u)", value->type);
  spindump_free(value);
}

//
// Create a new JSON value object for an integer value
//
// The return value is the new string object.
//

struct spindump_json_value*
spindump_json_value_new_integer(unsigned long long value) {
  struct spindump_json_value* newValue =
    (struct spindump_json_value*)spindump_malloc(sizeof(struct spindump_json_value));
  if (newValue == 0) {
    spindump_errorf("cannot allocate a JSON value");
    return(0);
  }
  newValue->type = spindump_json_value_type_integer;
  newValue->u.integer.value = value;
  return(newValue);
}

//
// Create a new JSON value object for a string value
//
// The return value is the new string object.
//

struct spindump_json_value*
spindump_json_value_new_string(const char* bytes,
                               size_t n) {
  struct spindump_json_value* newValue =
    (struct spindump_json_value*)spindump_malloc(sizeof(struct spindump_json_value));
  if (newValue == 0) {
    spindump_errorf("cannot allocate a JSON value");
    return(0);
  }
  newValue->type = spindump_json_value_type_string;
  newValue->u.string.value = (char*)spindump_malloc(n+1);
  if (newValue->u.string.value == 0) {
    spindump_errorf("cannot allocate a JSON value");
    spindump_free(newValue);
    return(0);
  }
  memcpy(newValue->u.string.value,bytes,n);
  newValue->u.string.value[n] = 0;
  return(newValue);
}

//
// Create a new JSON value object for a record {...} value. Note that
// the given field values are NOT copied, but rather used
// as-is. However, the arrays "schemeFields" and "otherFields" ARE
// copied.
//
// The return value is the new record object.
//

struct spindump_json_value*
spindump_json_value_new_record(unsigned int nSchemaFields,
                               struct spindump_json_value_field* schemaFields,
                               unsigned int nOtherFields,
                               struct spindump_json_value_field* otherFields) {

  //
  // Sanity checks
  //

  spindump_assert(schemaFields != 0);
  spindump_assert(otherFields != 0);

  //
  // Allocate and initialize basic object
  //
  
  struct spindump_json_value* newValue =
    (struct spindump_json_value*)spindump_malloc(sizeof(struct spindump_json_value));
  if (newValue == 0) {
    spindump_errorf("cannot allocate a JSON value");
    return(0);
  }
  newValue->type = spindump_json_value_type_record;

  //
  // Allocate and copy schema fields table
  //

  spindump_deepdeepdebugf("schema fields %u", nSchemaFields);
  newValue->u.record.nSchemaFields = nSchemaFields;
  newValue->u.record.schemaFields =
    (struct spindump_json_value_field*)spindump_malloc(spindump_max(1,nSchemaFields) *
                                                       sizeof(struct spindump_json_value_field));
  if (newValue->u.record.schemaFields == 0) {
    spindump_free(newValue);
    spindump_errorf("cannot allocate a JSON value record schema fields");
    return(0);
  }
  
  for (unsigned i = 0; i < nSchemaFields; i++) {
    newValue->u.record.schemaFields[i] = schemaFields[i];
  }
  
  //
  // Allocate and copy other fields table
  //
  
  spindump_deepdeepdebugf("other fields %u", nOtherFields);
  newValue->u.record.nOtherFields = nOtherFields;
  newValue->u.record.otherFields =
    (struct spindump_json_value_field*)spindump_malloc(spindump_max(1,nOtherFields) *
                                                       sizeof(struct spindump_json_value_field));
  if (newValue->u.record.otherFields == 0) {
    spindump_free(newValue->u.record.schemaFields);
    spindump_free(newValue);
    spindump_errorf("cannot allocate a JSON value record other fields");
    return(0);
  }
  
  for (unsigned i = 0; i < nOtherFields; i++) {
    newValue->u.record.otherFields[i] = otherFields[i];
  }
  
  //
  // Done!
  //
  
  return(newValue);
}

//
// Create a new JSON value object for an array [...] value, with no
// elements initially stored
//
// The return value is the new array object.
//

struct spindump_json_value*
spindump_json_value_new_array() {
  struct spindump_json_value* newValue =
    (struct spindump_json_value*)spindump_malloc(sizeof(struct spindump_json_value));
  if (newValue == 0) {
    spindump_errorf("cannot allocate a JSON value");
    return(0);
  }
  newValue->type = spindump_json_value_type_array;
  newValue->u.array.n = 0;
  newValue->u.array.elements = (struct spindump_json_value**)spindump_malloc(1);
  if (newValue->u.array.elements == 0) {
    spindump_errorf("cannot allocate a JSON value");
    spindump_free(newValue);
    return(0);
  }
  return(newValue);
}

//
// Add a new element into a JSON object that represents an array
// value. Note that the new element is NOT copied, but rather used
// as-is.
//
// The return value is 1 if the addition was successful, 0 otherwise.
//

int
spindump_json_value_new_array_element(struct spindump_json_value* array,
                                      struct spindump_json_value* newElement) {

  //
  // Sanity checks
  //
  
  spindump_assert(array != 0);
  spindump_assert(array->type == spindump_json_value_type_array);
  spindump_assert(array->u.array.elements != 0);
  spindump_assert(newElement != 0);
  spindump_deepdeepdebugf("adding a new array element (%uth)", array->u.array.n + 1);
  
  //
  // Allocate more memory
  //

  unsigned int newN = array->u.array.n + 1;
  struct spindump_json_value** newElements =
    (struct spindump_json_value**)spindump_malloc(spindump_max(1,newN) * sizeof(struct spindump_json_value*));
  if (newElements == 0) {
    spindump_errorf("cannot add space to a JSON array object");
    return(0);
  }
  
  //
  // Move old contents to new table
  //

  for (unsigned int i = 0; i < array->u.array.n; i++) {
    newElements[i] = array->u.array.elements[i];
  }
  spindump_free(array->u.array.elements);
  array->u.array.elements = newElements;
  array->u.array.elements[array->u.array.n] = newElement;
  array->u.array.n = newN;
  
  //
  // All ok
  //
  
  return(1);
}

//
// Convert a JSON structure onto a string. The return value is 0 if
// something (allocation) failed, otherwise it is a pointer to a
// NUL-terminated string containing the printed version of the JSON
// structure. The return value, if non-0, needs to be deallocated by the
// caller.
//

char*
spindump_json_value_tostring(const struct spindump_json_value* value) {
  const size_t initialSize = 50;
  size_t size = initialSize;
  char* buffer = (char*)spindump_malloc(initialSize);
  if (buffer == 0) {
    spindump_errorf("cannot allocate a string to JSON value");
    return(0);
  }
  unsigned int position = 0;
  spindump_json_value_tostring_aux(value,&buffer,&size,&position);
  if (size == 0) return(0);
  spindump_assert(position < size);
  buffer[position] = 0;
  return(buffer);
}

//
// Helper function to print a JSON objcet to a string.
//

static void
spindump_json_value_tostring_aux(const struct spindump_json_value* value,
                                 char** buffer,
                                 size_t* bufferSize,
                                 unsigned int* position) {

  //
  // Sanity checks
  //

  spindump_assert(value != 0);
  
  //
  // Helper macros for buffer allocation and string adding
  //

# define checkbufferspace(n)                            \
  if (!(*position + (n) + 1 < *bufferSize)) {           \
    size_t newSize = *bufferSize + 50 + (n);            \
    char* newBuffer = (char*)spindump_malloc(newSize);  \
    if (newBuffer == 0) {                               \
      spindump_errorf("cannot allocate space for JSON " \
                      "object string conversion");      \
      spindump_free(*buffer);                           \
      *bufferSize = 0;                                  \
      return;                                           \
    }                                                   \
    spindump_free(*buffer);                             \
    *buffer = newBuffer;                                \
    *bufferSize = newSize;                              \
  }

# define addtobuffer(s,n)                               \
  spindump_assert(*bufferSize - *position > (n));       \
  memcpy(*buffer + *position,(s),(n));                  \
  *position += (n);
  
  //
  // Switch based on what kind of object this is
  //
  
  switch (value->type) {
    
  case spindump_json_value_type_integer:
    {
      unsigned int maxdigits = 40;
      checkbufferspace(maxdigits);
      int used = snprintf((*buffer)+(*position),*bufferSize-*position,
                          "%llu",
                          value->u.integer.value);
      spindump_assert(((unsigned int)used) < maxdigits);
      *position += (unsigned int)used;
    }
    break;
    
  case spindump_json_value_type_string:
    {
      size_t needed = strlen(value->u.string.value);
      checkbufferspace(1+needed+1);
      addtobuffer("\"",1);
      addtobuffer(value->u.string.value,needed);
      addtobuffer("\"",1);
    }
    break;
    
  case spindump_json_value_type_record:
    {
      spindump_assert(value->u.record.schemaFields != 0);
      spindump_assert(value->u.record.otherFields != 0);
      checkbufferspace(1);
      addtobuffer("{",1);
      unsigned int i,j;
      for (i = 0; i < value->u.record.nSchemaFields; i++) {
        if (i > 0) {
          checkbufferspace(1);
          addtobuffer(",",1);
        }
        const struct spindump_json_value_field* field = &value->u.record.schemaFields[i];
        checkbufferspace(1);
        addtobuffer("\"",1);
        checkbufferspace(strlen(field->name));
        addtobuffer(field->name,strlen(field->name));
        checkbufferspace(2);
        addtobuffer("\":",2);
        spindump_json_value_tostring_aux(field->value,buffer,bufferSize,position);
      }
      for (j = 0; j < value->u.record.nOtherFields; j++) {
        if (i + j > 0) {
          checkbufferspace(1);
          addtobuffer(",",1);
        }
        const struct spindump_json_value_field* field = &value->u.record.otherFields[i];
        spindump_json_value_tostring_aux(field->value,buffer,bufferSize,position);
      }
      checkbufferspace(1);
      addtobuffer("}",1);
    }
    break;
    
  case spindump_json_value_type_array:
    {
      spindump_assert(value->u.array.elements != 0);
      checkbufferspace(1);
      addtobuffer("[",1);
      for (unsigned int k = 0; k < value->u.array.n; k++) {
        if (k > 0) {
          checkbufferspace(1);
          addtobuffer(",",1);
        }
        spindump_json_value_tostring_aux(value->u.array.elements[k],
                                         buffer,
                                         bufferSize,
                                         position);
      }
      checkbufferspace(1);
      addtobuffer("]",1);
    }
    break;
    
  default:
    spindump_errorf("invalid internal JSON value type");
  }
}
