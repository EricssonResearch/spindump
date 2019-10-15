# JSON Value

The spindump_json.h include file defines an API to a module that can parse and print JSON structures. See also the [JSON value](https://github.com/EricssonResearch/spindump/blob/master/doc/api/json_value.md) API.

The API functions and data structures are as follows:

# data structure spindump_json_value

This is an object that represents one (possibly complex) JSON value. The field 'type' in the object indicates which type of a value is there:

* spindump_json_value_type_integer -- integer value
* spindump_json_value_type_string -- string value
* spindump_json_value_type_record -- a record
* spindump_json_value_type_array -- an array

# spindump_json_value_new_integer

This function creates a new value object of type integer. 

The prototype is as follows: 

    struct spindump_json_value*
    spindump_json_value_new_integer(unsigned long long value);

# spindump_json_value_new_string

This function creates a new value object of type string.

The prototype is as follows: 

    struct spindump_json_value*
    spindump_json_value_new_string(const char* bytes,
                                   size_t n);

# spindump_json_value_new_record

This function creates a new value object of type record.

The prototype is as follows: 

    struct spindump_json_value*
    spindump_json_value_new_record(unsigned int nSchemaFields,
                                   struct spindump_json_value_field* schemaFields,
                                   unsigned int nOtherFields,
                                   struct spindump_json_value_field* otherFields);

# spindump_json_value_new_array

This function creates a new value object of type array.

The prototype is as follows: 

    struct spindump_json_value*
    spindump_json_value_new_array(void);

# spindump_json_value_new_array_element

This function adds a new element to an array.

The prototype is as follows: 

    int
    spindump_json_value_new_array_element(struct spindump_json_value* array,
                                          struct spindump_json_value* newElement);

# spindump_json_value_copy

This function copies a JSON value object.

The prototype is as follows: 

    struct spindump_json_value*
    spindump_json_value_copy(const struct spindump_json_value* value);

# spindump_json_value_free

This function frees a JSON value object.

The prototype is as follows: 

    void
    spindump_json_value_free(struct spindump_json_value* value);

# spindump_json_value_getfield

This function searches for a field in a record, and returns the associated value. Or 0, if no field with the given name was found.  
 
The prototype is as follows: 

    const struct spindump_json_value*
    spindump_json_value_getfield(const char* field,
                                 const struct spindump_json_value* value);

# spindump_json_value_getrequiredfield

This function searches for a field in a record, and returns the associated value. An assertion fails if the field is not present.
 
The prototype is as follows: 

    const struct spindump_json_value*
    spindump_json_value_getrequiredfield(const char* field,
                                         const struct spindump_json_value* value);

# spindump_json_value_getarrayelem

This function returns an array element from an array JSON object.

The prototype is as follows: 

    const struct spindump_json_value*
    spindump_json_value_getarrayelem(unsigned int index,
                                     const struct spindump_json_value* value);

# spindump_json_value_getinteger

This function returns the integer value of an integer JSON object. 
 
The prototype is as follows: 

    unsigned long long
    spindump_json_value_getinteger(const struct spindump_json_value* value);

#  spindump_json_value_getstring

This function returns the string value of a string JSON object. 
 
The prototype is as follows: 

    const char*
    spindump_json_value_getstring(const struct spindump_json_value* value);

# spindump_json_value_tostring

This function "prints" an JSON object as a string.

The prototype is as follows: 

    char*
    spindump_json_value_tostring(const struct spindump_json_value* value);
