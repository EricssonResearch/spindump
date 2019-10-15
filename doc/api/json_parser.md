# JSON Parser

The spindump_json.h include file defines an API to a module that can parse and print JSON structures. See also the [JSON value](https://github.com/EricssonResearch/spindump/blob/master/doc/api/json_value.md) API.

The API functions and data structures are as follows:

## spindump_json_parse function

This function simply takes a schema object (perhaps statically defined), a caller's data parameter, and an input string, and attempts to parse the input according to the schema object. Callbacks in the schema definition will be called when the input is read correctly, and the caller's data parameter is one of the parameters passed to the callbacks.

This function returns 1 upon successful parsing, and 0 upon failure.

The prototype is as follows: 

    int
    spindump_json_parse(const struct spindump_json_schema* schema,
                        void* data,
                        const char** input);

## callback  interface

The schema data structure may contain pointers to callback functions that get called when a particular part of an object is read. The object is given as a parameter to the callback function.

The prototype is as follows: 

    typedef void (*spindump_json_callback)(const struct spindump_json_value* value,
                                           const struct spindump_json_schema* type,
                                           void* data);


## spindump_json_schema data structure

The following 'struct' objects can be used to describe a JSON schema:

The struct spindump_json_schema is the overall schema type, internally representing either an integer, string, literal (either integer or string), record, array, recordorarray, or any type of a JSON object. This data structure has the following main components:

* type -- The type of JSON object expected.
* callback  -- A pointer to a function to be called upon successful parsing of the object (or 0 if no function needs to be called)
* u -- A union of more specific data structures to hold the complex objects.

The complex objects can be:

* struct spindump_json_schema_record describes a record type with specific fields 
* struct spindump_json_schema_field describes a field in a record
* struct spindump_json_schema_array describes an array
* struct spindump_json_schema_arrayorrecord describes something that needs to be either an array or a record
