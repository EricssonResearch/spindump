
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "spindump_util.h"
#include "spindump_event.h"
#include "spindump_event_parser_json.h"
#include "spindump_connections.h"
#include "spindump_json.h"
#include "spindump_json_value.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static int
spindump_event_parser_json_converteventtype(const char* string,
                                            enum spindump_event_type* type);
static int
spindump_event_parser_json_parse_aux_new_connection(const struct spindump_json_value* json,
                                                    struct spindump_event* event);
static int
spindump_event_parser_json_parse_aux_change_connection(const struct spindump_json_value* json,
                                                       struct spindump_event* event);
static int
spindump_event_parser_json_parse_aux_connection_delete(const struct spindump_json_value* json,
                                                       struct spindump_event* event);
static int
spindump_event_parser_json_parse_aux_new_rtt_measurement(const struct spindump_json_value* json,
                                                         struct spindump_event* event);
static int
spindump_event_parser_json_parse_aux_periodic(const struct spindump_json_value* json,
                                              struct spindump_event* event);
static int
spindump_event_parser_json_parse_aux_spin_flip(const struct spindump_json_value* json,
                                               struct spindump_event* event);
static int
spindump_event_parser_json_parse_aux_spin_value(const struct spindump_json_value* json,
                                                struct spindump_event* event);
static int
spindump_event_parser_json_parse_aux_ecn_congestion_event(const struct spindump_json_value* json,
                                                          struct spindump_event* event);
static int
spindump_event_parser_json_parse_aux_rtloss_measurement(const struct spindump_json_value* json,
                                                        struct spindump_event* event);
static int
spindump_event_parser_json_parse_aux_qrloss_measurement(const struct spindump_json_value* json,
                                                        struct spindump_event* event);
static int
spindump_event_parser_json_parse_aux_qlloss_measurement(const struct spindump_json_value* json,
                                                        struct spindump_event* event);
static int
spindump_event_parser_json_parse_aux_packet(const struct spindump_json_value* json,
                                            struct spindump_event* event);
static void
spindump_event_parser_json_textparse_callback(const struct spindump_json_value* value,
                                              const struct spindump_json_schema* type,
                                              void* data);

//
// Data types ---------------------------------------------------------------------------------
//

struct spindump_event_parser_json_parsingcontext {
  spindump_event_parser_json_callback callback;
  void* data;
  int success;
};

//
// Variables and constants --------------------------------------------------------------------
//

static struct spindump_json_schema fieldeventschema = {
  .type = spindump_json_schema_type_string,
  .callback = 0
};

static struct spindump_json_schema fieldtypeschema = {
  .type = spindump_json_schema_type_string,
  .callback = 0
};

static struct spindump_json_schema fieldstateschema = {
  .type = spindump_json_schema_type_string,
  .callback = 0
};

static struct spindump_json_schema fieldaddrschema = {
  .type = spindump_json_schema_type_string,
  .callback = 0
};

static struct spindump_json_schema fieldaddrsschema = {
  .type = spindump_json_schema_type_array,
  .callback = 0,
  .u = {
    .array = {
      .schema = &fieldaddrschema
    }
  }
};

static struct spindump_json_schema fieldsessionschema = {
  .type = spindump_json_schema_type_string,
  .callback = 0
};

static struct spindump_json_schema fieldtsschema = {
  .type = spindump_json_schema_type_integer,
  .callback = 0
};

static struct spindump_json_schema fieldrttschema = {
  .type = spindump_json_schema_type_integer,
  .callback = 0
};

static struct spindump_json_schema fieldvalueschema = {
  .type = spindump_json_schema_type_integer,
  .callback = 0
};

static struct spindump_json_schema fieldtransitionschema = {
  .type = spindump_json_schema_type_string,
  .callback = 0
};

static struct spindump_json_schema fieldwhoschema = {
  .type = spindump_json_schema_type_string,
  .callback = 0
};

static struct spindump_json_schema fieldpackets1schema = {
  .type = spindump_json_schema_type_integer,
  .callback = 0
};

static struct spindump_json_schema fieldpackets2schema = {
  .type = spindump_json_schema_type_integer,
  .callback = 0
};

static struct spindump_json_schema fieldbytes1schema = {
  .type = spindump_json_schema_type_integer,
  .callback = 0
};

static struct spindump_json_schema fieldbytes2schema = {
  .type = spindump_json_schema_type_integer,
  .callback = 0
};

static struct spindump_json_schema fieldbandwidth1schema = {
  .type = spindump_json_schema_type_integer,
  .callback = 0
};

static struct spindump_json_schema fieldbandwidth2schema = {
  .type = spindump_json_schema_type_integer,
  .callback = 0
};

static struct spindump_json_schema fieldecn0schema = {
  .type = spindump_json_schema_type_integer,
  .callback = 0
};

static struct spindump_json_schema fieldecn1schema = {
  .type = spindump_json_schema_type_integer,
  .callback = 0
};

static struct spindump_json_schema fieldceschema = {
  .type = spindump_json_schema_type_integer,
  .callback = 0
};

static struct spindump_json_schema fieldlossschema = {
  .type = spindump_json_schema_type_string,
  .callback = 0
};

static struct spindump_json_schema fieldlengthschema = {
  .type = spindump_json_schema_type_integer,
  .callback = 0
};

static struct spindump_json_schema fielddirschema = {
  .type = spindump_json_schema_type_string,
  .callback = 0
};

static struct spindump_json_schema fieldtagsschema = {
  .type = spindump_json_schema_type_string,
  .callback = 0
};

static struct spindump_json_schema fieldnotesschema = {
  .type = spindump_json_schema_type_string,
  .callback = 0
};

static struct spindump_json_schema recordschema = {
  .type = spindump_json_schema_type_record,
  .callback = 0,
  .u = {
    .record = {
      .nFields = 43,
      .fields = {
        { .required = 1, .name = "Event", .schema = &fieldeventschema },
        { .required = 1, .name = "Type", .schema = &fieldtypeschema },
        { .required = 1, .name = "State", .schema = &fieldstateschema },
        { .required = 1, .name = "Addrs", .schema = &fieldaddrsschema },
        { .required = 1, .name = "Session", .schema = &fieldsessionschema },
        { .required = 1, .name = "Ts", .schema = &fieldtsschema },
        { .required = 0, .name = "Left_rtt", .schema = &fieldrttschema },
        { .required = 0, .name = "Right_rtt", .schema = &fieldrttschema },
        { .required = 0, .name = "Full_rtt_initiator", .schema = &fieldrttschema },
        { .required = 0, .name = "Full_rtt_responder", .schema = &fieldrttschema },
        { .required = 0, .name = "Avg_left_rtt", .schema = &fieldrttschema },
        { .required = 0, .name = "Avg_right_rtt", .schema = &fieldrttschema },
        { .required = 0, .name = "Avg_full_rtt_initiator", .schema = &fieldrttschema },
        { .required = 0, .name = "Avg_full_rtt_responder", .schema = &fieldrttschema },
        { .required = 0, .name = "Filt_avg_left_rtt", .schema = &fieldrttschema },
        { .required = 0, .name = "Filt_avg_right_rtt", .schema = &fieldrttschema },
        { .required = 0, .name = "Filt_avg_full_rtt_initiator", .schema = &fieldrttschema },
        { .required = 0, .name = "Filt_avg_full_rtt_responder", .schema = &fieldrttschema },
        { .required = 0, .name = "Dev_left_rtt", .schema = &fieldrttschema },
        { .required = 0, .name = "Dev_right_rtt", .schema = &fieldrttschema },
        { .required = 0, .name = "Dev_full_rtt_initiator", .schema = &fieldrttschema },
        { .required = 0, .name = "Dev_full_rtt_responder", .schema = &fieldrttschema },
        { .required = 0, .name = "Min_left_rtt", .schema = &fieldrttschema },
        { .required = 0, .name = "Min_right_rtt", .schema = &fieldrttschema },
        { .required = 0, .name = "Min_full_rtt_initiator", .schema = &fieldrttschema },
        { .required = 0, .name = "Min_full_rtt_responder", .schema = &fieldrttschema },
        { .required = 0, .name = "Value", .schema = &fieldvalueschema },
        { .required = 0, .name = "Transition", .schema = &fieldtransitionschema },
        { .required = 0, .name = "Who", .schema = &fieldwhoschema },
        { .required = 1, .name = "Packets1", .schema = &fieldpackets1schema },
        { .required = 1, .name = "Packets2", .schema = &fieldpackets2schema },
        { .required = 1, .name = "Bytes1", .schema = &fieldbytes1schema },
        { .required = 1, .name = "Bytes2", .schema = &fieldbytes2schema },
        { .required = 0, .name = "Bandwidth1", .schema = &fieldbandwidth1schema },
        { .required = 0, .name = "Bandwidth2", .schema = &fieldbandwidth2schema },
        { .required = 0, .name = "Ecn0", .schema = &fieldecn0schema },
        { .required = 0, .name = "Ecn1", .schema = &fieldecn1schema },
        { .required = 0, .name = "Ce", .schema = &fieldceschema },
        { .required = 0, .name = "Avg_loss", .schema = &fieldlossschema },
        { .required = 0, .name = "Tot_loss", .schema = &fieldlossschema },
        { .required = 0, .name = "Q_loss", .schema = &fieldlossschema },
        { .required = 0, .name = "L_loss", .schema = &fieldlossschema },
        { .required = 0, .name = "Length", .schema = &fieldlengthschema },
        { .required = 0, .name = "Dir", .schema = &fielddirschema },
        { .required = 0, .name = "Tags", .schema = &fieldtagsschema },
        { .required = 0, .name = "Notes", .schema = &fieldnotesschema }
      }
    }
  }
};

static struct spindump_json_schema arrayschema = {
  .type = spindump_json_schema_type_array,
  .callback = 0,
  .u = {
    .array = {
      .schema = &recordschema
    }
  }
};

static struct spindump_json_schema schema = {
  .type = spindump_json_schema_type_recordorarray,
  .callback = 0,
  .u = {
    .arrayorrecord = {
      .array = &arrayschema,
      .record = &recordschema
    }
  }
};

//
// Actual code --------------------------------------------------------------------------------
//

//
// Return the schema for the JSON that we should be using for Spindump logs.
//

const struct spindump_json_schema*
spindump_event_parser_json_getschema() {
  return(&schema);
}

//
// Parse text as JSON and call a callback for every Spindump event
// found from it.
//
// The input text point moves further as the input is read. Only a
// single JSON object is read at one time. That object may of course
// be a composite object, such as an array.
//
// If successful, return 1, otherwise 0.
//

int
spindump_event_parser_json_textparse(const char** jsonText,
                                     spindump_event_parser_json_callback callback,
                                     void* data) {
  struct spindump_event_parser_json_parsingcontext context;
  context.callback = callback;
  context.data = data;
  context.success = 1;
  struct spindump_json_schema usedSchema = *spindump_event_parser_json_getschema();
  usedSchema.callback = spindump_event_parser_json_textparse_callback;
  int ans =
    spindump_json_parse(&usedSchema,
                        &context,
                        jsonText);
  if (ans == 0) context.success = 0;
  return(context.success);
}

//
// Helper function to be called upon every JSON object being
// parsed. Called by spindump_event_parser_json_textparse and
// spindump_json_parse.
//

static void
spindump_event_parser_json_textparse_callback(const struct spindump_json_value* value,
                                              const struct spindump_json_schema* type,
                                              void* data) {
  spindump_assert(value != 0);
  spindump_assert(type != 0);
  spindump_assert(data != 0);
  struct spindump_event_parser_json_parsingcontext* context = (struct spindump_event_parser_json_parsingcontext*)data;
  struct spindump_event event;

  spindump_deepdeepdebugf("spindump_event_parser_json_textparse_callback");
  switch (value->type) {
  case spindump_json_value_type_integer:
  case spindump_json_value_type_string:
    spindump_deepdeepdebugf("spindump_event_parser_json_textparse_callback case literal");
    break;
  case spindump_json_value_type_record:
    spindump_deepdeepdebugf("spindump_event_parser_json_textparse_callback case record");
    if (spindump_event_parser_json_parse(value,&event)) {
      (*(context->callback))(&event,context->data);
    } else {
      context->success = 0;
    }
    break;
  case spindump_json_value_type_array:
    spindump_deepdeepdebugf("spindump_event_parser_json_textparse_callback case array n = %u",
                            value->u.array.n);
    for (unsigned int i = 0; i < value->u.array.n; i++) {
      const struct spindump_json_value* element = value->u.array.elements[i];
      if (spindump_event_parser_json_parse(element,&event)) {
        (*(context->callback))(&event,context->data);
      } else {
        context->success = 0;
      }
    }
    break;
  default:
    break;
  }
}

//
// Take a JSON object and parse it as a JSON-formatted event
// description from Spindump, placing the result in the output
// parameter "event".
//
// If successful, return 1, otherwise 0.
//

int
spindump_event_parser_json_parse(const struct spindump_json_value* json,
                                 struct spindump_event* event) {

  //
  // Sanity checks
  //

  spindump_assert(json != 0);
  spindump_assert(json->type == spindump_json_value_type_record);
  spindump_assert(event != 0);

  //
  // Get the mandatory fields
  //

  const char* eventType = spindump_json_value_getstring(spindump_json_value_getrequiredfield("Event",json));
  spindump_deepdeepdebugf("spindump_event_parser_json_parse %s", eventType);
  if (!spindump_event_parser_json_converteventtype(eventType,&event->eventType)) {
    spindump_errorf("Invalid event type %s", eventType);
    return(0);
  }
  const char* connectionType = spindump_json_value_getstring(spindump_json_value_getrequiredfield("Type",json));
  if (!spindump_connection_string_to_connectiontype(connectionType,&event->connectionType)) {
    spindump_errorf("Invalid connection type %s", connectionType);
    return(0);
  }
  const char* state = spindump_json_value_getstring(spindump_json_value_getrequiredfield("State",json));
  if (!spindump_connection_statestring_to_state(state,&event->state)) {
    spindump_errorf("Invalid state %s", state);
    return(0);
  }
  const struct spindump_json_value* addrs = spindump_json_value_getrequiredfield("Addrs",json);
  const struct spindump_json_value* addr1elem = spindump_json_value_getarrayelem(0,addrs);
  const struct spindump_json_value* addr2elem = spindump_json_value_getarrayelem(1,addrs);
  if (addr1elem == 0 || addr2elem == 0) {
    spindump_errorf("Missing addresses in an event");
    return(0);
  }
  const char* addr1 = spindump_json_value_getstring(addr1elem);
  if (!spindump_network_fromstringoraddr(&event->initiatorAddress,addr1)) {
    spindump_errorf("Cannot parse initiator address");
    return(0);
  }
  const char* addr2 = spindump_json_value_getstring(addr2elem);
  if (!spindump_network_fromstringoraddr(&event->responderAddress,addr2)) {
    spindump_errorf("Cannot parse responder address");
    return(0);
  }
  const char* session = spindump_json_value_getstring(spindump_json_value_getrequiredfield("Session",json));
  if (strlen(session) + 1 > sizeof(event->session)) {
    spindump_errorf("Session field is too long for the event");
    return(0);
  }
  strncpy(&event->session[0],session,sizeof(event->session));
  unsigned long long ts = spindump_json_value_getinteger(spindump_json_value_getrequiredfield("Ts",json));
  event->timestamp = ts;
  spindump_deepdeepdebugf("spindump_event_parser_json reading timestamp %llu from JSON", event->timestamp);
  unsigned long long packets1 = spindump_json_value_getinteger(spindump_json_value_getrequiredfield("Packets1",json));
  event->packetsFromSide1 = (unsigned int)packets1;
  unsigned long long packets2 = spindump_json_value_getinteger(spindump_json_value_getrequiredfield("Packets2",json));
  event->packetsFromSide2 = (unsigned int)packets2;
  unsigned long long bytes1 = spindump_json_value_getinteger(spindump_json_value_getrequiredfield("Bytes1",json));
  event->bytesFromSide1 = (unsigned int)bytes1;
  unsigned long long bytes2 = spindump_json_value_getinteger(spindump_json_value_getrequiredfield("Bytes2",json));
  event->bytesFromSide2 = (unsigned int)bytes2;
  const struct spindump_json_value* bandwidth1Elem = spindump_json_value_getfield("Bandwidth1",json);
  if (bandwidth1Elem != 0) {
    unsigned long long bandwidth1 = spindump_json_value_getinteger(bandwidth1Elem);
    event->bandwidthFromSide1 = (unsigned int)bandwidth1;
  } else {
    event->bandwidthFromSide1 = 0;
  }
  const struct spindump_json_value* bandwidth2Elem = spindump_json_value_getfield("Bandwidth2",json);
  if (bandwidth2Elem != 0) {
    unsigned long long bandwidth2 = spindump_json_value_getinteger(bandwidth2Elem);
    event->bandwidthFromSide2 = (unsigned int)bandwidth2;
  } else {
    event->bandwidthFromSide2 = 0;
  }

  //
  // Get the optional fields
  //
  
  const struct spindump_json_value* tags = spindump_json_value_getfield("Tags",json);
  spindump_tags_initialize(&event->tags);
  if (tags != 0) {
    const char* tagsString = spindump_json_value_getstring(tags);
    spindump_tags_addtag(&event->tags,tagsString);
  }
  
  const struct spindump_json_value* notes = spindump_json_value_getfield("Notes",json);
  if (notes != 0) {
    const char* notesString = spindump_json_value_getstring(notes);
    strncpy(event->notes,notesString,sizeof(event->notes)-1);
  }
  
  //
  // Get the rest of the fields based on the type of event
  //

  switch (event->eventType) {
    
  case spindump_event_type_new_connection:
    if (!spindump_event_parser_json_parse_aux_new_connection(json,event)) {
      return(0);
    }
    break;
    
  case spindump_event_type_change_connection:
    if (!spindump_event_parser_json_parse_aux_change_connection(json,event)) {
      return(0);
    }
    break;
    
  case spindump_event_type_connection_delete:
    if (!spindump_event_parser_json_parse_aux_connection_delete(json,event)) {
      return(0);
    }
    break;
    
  case spindump_event_type_new_rtt_measurement:
    if (!spindump_event_parser_json_parse_aux_new_rtt_measurement(json,event)) {
      return(0);
    }
    break;
    
  case spindump_event_type_periodic:
    if (!spindump_event_parser_json_parse_aux_periodic(json,event)) {
      return(0);
    }
    break;
    
  case spindump_event_type_spin_flip:
    if (!spindump_event_parser_json_parse_aux_spin_flip(json,event)) {
      return(0);
    }
    break;
    
  case spindump_event_type_spin_value:
    if (!spindump_event_parser_json_parse_aux_spin_value(json,event)) {
      return(0);
    }
    break;
    
  case spindump_event_type_ecn_congestion_event:
    if (!spindump_event_parser_json_parse_aux_ecn_congestion_event(json,event)) {
      return(0);
    }
    break;

  case spindump_event_type_rtloss_measurement:
    if (!spindump_event_parser_json_parse_aux_rtloss_measurement(json, event)) {
      return(0);
    }
    break;

  case spindump_event_type_qrloss_measurement:
    if (!spindump_event_parser_json_parse_aux_qrloss_measurement(json, event)) {
      return(0);
    }
    break;

  case spindump_event_type_qlloss_measurement:
    if (!spindump_event_parser_json_parse_aux_qlloss_measurement(json, event)) {
      return(0);
    }
    break;
    
  case spindump_event_type_packet:
    if (!spindump_event_parser_json_parse_aux_packet(json,event)) {
      return(0);
    }
    break;
    
  default:
    spindump_errorf("Invalid event type %u", event->eventType);
    return(0);
  }
  
  return(1);
}

//
// Copy fields from JSON event to the event struct, for events of the
// type "". Return value is 0 upon error, 1 upon success.
//

static int
spindump_event_parser_json_parse_aux_new_connection(const struct spindump_json_value* json,
                                                    struct spindump_event* event) {
  //
  // This always succeeds
  //
  
  return(1);
}

//
// Copy fields from JSON event to the event struct, for events of the
// type "Change Connection". Return value is 0 upon error, 1 upon success.
//

static int
spindump_event_parser_json_parse_aux_change_connection(const struct spindump_json_value* json,
                                                       struct spindump_event* event) {
  //
  // This always succeeds
  //
  
  return(1);
}

//
// Copy fields from JSON event to the event struct, for events of the
// type "Connection Delete". Return value is 0 upon error, 1 upon
// success.
//

static int
spindump_event_parser_json_parse_aux_connection_delete(const struct spindump_json_value* json,
                                                       struct spindump_event* event) {
  //
  // This always succeeds
  //
  
  return(1);
}

//
// Copy fields from JSON event to the event struct, for events of the
// type "". Return value is 0 upon error, 1 upon success.
//

static int
spindump_event_parser_json_parse_aux_new_rtt_measurement(const struct spindump_json_value* json,
                                                         struct spindump_event* event) {
  const struct spindump_json_value* field = 0;
  const struct spindump_json_value* avgfield = 0;
  const struct spindump_json_value* devfield = 0;
  const struct spindump_json_value* minfield = 0;
  const struct spindump_json_value* filtavgfield = 0;
  if ((field = spindump_json_value_getfield("Left_rtt",json)) != 0) {
    event->u.newRttMeasurement.measurement = spindump_measurement_type_bidirectional;
    event->u.newRttMeasurement.direction = spindump_direction_frominitiator;
    avgfield = spindump_json_value_getfield("Avg_left_rtt",json);
    devfield = spindump_json_value_getfield("Dev_left_rtt",json);
    minfield = spindump_json_value_getfield("Min_left_rtt",json);
    filtavgfield = spindump_json_value_getfield("Filt_avg_left_rtt",json);
  } else if ((field = spindump_json_value_getfield("Right_rtt",json)) != 0) {
    event->u.newRttMeasurement.measurement = spindump_measurement_type_bidirectional;
    event->u.newRttMeasurement.direction = spindump_direction_fromresponder;
    avgfield = spindump_json_value_getfield("Avg_right_rtt",json);
    devfield = spindump_json_value_getfield("Dev_right_rtt",json);
    minfield = spindump_json_value_getfield("Min_right_rtt",json);
    filtavgfield = spindump_json_value_getfield("Filt_avg_right_rtt",json);
  } else if ((field = spindump_json_value_getfield("Full_rtt_initiator",json)) != 0) {
    event->u.newRttMeasurement.measurement = spindump_measurement_type_unidirectional;
    event->u.newRttMeasurement.direction = spindump_direction_frominitiator;
    avgfield = spindump_json_value_getfield("Avg_full_rtt_initiator",json);
    devfield = spindump_json_value_getfield("Dev_full_rtt_initiator",json);
    minfield = spindump_json_value_getfield("Min_full_rtt_initiator",json);
    filtavgfield = spindump_json_value_getfield("Filt_avg_full_rtt_initiator",json);
  } else if ((field = spindump_json_value_getfield("Full_rtt_responder",json)) != 0) {
    event->u.newRttMeasurement.measurement = spindump_measurement_type_unidirectional;
    event->u.newRttMeasurement.direction = spindump_direction_fromresponder;
    avgfield = spindump_json_value_getfield("Avg_full_rtt_responder",json);
    devfield = spindump_json_value_getfield("Dev_full_rtt_responder",json);
    minfield = spindump_json_value_getfield("Min_full_rtt_responder",json);
    filtavgfield = spindump_json_value_getfield("Filt_avg_full_rtt_responder",json);
  } else {
    spindump_errorf("new RTT measurement event does not have the necessary JSON fields");
    return(0);
  }
  unsigned long long value = spindump_json_value_getinteger(field);
  unsigned long long avgValue;
  unsigned long long devValue;
  unsigned long long minValue;
  unsigned long long filtAvgValue;
  event->u.newRttMeasurement.rtt = (unsigned long)value;
  if (avgfield != 0 &&
      (avgValue = spindump_json_value_getinteger(avgfield)) > 0) {
    event->u.newRttMeasurement.avgRtt = (unsigned long)avgValue;
  }
  if (devfield != 0 &&
      (devValue = spindump_json_value_getinteger(devfield)) > 0) {
    event->u.newRttMeasurement.devRtt = (unsigned long)devValue;
  }
  if (minfield != 0 &&
      (minValue = spindump_json_value_getinteger(minfield)) > 0) {
    event->u.newRttMeasurement.minRtt = (unsigned long)minValue;
  }
  if (filtavgfield != 0 &&
      (filtAvgValue = spindump_json_value_getinteger(filtavgfield)) > 0) {
    event->u.newRttMeasurement.filtAvgRtt = (unsigned long)filtAvgValue;
  }
  return(1);
}

//
// Copy fields from JSON event to the event struct, for events of the
// type "". Return value is 0 upon error, 1 upon success.
//

static int
spindump_event_parser_json_parse_aux_periodic(const struct spindump_json_value* json,
                                              struct spindump_event* event) {
  const struct spindump_json_value* field = 0;
  const struct spindump_json_value* avgfield = 0;
  const struct spindump_json_value* devfield = 0;
  if ((field = spindump_json_value_getfield("Right_rtt",json)) != 0) {
    avgfield = spindump_json_value_getfield("Avg_right_rtt",json);
    devfield = spindump_json_value_getfield("Dev_right_rtt",json);
  } else {
    event->u.periodic.rttRight = spindump_rtt_infinite;
    event->u.periodic.avgRttRight = spindump_rtt_infinite;
    event->u.periodic.devRttRight = spindump_rtt_infinite;
    return(1);
  }
  unsigned long long value = spindump_json_value_getinteger(field);
  unsigned long long avgValue;
  unsigned long long devValue;
  event->u.periodic.rttRight = (unsigned long)value;
  if (avgfield != 0 &&
      (avgValue = spindump_json_value_getinteger(avgfield)) > 0) {
    event->u.periodic.avgRttRight = (unsigned long)avgValue;
  }
  if (devfield != 0 &&
      (devValue = spindump_json_value_getinteger(devfield)) > 0) {
    event->u.periodic.devRttRight = (unsigned long)devValue;
  }
  return(1);
}

//
// Copy fields from JSON event to the event struct, for events of the
// type "Spin Flip". Return value is 0 upon error, 1 upon success.
//

static int
spindump_event_parser_json_parse_aux_spin_flip(const struct spindump_json_value* json,
                                               struct spindump_event* event) {
  const struct spindump_json_value* transitionField = spindump_json_value_getfield("Transition",json);
  const struct spindump_json_value* whoField = spindump_json_value_getfield("Who",json);
  if (transitionField == 0 || whoField == 0) {
    spindump_errorf("spin flip event does not have the necessary JSON fields");
    return(0);
  }
  const char* transitionValue = spindump_json_value_getstring(transitionField);
  const char* whoValue = spindump_json_value_getstring(whoField);
  if (strcmp(transitionValue,"0-1") == 0) {
    event->u.spinFlip.spin0to1 = 1;
  } else if (strcmp(transitionValue,"1-0") == 0) {
    event->u.spinFlip.spin0to1 = 0;
  } else {
    spindump_errorf("spin flip transition value does not have the right value in JSON: %s", transitionValue);
    return(0);
  }
  if (strcasecmp(whoValue,"initiator") == 0) {
    event->u.spinFlip.direction = spindump_direction_frominitiator;
  } else if (strcasecmp(whoValue,"responder") == 0) {
    event->u.spinFlip.direction = spindump_direction_fromresponder;
  } else {
    spindump_errorf("spin flip direction does not have the right value in JSON: %s", whoValue);
    return(0);
  }
  return(1);
}

//
// Copy fields from JSON event to the event struct, for events of the
// type "Spin Value". Return value is 0 upon error, 1 upon success.
//

static int
spindump_event_parser_json_parse_aux_spin_value(const struct spindump_json_value* json,
                                                struct spindump_event* event) {
  const struct spindump_json_value* valueField = spindump_json_value_getfield("Value",json);
  const struct spindump_json_value* whoField = spindump_json_value_getfield("Who",json);
  if (valueField == 0 || whoField == 0) {
    spindump_errorf("spin value event does not have the necessary JSON fields");
    return(0);
  }
  unsigned long long valueValue = spindump_json_value_getinteger(valueField);
  const char* whoValue = spindump_json_value_getstring(whoField);
  if (valueValue == 0) {
    event->u.spinValue.value = 0;
  } else if (valueValue == 1) {
    event->u.spinValue.value = 1;
  } else {
    spindump_errorf("spin value bit value does not have the right value in JSON: %llu", valueValue);
    return(0);
  }
  if (strcasecmp(whoValue,"initiator") == 0) {
    event->u.spinValue.direction = spindump_direction_frominitiator;
  } else if (strcasecmp(whoValue,"responder") == 0) {
    event->u.spinValue.direction = spindump_direction_fromresponder;
  } else {
    spindump_errorf("spin value direction does not have the right value in JSON: %s", whoValue);
    return(0);
  }
  return(1);
}

//
// Copy fields from JSON event to the event struct, for events of the
// type "ECN Congestion Event". Return value is 0 upon error, 1 upon success.
//

static int
spindump_event_parser_json_parse_aux_ecn_congestion_event(const struct spindump_json_value* json,
                                                          struct spindump_event* event) {
  const struct spindump_json_value* whoField = spindump_json_value_getfield("Who",json);
  const struct spindump_json_value* ecn0Field = spindump_json_value_getfield("Ecn0",json);
  const struct spindump_json_value* ecn1Field = spindump_json_value_getfield("Ecn1",json);
  const struct spindump_json_value* ceField = spindump_json_value_getfield("Ce",json);
  if (whoField == 0 || ecn0Field == 0 || ecn1Field == 0 || ceField == 0) {
    spindump_errorf("congestion notification event does not have the necessary JSON fields");
    return(0);
  }
  const char* whoValue = spindump_json_value_getstring(whoField);
  unsigned long long ecn0Value = spindump_json_value_getinteger(ecn0Field);
  unsigned long long ecn1Value = spindump_json_value_getinteger(ecn1Field);
  unsigned long long ceValue = spindump_json_value_getinteger(ceField);
  event->u.ecnCongestionEvent.ecn0 = (unsigned int)ecn0Value;
  event->u.ecnCongestionEvent.ecn1 = (unsigned int)ecn1Value;
  event->u.ecnCongestionEvent.ce = (unsigned int)ceValue;
  if (strcasecmp(whoValue,"initiator") == 0) {
    event->u.ecnCongestionEvent.direction = spindump_direction_frominitiator;
  } else if (strcasecmp(whoValue,"responder") == 0) {
    event->u.ecnCongestionEvent.direction = spindump_direction_fromresponder;
  } else {
    spindump_errorf("congestion notification event direction does not have the right value in JSON: %s", whoValue);
    return(0);
  }
  return(1);
}

static int
spindump_event_parser_json_parse_aux_rtloss_measurement(const struct spindump_json_value* json,
                                                        struct spindump_event* event) {
  const struct spindump_json_value* whoField = spindump_json_value_getfield("Who",json);
  const struct spindump_json_value* avgField = spindump_json_value_getfield("Avg_loss",json);
  const struct spindump_json_value* totField = spindump_json_value_getfield("Tot_loss",json);
  
  if (whoField == 0 || avgField == 0 || totField == 0) {
    spindump_errorf("rtloss event does not have the necessary JSON fields");
    return(0);
  }

  const char* avgValue = spindump_json_value_getstring(avgField);
  const char* totValue = spindump_json_value_getstring(totField);
  const char* whoValue = spindump_json_value_getstring(whoField);

  // Implement validity check
  memset(event->u.rtlossMeasurement.avgLoss, '\0', sizeof(event->u.rtlossMeasurement.avgLoss));
  strcpy(event->u.rtlossMeasurement.avgLoss, avgValue);

  memset(event->u.rtlossMeasurement.totLoss, '\0', sizeof(event->u.rtlossMeasurement.totLoss));
  strcpy(event->u.rtlossMeasurement.totLoss, totValue);

  if (strcasecmp(whoValue,"initiator") == 0) {
    event->u.rtlossMeasurement.direction = spindump_direction_frominitiator;
  } else if (strcasecmp(whoValue,"responder") == 0) {
    event->u.rtlossMeasurement.direction = spindump_direction_fromresponder;
  } else {
    spindump_errorf("rtloss value direction does not have the right value in JSON: %s", whoValue);
    return(0);
  }
  return(1);
}

static int
spindump_event_parser_json_parse_aux_qrloss_measurement(const struct spindump_json_value* json,
                                                        struct spindump_event* event) {
  const struct spindump_json_value* whoField = spindump_json_value_getfield("Who",json);
  const struct spindump_json_value* avgField = spindump_json_value_getfield("Avg_loss",json); // Note that fieldlossschema type in spindump_remote_server is string
  const struct spindump_json_value* totField = spindump_json_value_getfield("Tot_loss",json);

  if (whoField == 0 || avgField == 0 || totField == 0) {
    spindump_errorf("qrloss event does not have the necessary JSON fields");
    return(0);
  }

  const char* avgValue = spindump_json_value_getstring(avgField);
  const char* totValue = spindump_json_value_getstring(totField);
  const char* whoValue = spindump_json_value_getstring(whoField);

  // Implement validity check
  memset(event->u.qrlossMeasurement.avgLoss, '\0', sizeof(event->u.qrlossMeasurement.avgLoss));
  strncpy(event->u.qrlossMeasurement.avgLoss, avgValue, sizeof(event->u.qrlossMeasurement.avgLoss)-1);

  memset(event->u.qrlossMeasurement.totLoss, '\0', sizeof(event->u.qrlossMeasurement.totLoss));
  strncpy(event->u.qrlossMeasurement.totLoss, totValue, sizeof(event->u.qrlossMeasurement.totLoss)-1);

  if (strcasecmp(whoValue,"initiator") == 0) {
    event->u.qrlossMeasurement.direction = spindump_direction_frominitiator;
  } else if (strcasecmp(whoValue,"responder") == 0) {
    event->u.qrlossMeasurement.direction = spindump_direction_fromresponder;
  } else {
    spindump_errorf("qrloss value direction does not have the right value in JSON: %s", whoValue);
    return(0);
  }
  return(1);
}

static int
spindump_event_parser_json_parse_aux_qlloss_measurement(const struct spindump_json_value* json,
                                                        struct spindump_event* event) {
  const struct spindump_json_value* whoField = spindump_json_value_getfield("Who",json);
  const struct spindump_json_value* qField = spindump_json_value_getfield("Q_loss",json); // Note that fieldlossschema type in spindump_remote_server is string
  const struct spindump_json_value* lField = spindump_json_value_getfield("L_loss", json);
  
  if (whoField == 0 || qField == 0 || lField == 0) {
    spindump_errorf("qlloss event does not have the necessary JSON fields");
    return(0);
  }

  const char* whoValue = spindump_json_value_getstring(whoField);
  const char* qValue = spindump_json_value_getstring(qField);
  const char* lValue = spindump_json_value_getstring(lField);

  // Implement validity check
  memset(event->u.qllossMeasurement.qLoss, '\0', sizeof(event->u.qllossMeasurement.qLoss));
  strncpy(event->u.qllossMeasurement.qLoss, qValue, sizeof(event->u.qllossMeasurement.qLoss)-1);

  memset(event->u.qllossMeasurement.lLoss, '\0', sizeof(event->u.qllossMeasurement.lLoss));
  strncpy(event->u.qllossMeasurement.lLoss, lValue, sizeof(event->u.qllossMeasurement.lLoss)-1);

  if (strcasecmp(whoValue,"initiator") == 0) {
    event->u.qllossMeasurement.direction = spindump_direction_frominitiator;
  } else if (strcasecmp(whoValue,"responder") == 0) {
    event->u.qllossMeasurement.direction = spindump_direction_fromresponder;
  } else {
    spindump_errorf("qlloss value direction does not have the right value in JSON: %s", whoValue);
    return(0);
  }
  return(1);
}

//
// Parse the record about a new packet. It has no extra information.
//

static int
spindump_event_parser_json_parse_aux_packet(const struct spindump_json_value* json,
                                            struct spindump_event* event) {
  const struct spindump_json_value* dirField = spindump_json_value_getfield("Dir",json);
  const struct spindump_json_value* lengthField = spindump_json_value_getfield("Length",json);
  
  if (dirField == 0 || lengthField == 0) {
    spindump_errorf("packet event does not have the necessary JSON fields");
    return(0);
  }

  const char* dirValue = spindump_json_value_getstring(dirField);
  unsigned long long lengthValue = spindump_json_value_getinteger(lengthField);

  if (strcasecmp(dirValue,"initiator") == 0) {
    event->u.packet.direction = spindump_direction_frominitiator;
  } else if (strcasecmp(dirValue,"responder") == 0) {
    event->u.packet.direction = spindump_direction_fromresponder;
  } else {
    spindump_errorf("Dir value direction does not have the right value in JSON: %s", dirValue);
    return(0);
  }
  event->u.packet.length = (unsigned long)lengthValue;
  return(1);
}

//
// The next helper function maps a string to an event type.
//
// The mapping in this function needs to match what's given in the
// function spindump_event_type_tostring in spindump_event.c.
//

static int
spindump_event_parser_json_converteventtype(const char* string,
                                            enum spindump_event_type* type) {
  spindump_assert(string != 0);
  spindump_assert(type != 0);
  if (strcasecmp("new",string) == 0) {
    *type = spindump_event_type_new_connection;
    return(1);
  } else if (strcasecmp("change",string) == 0) {
    *type = spindump_event_type_change_connection;
    return(1);
  } else if (strcasecmp("delete",string) == 0) {
    *type = spindump_event_type_connection_delete;
    return(1);
  } else if (strcasecmp("spinflip",string) == 0) {
    *type = spindump_event_type_spin_flip;
    return(1);
  } else if (strcasecmp("spin",string) == 0) {
    *type = spindump_event_type_spin_value;
    return(1);
  } else if (strcasecmp("measurement" ,string) == 0) {
    *type = spindump_event_type_new_rtt_measurement;
    return(1);
  } else if (strcasecmp("periodic" ,string) == 0) {
    *type = spindump_event_type_periodic;
    return(1);
  } else if (strcasecmp("ecnce",string) == 0) {
    *type = spindump_event_type_ecn_congestion_event;
    return(1);
  } else if (strcasecmp("rtloss",string) == 0) {
    *type = spindump_event_type_rtloss_measurement;
    return(1);
  } else if (strcasecmp("qrloss",string) == 0) {
    *type = spindump_event_type_qrloss_measurement;
    return(1);
  } else if (strcasecmp("qlloss",string) == 0) {
    *type = spindump_event_type_qlloss_measurement;
    return(1);
  } else if (strcasecmp("packet",string) == 0) {
    *type = spindump_event_type_packet;
    return(1);
  } else {
    return(0);
  }
}
