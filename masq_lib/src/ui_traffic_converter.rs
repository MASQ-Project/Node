// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::ui_gateway::MessagePath::{Conversation, FireAndForget};
use crate::ui_gateway::{MessageBody, MessageTarget, NodeFromUiMessage, NodeToUiMessage};
use crate::ui_traffic_converter::TrafficConversionError::{
    FieldTypeError, JsonSyntaxError, MissingFieldError, NotJsonObjectError,
};
use crate::ui_traffic_converter::UnmarshalError::{Critical, NonCritical};
use serde_json::Value;
use std::fmt::Display;

#[derive(Debug, PartialEq, Clone)]
pub enum TrafficConversionError {
    JsonSyntaxError(String),                // couldn't parse as JSON
    NotJsonObjectError(String),             // root level wasn't a JSON object
    MissingFieldError(String), // noncritical field missing; can send error message under same opcode
    FieldTypeError(String, String, String), // noncritical field was mistyped; can send error message under same opcode
}

impl Display for TrafficConversionError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match self {
            JsonSyntaxError(s) => write!(f, "Couldn't parse text as JSON: {}", s),
            NotJsonObjectError(s) => {
                write!(f, "Root was not a JSON object:\n------\n{}\n------\n", s)
            }
            MissingFieldError(field) => write!(f, "Required field was missing: {}", field),
            FieldTypeError(field, wanted, got) => write!(
                f,
                "Field {} should have been of type {}, but was '{}' instead",
                field, wanted, got
            ),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum UnmarshalError {
    Critical(TrafficConversionError),
    NonCritical(String, Option<u64>, TrafficConversionError),
}

impl Display for UnmarshalError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match self {
            Critical(e) => write!(
                f,
                "Critical error unmarshalling unidentified message: {}",
                e
            ),
            NonCritical(opcode, _, e) => {
                write!(f, "Error unmarshalling '{}' message: {}", opcode, e)
            }
        }
    }
}

pub struct UiTrafficConverter {}

impl Default for UiTrafficConverter {
    fn default() -> Self {
        Self {}
    }
}

impl UiTrafficConverter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_marshal_from_ui(msg: NodeFromUiMessage) -> String {
        Self::new_marshal(msg.body)
    }

    pub fn new_marshal_to_ui(msg: NodeToUiMessage) -> String {
        Self::new_marshal(msg.body)
    }

    pub fn new_unmarshal_from_ui(
        json: &str,
        client_id: u64,
    ) -> Result<NodeFromUiMessage, UnmarshalError> {
        match Self::new_unmarshal(json) {
            Ok(body) => Ok(NodeFromUiMessage { client_id, body }),
            Err(e) => Err(e),
        }
    }

    pub fn new_unmarshal_to_ui(
        json: &str,
        target: MessageTarget,
    ) -> Result<NodeToUiMessage, UnmarshalError> {
        match Self::new_unmarshal(json) {
            Ok(body) => Ok(NodeToUiMessage { target, body }),
            Err(e) => Err(e),
        }
    }

    fn new_marshal(body: MessageBody) -> String {
        let opcode_section = format!("\"opcode\": \"{}\", ", body.opcode);
        let path_section = match body.path {
            FireAndForget => "".to_string(),
            Conversation(context_id) => format!("\"contextId\": {}, ", context_id),
        };
        let payload_section = match body.payload {
            Ok(json) => format!("\"payload\": {}", json),
            Err((error_code, error_msg)) => format!(
                "\"error\": {{\"code\": {}, \"message\": \"{}\"}}",
                error_code, error_msg
            ),
        };
        format!("{{{}{}{}}}", opcode_section, path_section, payload_section)
    }

    fn new_unmarshal(json: &str) -> Result<MessageBody, UnmarshalError> {
        match serde_json::from_str(json) {
            Ok(Value::Object(map)) => {
                let opcode = match Self::get_string(&map, "opcode") {
                    Ok(s) => s,
                    Err(MissingFieldError(s)) => return Err(Critical(MissingFieldError(s))),
                    Err(FieldTypeError(a, b, c)) => return Err(Critical(FieldTypeError(a, b, c))),
                    Err(e) => return Err(Critical(e)),
                };
                let (context_id_opt, path) = match Self::get_u64(&map, "contextId") {
                    Ok(context_id) => (Some(context_id), Conversation(context_id)),
                    Err(MissingFieldError(_)) => (None, FireAndForget),
                    Err(FieldTypeError(a, b, c)) => return Err(Critical(FieldTypeError(a, b, c))),
                    Err(e) => return Err(Critical(e)),
                };
                match map.get("payload") {
                    Some(Value::Object(payload_map)) => {
                        let payload =
                            serde_json::to_string(payload_map).expect("Reserialization problem");
                        Ok(MessageBody {
                            opcode,
                            path,
                            payload: Ok(payload),
                        })
                    }
                    Some(other_value) => Err(NonCritical(
                        opcode,
                        context_id_opt,
                        FieldTypeError(
                            "payload".to_string(),
                            "object".to_string(),
                            format!("{:?}", other_value),
                        ),
                    )),
                    None => match map.get("error") {
                        Some(Value::Object(error_map)) => {
                            let code = match Self::get_u64(&error_map, "code") {
                                Ok(code) => code,
                                Err(e) => return Err(NonCritical(opcode, context_id_opt, e)),
                            };
                            let message = match Self::get_string(&error_map, "message") {
                                Ok(message) => message,
                                Err(e) => return Err(NonCritical(opcode, context_id_opt, e)),
                            };
                            Ok(MessageBody {
                                opcode,
                                path,
                                payload: Err((code, message)),
                            })
                        }
                        Some(other_value) => Err(NonCritical(
                            opcode,
                            context_id_opt,
                            FieldTypeError(
                                "error".to_string(),
                                "object".to_string(),
                                other_value.to_string(),
                            ),
                        )),
                        None => Err(NonCritical(
                            opcode,
                            context_id_opt,
                            MissingFieldError("payload, error".to_string()),
                        )),
                    },
                }
            }
            Ok(e) => Err(Critical(NotJsonObjectError(e.to_string()))),
            Err(e) => Err(Critical(JsonSyntaxError(format!("{:?}", e)))),
        }
    }

    fn get_string(
        map: &serde_json::map::Map<String, Value>,
        name: &str,
    ) -> Result<String, TrafficConversionError> {
        match map.get(name) {
            Some(Value::String(s)) => Ok(s.clone()),
            Some(x) => Err(FieldTypeError(
                name.to_string(),
                "string".to_string(),
                x.to_string(),
            )),
            None => Err(MissingFieldError(name.to_string())),
        }
    }

    fn get_u64(
        map: &serde_json::map::Map<String, Value>,
        name: &str,
    ) -> Result<u64, TrafficConversionError> {
        match map.get(name) {
            Some(Value::Number(n)) => match n.as_u64() {
                Some(n) => Ok(n),
                None => Err(FieldTypeError(
                    name.to_string(),
                    "u64".to_string(),
                    n.to_string(),
                )),
            },
            Some(x) => Err(FieldTypeError(
                name.to_string(),
                "u64".to_string(),
                x.to_string(),
            )),
            None => Err(MissingFieldError(name.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui_traffic_converter::TrafficConversionError::{
        FieldTypeError, JsonSyntaxError, MissingFieldError, NotJsonObjectError,
    };
    use serde_json::Number;

    #[test]
    fn new_marshaling_and_unmarshaling_works_from_ui_one_way_for_success() {
        let ui_msg = NodeFromUiMessage {
            client_id: 4321,
            body: MessageBody {
                opcode: "opcode".to_string(),
                path: FireAndForget,
                payload: Ok(
                    r#"{"null": null, "bool": true, "number": 1.23, "string": "Booga"}"#
                        .to_string(),
                ),
            },
        };

        let json = UiTrafficConverter::new_marshal_from_ui(ui_msg);

        let ui_msg = UiTrafficConverter::new_unmarshal_from_ui(&json, 1234).unwrap();
        assert_eq!(ui_msg.client_id, 1234);
        assert_eq!(ui_msg.body.opcode, "opcode".to_string());
        assert_eq!(ui_msg.body.path, FireAndForget);
        match serde_json::from_str::<Value>(&ui_msg.body.payload.unwrap()) {
            Ok(Value::Object(map)) => {
                assert_eq!(map.get("null"), Some(&Value::Null));
                assert_eq!(map.get("bool"), Some(&Value::Bool(true)));
                assert_eq!(
                    map.get("number"),
                    Some(&Value::Number(Number::from_f64(1.23).unwrap()))
                );
                assert_eq!(map.get("string"), Some(&Value::String("Booga".to_string())));
            }
            v => panic!("Needed Some(Value::Map); got {:?}", v),
        }
    }

    #[test]
    fn new_marshaling_and_unmarshaling_works_to_ui_one_way_for_success() {
        let ui_msg = NodeToUiMessage {
            target: MessageTarget::ClientId(4321),
            body: MessageBody {
                opcode: "opcode".to_string(),
                path: FireAndForget,
                payload: Ok(
                    r#"{"null": null, "bool": true, "number": 1.23, "string": "Booga"}"#
                        .to_string(),
                ),
            },
        };

        let json = UiTrafficConverter::new_marshal_to_ui(ui_msg);

        let ui_msg =
            UiTrafficConverter::new_unmarshal_to_ui(&json, MessageTarget::ClientId(1234)).unwrap();
        assert_eq!(ui_msg.target, MessageTarget::ClientId(1234));
        assert_eq!(ui_msg.body.opcode, "opcode".to_string());
        assert_eq!(ui_msg.body.path, FireAndForget);
        match serde_json::from_str::<Value>(&ui_msg.body.payload.unwrap()) {
            Ok(Value::Object(map)) => {
                assert_eq!(map.get("null"), Some(&Value::Null));
                assert_eq!(map.get("bool"), Some(&Value::Bool(true)));
                assert_eq!(
                    map.get("number"),
                    Some(&Value::Number(Number::from_f64(1.23).unwrap()))
                );
                assert_eq!(map.get("string"), Some(&Value::String("Booga".to_string())));
            }
            v => panic!("Needed Some(Value::Map); got {:?}", v),
        }
    }

    #[test]
    fn new_marshaling_and_unmarshaling_works_from_ui_one_way_for_failure() {
        let ui_msg = NodeFromUiMessage {
            client_id: 4321,
            body: MessageBody {
                opcode: "opcode".to_string(),
                path: FireAndForget,
                payload: Err((4567, "Moron".to_string())),
            },
        };

        let json = UiTrafficConverter::new_marshal_from_ui(ui_msg);

        let ui_msg = UiTrafficConverter::new_unmarshal_from_ui(&json, 1234).unwrap();
        assert_eq!(ui_msg.client_id, 1234);
        assert_eq!(ui_msg.body.opcode, "opcode".to_string());
        assert_eq!(ui_msg.body.path, FireAndForget);
        assert_eq!(
            ui_msg.body.payload.err().unwrap(),
            (4567, "Moron".to_string())
        );
    }

    #[test]
    fn new_marshaling_and_unmarshaling_works_to_ui_one_way_for_failure() {
        let ui_msg = NodeToUiMessage {
            target: MessageTarget::ClientId(4321),
            body: MessageBody {
                opcode: "opcode".to_string(),
                path: FireAndForget,
                payload: Err((4567, "Moron".to_string())),
            },
        };

        let json = UiTrafficConverter::new_marshal_to_ui(ui_msg);

        let ui_msg =
            UiTrafficConverter::new_unmarshal_to_ui(&json, MessageTarget::ClientId(1234)).unwrap();
        assert_eq!(ui_msg.target, MessageTarget::ClientId(1234));
        assert_eq!(ui_msg.body.opcode, "opcode".to_string());
        assert_eq!(ui_msg.body.path, FireAndForget);
        assert_eq!(
            ui_msg.body.payload.err().unwrap(),
            (4567, "Moron".to_string())
        );
    }

    #[test]
    fn new_marshaling_and_unmarshaling_works_from_ui_two_way_for_success() {
        let ui_msg = NodeFromUiMessage {
            client_id: 4321,
            body: MessageBody {
                opcode: "opcode".to_string(),
                path: Conversation(2222),
                payload: Ok(
                    r#"{"null": null, "bool": true, "number": 1.23, "string": "Booga"}"#
                        .to_string(),
                ),
            },
        };

        let json = UiTrafficConverter::new_marshal_from_ui(ui_msg);

        let ui_msg = UiTrafficConverter::new_unmarshal_from_ui(&json, 1234).unwrap();
        assert_eq!(ui_msg.client_id, 1234);
        assert_eq!(ui_msg.body.opcode, "opcode".to_string());
        assert_eq!(ui_msg.body.path, Conversation(2222));
        match serde_json::from_str::<Value>(&ui_msg.body.payload.unwrap()) {
            Ok(Value::Object(map)) => {
                assert_eq!(map.get("null"), Some(&Value::Null));
                assert_eq!(map.get("bool"), Some(&Value::Bool(true)));
                assert_eq!(
                    map.get("number"),
                    Some(&Value::Number(Number::from_f64(1.23).unwrap()))
                );
                assert_eq!(map.get("string"), Some(&Value::String("Booga".to_string())));
            }
            v => panic!("Needed Some(Value::Map); got {:?}", v),
        }
    }

    #[test]
    fn new_marshaling_and_unmarshaling_works_to_ui_two_way_for_success() {
        let ui_msg = NodeToUiMessage {
            target: MessageTarget::ClientId(4321),
            body: MessageBody {
                opcode: "opcode".to_string(),
                path: Conversation(2222),
                payload: Ok(
                    r#"{"null": null, "bool": true, "number": 1.23, "string": "Booga"}"#
                        .to_string(),
                ),
            },
        };

        let json = UiTrafficConverter::new_marshal_to_ui(ui_msg);

        let ui_msg =
            UiTrafficConverter::new_unmarshal_to_ui(&json, MessageTarget::ClientId(1234)).unwrap();
        assert_eq!(ui_msg.target, MessageTarget::ClientId(1234));
        assert_eq!(ui_msg.body.opcode, "opcode".to_string());
        assert_eq!(ui_msg.body.path, Conversation(2222));
        match serde_json::from_str::<Value>(&ui_msg.body.payload.unwrap()) {
            Ok(Value::Object(map)) => {
                assert_eq!(map.get("null"), Some(&Value::Null));
                assert_eq!(map.get("bool"), Some(&Value::Bool(true)));
                assert_eq!(
                    map.get("number"),
                    Some(&Value::Number(Number::from_f64(1.23).unwrap()))
                );
                assert_eq!(map.get("string"), Some(&Value::String("Booga".to_string())));
            }
            v => panic!("Needed Some(Value::Map); got {:?}", v),
        }
    }

    #[test]
    fn new_marshaling_and_unmarshaling_works_from_ui_two_way_for_failure() {
        let ui_msg = NodeFromUiMessage {
            client_id: 4321,
            body: MessageBody {
                opcode: "opcode".to_string(),
                path: Conversation(2222),
                payload: Err((4567, "Moron".to_string())),
            },
        };

        let json = UiTrafficConverter::new_marshal_from_ui(ui_msg);

        let ui_msg = UiTrafficConverter::new_unmarshal_from_ui(&json, 1234).unwrap();
        assert_eq!(ui_msg.client_id, 1234);
        assert_eq!(ui_msg.body.opcode, "opcode".to_string());
        assert_eq!(ui_msg.body.path, Conversation(2222));
        assert_eq!(
            ui_msg.body.payload.err().unwrap(),
            (4567, "Moron".to_string())
        );
    }

    #[test]
    fn new_marshaling_and_unmarshaling_works_to_ui_two_way_for_failure() {
        let ui_msg = NodeToUiMessage {
            target: MessageTarget::ClientId(4321),
            body: MessageBody {
                opcode: "opcode".to_string(),
                path: Conversation(2222),
                payload: Err((4567, "Moron".to_string())),
            },
        };

        let json = UiTrafficConverter::new_marshal_to_ui(ui_msg);

        let ui_msg =
            UiTrafficConverter::new_unmarshal_to_ui(&json, MessageTarget::ClientId(1234)).unwrap();
        assert_eq!(ui_msg.target, MessageTarget::ClientId(1234));
        assert_eq!(ui_msg.body.opcode, "opcode".to_string());
        assert_eq!(ui_msg.body.path, Conversation(2222));
        assert_eq!(
            ui_msg.body.payload.err().unwrap(),
            (4567, "Moron".to_string())
        );
    }

    #[test]
    fn new_unmarshaling_handles_missing_opcode() {
        let json = r#"{"payload": {}}"#;

        let result = UiTrafficConverter::new_unmarshal_from_ui(json, 1234);

        assert_eq!(
            result,
            Err(Critical(MissingFieldError("opcode".to_string())))
        )
    }

    #[test]
    fn new_unmarshaling_handles_badly_typed_opcode() {
        let json = r#"{"opcode": false, "payload": {}}"#;

        let result = UiTrafficConverter::new_unmarshal_to_ui(json, MessageTarget::ClientId(1234));

        assert_eq!(
            result,
            Err(Critical(FieldTypeError(
                "opcode".to_string(),
                "string".to_string(),
                "false".to_string()
            )))
        )
    }

    #[test]
    fn new_unmarshaling_handles_missing_payload_and_error() {
        let json = r#"{"opcode": "whomp"}"#;

        let result = UiTrafficConverter::new_unmarshal_from_ui(json, 1234);

        assert_eq!(
            result,
            Err(NonCritical(
                "whomp".to_string(),
                None,
                MissingFieldError("payload, error".to_string())
            ))
        )
    }

    #[test]
    fn new_unmarshaling_handles_badly_typed_payload() {
        let json = r#"{"opcode": "whomp", "contextId": 4321, "payload": 1}"#;

        let result = UiTrafficConverter::new_unmarshal_to_ui(json, MessageTarget::ClientId(1234));

        assert_eq!(
            result,
            Err(NonCritical(
                "whomp".to_string(),
                Some(4321),
                FieldTypeError(
                    "payload".to_string(),
                    "object".to_string(),
                    "Number(1)".to_string()
                )
            ))
        )
    }

    #[test]
    fn new_unmarshaling_handles_badly_typed_error() {
        let json = r#"{"opcode": "whomp", "error": 1}"#;

        let result = UiTrafficConverter::new_unmarshal_to_ui(json, MessageTarget::ClientId(1234));

        assert_eq!(
            result,
            Err(NonCritical(
                "whomp".to_string(),
                None,
                FieldTypeError("error".to_string(), "object".to_string(), "1".to_string())
            ))
        )
    }

    #[test]
    fn new_unmarshaling_handles_badly_typed_json() {
        let json = r#"[1, 2, 3, 4]"#;

        let result = UiTrafficConverter::new_unmarshal_from_ui(json, 1234);

        assert_eq!(
            result,
            Err(Critical(NotJsonObjectError("[1,2,3,4]".to_string())))
        );
    }

    #[test]
    fn new_unmarshaling_handles_unparseable_json() {
        let json = r#"}--{"#;

        let result = UiTrafficConverter::new_unmarshal_to_ui(json, MessageTarget::ClientId(1234));

        assert_eq!(
            result,
            Err(Critical(JsonSyntaxError(
                "Error(\"expected value\", line: 1, column: 1)".to_string()
            )))
        );
    }

    #[test]
    fn get_u64_handles_errors() {
        let json = r#"{"bad_u64": -47}"#;
        let map = serde_json::from_str(json).unwrap();

        let result = UiTrafficConverter::get_u64(&map, "bad_u64");

        assert_eq!(
            result,
            Err(FieldTypeError(
                "bad_u64".to_string(),
                "u64".to_string(),
                "-47".to_string()
            ))
        )
    }

    #[test]
    fn display_works_for_traffic_conversion_error() {
        let a = "a".to_string();
        let b = "b".to_string();
        let c = "c".to_string();
        assert_eq!(
            JsonSyntaxError(a.clone()).to_string(),
            "Couldn't parse text as JSON: a".to_string()
        );
        assert_eq!(
            NotJsonObjectError(a.clone()).to_string(),
            "Root was not a JSON object:\n------\na\n------\n".to_string()
        );
        assert_eq!(
            MissingFieldError(a.clone()).to_string(),
            "Required field was missing: a".to_string()
        );
        assert_eq!(
            FieldTypeError(a, b, c).to_string(),
            "Field a should have been of type b, but was 'c' instead".to_string()
        );
    }

    #[test]
    fn display_works_for_unmarshal_error() {
        let error = MissingFieldError("booga".to_string());
        assert_eq!(
            Critical(error.clone()).to_string(),
            "Critical error unmarshalling unidentified message: Required field was missing: booga"
                .to_string()
        );
        assert_eq!(
            NonCritical("whomp".to_string(), None, error).to_string(),
            "Error unmarshalling 'whomp' message: Required field was missing: booga".to_string()
        );
    }
}
