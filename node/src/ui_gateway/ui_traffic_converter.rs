// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::sub_lib::ui_gateway::{NewToUiMessage, UiMessage, MessageTarget, NewFromUiMessage};
use serde_json::Value;

#[allow(dead_code)]
pub const BROADCAST: u64 = 0xFFFF_FFFF_FFFF_FFFF;

pub trait UiTrafficConverter: Send {
    fn marshal(&self, ui_message: UiMessage) -> Result<String, String>;
    fn unmarshal(&self, json: &str) -> Result<UiMessage, String>;

    fn new_marshal_from_ui(&self, msg: NewFromUiMessage) -> String;
    fn new_marshal_to_ui(&self, msg: NewToUiMessage) -> String;
    fn new_unmarshal_from_ui(&self, json: &str, client_id: u64) -> Result<NewFromUiMessage, String>;
    fn new_unmarshal_to_ui(&self, json: &str, target: MessageTarget) -> Result<NewToUiMessage, String>;
}

#[derive(Default)]
pub struct UiTrafficConverterReal {}

impl UiTrafficConverter for UiTrafficConverterReal {
    // TODO: After these methods are obsoleted and removed, get rid of the trait and make the
    // remaining methods into static functions, or possibly TryFrom and TryInto implementations for
    // NewFromUiMessage and NewToUiMessage.
    fn marshal(&self, ui_message: UiMessage) -> Result<String, String> {
        serde_json::to_string(&ui_message).map_err(|e| e.to_string())
    }

    fn unmarshal(&self, _json: &str) -> Result<UiMessage, String> {
        serde_json::from_str(_json).map_err(|e| e.to_string())
    }

    fn new_marshal_from_ui(&self, msg: NewFromUiMessage) -> String {
        self.new_marshal(msg.opcode, serde_json::from_str(&msg.payload).expect("Serialization problem"))
    }

    fn new_marshal_to_ui(&self, msg: NewToUiMessage) -> String {
        self.new_marshal(msg.opcode, serde_json::from_str(&msg.payload).expect("Serialization problem"))
    }

    fn new_unmarshal_from_ui(&self, json: &str, client_id: u64) -> Result<NewFromUiMessage, String> {
        match self.new_unmarshal (json) {
            Ok ((opcode, payload)) => Ok (NewFromUiMessage {
                client_id,
                opcode,
                payload
            }),
            Err (e) => Err (e)
        }
    }

    fn new_unmarshal_to_ui(&self, json: &str, target: MessageTarget) -> Result<NewToUiMessage, String> {
        match self.new_unmarshal (json) {
            Ok ((opcode, payload)) => Ok (NewToUiMessage {
                target,
                opcode,
                payload
            }),
            Err (e) => Err (e)
        }
    }
}

impl UiTrafficConverterReal {
    pub fn new() -> Self {
        Self {}
    }

    fn new_marshal(&self, opcode: String, payload: Value) -> String {
        let mut msg_map = serde_json::map::Map::new();
        msg_map.insert("opcode".to_string(), Value::String(opcode));
        msg_map.insert("payload".to_string(), payload);
        serde_json::to_string(&msg_map).expect("Problem converting Value::Object to JSON")
    }

    fn new_unmarshal(&self, json: &str) -> Result<(String, String), String> {
        match serde_json::from_str(json) {
            Ok(Value::Object(map)) => {
                let opcode = Self::get_string(&map, "opcode")?;
                let payload_map = match map.get("payload") {
                    Some(Value::Object(value)) => value,
                    Some(x) => {
                        return Err(format!(
                            "payload should have been of type Value::Object, not {:?}",
                            x
                        ))
                    }
                    None => return Err("payload field is missing".to_string()),
                };
                let payload = serde_json::to_string(payload_map).expect("Reserialization problem");
                Ok((opcode, payload))
            }
            Ok(x) => Err(format!(
                "JSON packet should have been of type Value::Object, not {:?}",
                x
            )),
            Err(e) => Err(format!(
                "Packet could not be parsed as JSON: '{}' - {:?}",
                json, e
            )),
        }
    }

    fn get_string(map: &serde_json::map::Map<String, Value>, name: &str) -> Result<String, String> {
        match map.get(name) {
            Some(Value::String(s)) => Ok(s.clone()),
            Some(x) => Err(format!(
                "{} should have been of type Value::String, not {:?}",
                name, x
            )),
            None => Err(format!("{} field is missing", name)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::ui_gateway::{MessageTarget};
    use serde_json::Number;

    #[test]
    fn a_shutdown_message_is_properly_marshalled_and_unmarshalled() {
        let subject = UiTrafficConverterReal::new();

        let marshalled = serde_json::to_string(&UiMessage::ShutdownMessage).unwrap();
        let unmarshalled = subject.unmarshal(&marshalled);

        assert_eq!(unmarshalled, Ok(UiMessage::ShutdownMessage));
    }

    #[test]
    fn a_neighborhood_dot_graph_request_is_properly_marshaled_and_unmarshaled() {
        let subject = UiTrafficConverterReal::new();

        let marshaled = serde_json::to_string(&UiMessage::NeighborhoodDotGraphRequest).unwrap();
        let unmarshaled = subject.unmarshal(&marshaled);

        assert_eq!(unmarshaled, Ok(UiMessage::NeighborhoodDotGraphRequest));
    }

    #[test]
    fn new_marshaling_and_unmarshaling_works_from_ui() {
        let subject = UiTrafficConverterReal::new();
        let out_ui_msg = NewFromUiMessage {
            client_id: 4321,
            opcode: "opcode".to_string(),
            payload: r#"{"null": null, "bool": true, "number": 1.23, "string": "Booga"}"#
                .to_string(),
        };

        let json = subject.new_marshal_from_ui(out_ui_msg);

        let out_ui_msg = subject.new_unmarshal_from_ui(&json, 1234).unwrap();
        assert_eq!(out_ui_msg.client_id, 1234);
        assert_eq!(out_ui_msg.opcode, "opcode".to_string());
        match serde_json::from_str::<Value>(&out_ui_msg.payload) {
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
    fn new_marshaling_and_unmarshaling_works_to_ui() {
        let subject = UiTrafficConverterReal::new();
        let in_ui_msg = NewToUiMessage {
            target: MessageTarget::ClientId(4321),
            opcode: "opcode".to_string(),
            payload: r#"{"null": null, "bool": true, "number": 1.23, "string": "Booga"}"#
                .to_string(),
        };

        let json = subject.new_marshal_to_ui(in_ui_msg);

        let out_ui_msg = subject.new_unmarshal_to_ui(&json, MessageTarget::ClientId(1234)).unwrap();
        assert_eq!(out_ui_msg.target, MessageTarget::ClientId(1234));
        assert_eq!(out_ui_msg.opcode, "opcode".to_string());
        match serde_json::from_str::<Value>(&out_ui_msg.payload) {
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
    fn new_unmarshaling_handles_missing_opcode() {
        let subject = UiTrafficConverterReal::new();
        let json = r#"{"payload": {}}"#;

        let result = subject.new_unmarshal_from_ui(json, 1234);

        assert_eq!(result, Err("opcode field is missing".to_string()))
    }

    #[test]
    fn new_unmarshaling_handles_badly_typed_opcode() {
        let subject = UiTrafficConverterReal::new();
        let json = r#"{"opcode": false, "payload": {}}"#;

        let result = subject.new_unmarshal_to_ui(json, MessageTarget::ClientId(1234));

        assert_eq!(
            result,
            Err("opcode should have been of type Value::String, not Bool(false)".to_string())
        )
    }

    #[test]
    fn new_unmarshaling_handles_missing_payload() {
        let subject = UiTrafficConverterReal::new();
        let json = r#"{"opcode": "whomp"}"#;

        let result = subject.new_unmarshal_from_ui(json, 1234);

        assert_eq!(result, Err("payload field is missing".to_string()))
    }

    #[test]
    fn new_unmarshaling_handles_badly_typed_payload() {
        let subject = UiTrafficConverterReal::new();
        let json = r#"{"opcode": "whomp", "payload": 1}"#;

        let result = subject.new_unmarshal_to_ui(json, MessageTarget::ClientId(1234));

        assert_eq!(
            result,
            Err("payload should have been of type Value::Object, not Number(1)".to_string())
        )
    }

    #[test]
    fn new_unmarshaling_handles_badly_typed_json() {
        let subject = UiTrafficConverterReal::new();
        let json = r#"[1, 2, 3, 4]"#;

        let result = subject.new_unmarshal_from_ui(json, 1234);

        assert_eq! (result, Err("JSON packet should have been of type Value::Object, not Array([Number(1), Number(2), Number(3), Number(4)])".to_string()))
    }

    #[test]
    fn new_unmarshaling_handles_unparseable_json() {
        let subject = UiTrafficConverterReal::new();
        let json = r#"}--{"#;

        let result = subject.new_unmarshal_to_ui(json, MessageTarget::ClientId(1234));

        assert_eq! (result, Err("Packet could not be parsed as JSON: '}--{' - Error(\"expected value\", line: 1, column: 1)".to_string()))
    }
}
