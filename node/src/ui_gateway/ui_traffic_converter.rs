// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::sub_lib::ui_gateway::{MessageDirection, NewUiMessage, UiMessage};
use serde_json::Value;

#[allow(dead_code)]
pub const BROADCAST: u64 = 0xFFFF_FFFF_FFFF_FFFF;

pub trait UiTrafficConverter: Send {
    fn marshal(&self, ui_message: UiMessage) -> Result<String, String>;
    fn unmarshal(&self, json: &str) -> Result<UiMessage, String>;
    fn new_marshal(&self, msg: NewUiMessage) -> String;
    fn new_unmarshal(&self, json: &str, client_id: u64) -> Result<NewUiMessage, String>;
}

#[derive(Default)]
pub struct UiTrafficConverterReal {}

impl UiTrafficConverter for UiTrafficConverterReal {
    // TODO: After these methods are obsoleted and removed, get rid of the trait and make the
    // remaining methods into static functions.
    fn marshal(&self, ui_message: UiMessage) -> Result<String, String> {
        serde_json::to_string(&ui_message).map_err(|e| e.to_string())
    }

    fn unmarshal(&self, _json: &str) -> Result<UiMessage, String> {
        serde_json::from_str(_json).map_err(|e| e.to_string())
    }

    fn new_marshal(&self, msg: NewUiMessage) -> String {
        let mut msg_map = serde_json::map::Map::new();
        msg_map.insert("opcode".to_string(), Value::String(msg.opcode));
        msg_map.insert(
            "direction".to_string(),
            Value::String(match msg.direction {
                MessageDirection::FromUi => "fromUi".to_string(),
                MessageDirection::ToUi => "toUi".to_string(),
            }),
        );
        msg_map.insert("payload".to_string(), serde_json::from_str(&msg.payload).expect ("Serialization problem"));
        serde_json::to_string(&msg_map).expect("Problem converting Value::Object to JSON")
    }

    fn new_unmarshal(&self, json: &str, client_id: u64) -> Result<NewUiMessage, String> {
        match serde_json::from_str(json) {
            Ok(Value::Object(map)) => {
                let opcode = Self::get_string(&map, "opcode")?;
                let direction = match Self::get_string(&map, "direction")? {
                    s if s == "fromUi".to_string() => MessageDirection::FromUi,
                    s if s == "toUi".to_string() => MessageDirection::ToUi,
                    other => {
                        return Err(format!(
                            "direction should be fromUi or toUi, not '{}'",
                            other
                        ))
                    }
                };
                let payload_map = match map.get("payload") {
                    Some(Value::Object(value)) => value,
                    Some(x) => return Err(format!(
                        "payload should have been of type Value::Object, not {:?}",
                        x
                    )),
                    None => return Err("payload field is missing".to_string()),
                };
                let payload = serde_json::to_string (payload_map).expect ("Reserialization problem");
                Ok(NewUiMessage {client_id, opcode, direction, payload})
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
}

impl UiTrafficConverterReal {
    pub fn new() -> Self {
        Self {}
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
    use crate::sub_lib::ui_gateway::MessageDirection;

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
    fn new_marshaling_and_unmarshaling_works() {
        let subject = UiTrafficConverterReal::new();
        let in_ui_msg = NewUiMessage {
            client_id: 4321,
            opcode: "opcode".to_string(),
            direction: MessageDirection::ToUi,
            payload: r#"{"null": null, "bool": true, "number": 1.23, "string": "Booga"}"#.to_string(),
        };

        let json = subject.new_marshal(in_ui_msg);

        let out_ui_msg = subject.new_unmarshal(&json, 1234).unwrap();
        assert_eq!(out_ui_msg.client_id, 1234);
        assert_eq!(out_ui_msg.opcode, "opcode".to_string());
        assert_eq!(out_ui_msg.direction, MessageDirection::ToUi);
        assert_eq!(out_ui_msg.payload, r#"{"null": null, "bool": true, "number": 1.23, "string": "Booga"}"#.to_string())
    }

    #[test]
    fn new_unmarshaling_handles_missing_opcode() {
        let subject = UiTrafficConverterReal::new();
        let json = r#"{"direction": "fromUi", "data": {}}"#;

        let result = subject.new_unmarshal(json, 1234);

        assert_eq!(result, Err("opcode field is missing".to_string()))
    }

    #[test]
    fn new_unmarshaling_handles_badly_typed_opcode() {
        let subject = UiTrafficConverterReal::new();
        let json = r#"{"opcode": false, "direction": "fromUi", "data": {}}"#;

        let result = subject.new_unmarshal(json, 1234);

        assert_eq!(
            result,
            Err("opcode should have been of type Value::String, not Bool(false)".to_string())
        )
    }

    #[test]
    fn new_unmarshaling_handles_bad_message_direction() {
        let subject = UiTrafficConverterReal::new();
        let json = r#"{"opcode": "whomp", "direction": "booga", "data": {}}"#;

        let result = subject.new_unmarshal(json, 1234);

        assert_eq!(
            result,
            Err("direction should be fromUi or toUi, not 'booga'".to_string())
        )
    }

    #[test]
    fn new_unmarshaling_handles_missing_data() {
        let subject = UiTrafficConverterReal::new();
        let json = r#"{"opcode": "whomp", "direction": "fromUi"}"#;

        let result = subject.new_unmarshal(json, 1234);

        assert_eq!(result, Err("data field is missing".to_string()))
    }

    #[test]
    fn new_unmarshaling_handles_badly_typed_data() {
        let subject = UiTrafficConverterReal::new();
        let json = r#"{"opcode": "whomp", "direction": "fromUi", "data": 1}"#;

        let result = subject.new_unmarshal(json, 1234);

        assert_eq!(
            result,
            Err("data should have been of type Value::Object, not Number(1)".to_string())
        )
    }

    #[test]
    fn new_unmarshaling_handles_badly_typed_json() {
        let subject = UiTrafficConverterReal::new();
        let json = r#"[1, 2, 3, 4]"#;

        let result = subject.new_unmarshal(json, 1234);

        assert_eq! (result, Err("JSON packet should have been of type Value::Object, not Array([Number(1), Number(2), Number(3), Number(4)])".to_string()))
    }

    #[test]
    fn new_unmarshaling_handles_unparseable_json() {
        let subject = UiTrafficConverterReal::new();
        let json = r#"}--{"#;

        let result = subject.new_unmarshal(json, 1234);

        assert_eq! (result, Err("Packet could not be parsed as JSON: '}--{' - Error(\"expected value\", line: 1, column: 1)".to_string()))
    }
}
