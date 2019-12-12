// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::sub_lib::logger::Logger;
use crate::sub_lib::ui_gateway::MessagePath::{OneWay, TwoWay};
use crate::sub_lib::ui_gateway::MessageTarget::ClientId;
use crate::sub_lib::ui_gateway::{
    MessageBody, MessageTarget, NewFromUiMessage, NewToUiMessage, UiMessage,
};
use crate::ui_gateway::websocket_supervisor::UNEXPECTED_ERROR_REQUEST_CODE;
use actix::Recipient;
use serde_json::Value;

#[allow(dead_code)]
pub const BROADCAST: u64 = 0xFFFF_FFFF_FFFF_FFFF;

pub trait UiTrafficConverter: Send {
    fn marshal(&self, ui_message: UiMessage) -> Result<String, String>;
    fn unmarshal(&self, json: &str) -> Result<UiMessage, String>;

    fn new_marshal_from_ui(&self, msg: NewFromUiMessage) -> String;
    fn new_marshal_to_ui(&self, msg: NewToUiMessage) -> String;
    fn new_unmarshal_from_ui(&self, json: &str, client_id: u64)
        -> Result<NewFromUiMessage, String>;
    fn new_unmarshal_to_ui(
        &self,
        json: &str,
        target: MessageTarget,
    ) -> Result<NewToUiMessage, String>;
    fn reject_error_from_ui(
        &self,
        logger: &Logger,
        msg: &NewFromUiMessage,
        reply_sub_opt: Option<&Recipient<NewToUiMessage>>,
    ) -> Result<String, String>;
    fn reject_error_to_ui(
        &self,
        logger: &Logger,
        msg: &NewToUiMessage,
        reply_sub_opt: Option<&Recipient<NewFromUiMessage>>,
    ) -> Result<String, String>;
    fn get_context_id(&self, logger: &Logger, body: &MessageBody) -> Option<u64>;
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
        self.new_marshal(msg.body)
    }

    fn new_marshal_to_ui(&self, msg: NewToUiMessage) -> String {
        self.new_marshal(msg.body)
    }

    fn new_unmarshal_from_ui(
        &self,
        json: &str,
        client_id: u64,
    ) -> Result<NewFromUiMessage, String> {
        match self.new_unmarshal(json) {
            Ok(body) => Ok(NewFromUiMessage { client_id, body }),
            Err(e) => Err(e),
        }
    }

    fn new_unmarshal_to_ui(
        &self,
        json: &str,
        target: MessageTarget,
    ) -> Result<NewToUiMessage, String> {
        match self.new_unmarshal(json) {
            Ok(body) => Ok(NewToUiMessage { target, body }),
            Err(e) => Err(e),
        }
    }

    fn reject_error_from_ui(
        &self,
        logger: &Logger,
        msg: &NewFromUiMessage,
        reply_sub_opt: Option<&Recipient<NewToUiMessage>>,
    ) -> Result<String, String> {
        match &msg.body.payload {
            Ok(json) => Ok(json.clone()),
            Err((code, message)) => {
                match msg.body.path {
                    OneWay => {
                        let msg = format! ("Unexpected error request from client {} for '{}' ({}: {}) - discarding", msg.client_id, msg.body.opcode, code, message);
                        error!(logger, "{}", msg);
                        Err(msg)
                    }
                    TwoWay(context_id) => {
                        let msg_prefix = format!(
                            "Unexpected error request from client {} for '{}' ({}: {})",
                            msg.client_id, msg.body.opcode, code, message
                        );
                        let full_msg = match reply_sub_opt {
                            Some(reply_sub) => {
                                reply_sub
                                    .try_send(NewToUiMessage {
                                        target: ClientId(msg.client_id),
                                        body: MessageBody {
                                            opcode: msg.body.opcode.clone(),
                                            path: TwoWay(context_id),
                                            payload: Err((
                                                UNEXPECTED_ERROR_REQUEST_CODE,
                                                msg_prefix.clone(),
                                            )),
                                        },
                                    })
                                    .expect("UiGateway is poisoned");
                                format!(
                                    "{} - complaining to sender with context {}",
                                    msg_prefix, context_id
                                )
                            }
                            None => format!("{} - discarding", msg_prefix),
                        };
                        error!(logger, "{}", full_msg);
                        Err(full_msg)
                    }
                }
            }
        }
    }

    fn reject_error_to_ui(
        &self,
        logger: &Logger,
        msg: &NewToUiMessage,
        reply_sub_opt: Option<&Recipient<NewFromUiMessage>>,
    ) -> Result<String, String> {
        match &msg.body.payload {
            Ok(json) => Ok(json.clone()),
            Err((code, message)) => {
                match msg.body.path {
                    OneWay => {
                        let msg = format!(
                            "Unexpected error request from server for '{}' ({}: {}) - discarding",
                            msg.body.opcode, code, message
                        );
                        error!(logger, "{}", msg);
                        Err(msg)
                    }
                    TwoWay(context_id) => {
                        let msg_prefix = format!(
                            "Unexpected error request from server for '{}' ({}: {})",
                            msg.body.opcode, code, message
                        );
                        let full_msg = match reply_sub_opt {
                            Some(reply_sub) => {
                                reply_sub
                                    .try_send(NewFromUiMessage {
                                        client_id: 0, // client_id is irrelevant; will be replaced on the other end anyway
                                        body: MessageBody {
                                            opcode: msg.body.opcode.clone(),
                                            path: TwoWay(context_id),
                                            payload: Err((
                                                UNEXPECTED_ERROR_REQUEST_CODE,
                                                msg_prefix.clone(),
                                            )),
                                        },
                                    })
                                    .expect("UiGateway is poisoned");
                                format!(
                                    "{} - complaining to sender with context {}",
                                    msg_prefix, context_id
                                )
                            }
                            None => format!("{} - discarding", msg_prefix),
                        };
                        error!(logger, "{}", full_msg);
                        Err(full_msg)
                    }
                }
            }
        }
    }

    fn get_context_id(&self, logger: &Logger, body: &MessageBody) -> Option<u64> {
        match body.path {
            TwoWay(context_id) => Some(context_id),
            OneWay => {
                error!(
                    logger,
                    "TwoWay UI message '{}' was sent as OneWay - discarding", body.opcode
                );
                None
            }
        }
    }
}

impl UiTrafficConverterReal {
    pub fn new() -> Self {
        Self {}
    }

    fn new_marshal(&self, body: MessageBody) -> String {
        let opcode_section = format!("\"opcode\": \"{}\", ", body.opcode);
        let path_section = match body.path {
            OneWay => "".to_string(),
            TwoWay(context_id) => format!("\"contextId\": {}, ", context_id),
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

    fn new_unmarshal(&self, json: &str) -> Result<MessageBody, String> {
        match serde_json::from_str(json) {
            Ok(Value::Object(map)) => {
                let opcode = Self::get_string(&map, "opcode")?;
                let path = match Self::get_u64(&map, "contextId") {
                    Ok(context_id) => TwoWay(context_id),
                    Err(s) if s == "contextId field is missing" => OneWay,
                    Err(s) => return Err(s),
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
                    Some(other_value) => Err(format!(
                        "payload should have been of type Value::Object, not {:?}",
                        other_value
                    )),
                    None => match map.get("error") {
                        Some(Value::Object(error_map)) => {
                            let code = Self::get_u64(&error_map, "code")?;
                            let message = Self::get_string(&error_map, "message")?;
                            Ok(MessageBody {
                                opcode,
                                path,
                                payload: Err((code, message)),
                            })
                        }
                        Some(other_value) => Err(format!(
                            "error should have been of type Value::Object, not {:?}",
                            other_value
                        )),
                        None => Err("Neither payload nor error field is present".to_string()),
                    },
                }
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

    fn get_u64(map: &serde_json::map::Map<String, Value>, name: &str) -> Result<u64, String> {
        match map.get(name) {
            Some(Value::Number(n)) => match n.as_u64() {
                Some(n) => Ok(n),
                None => Err(format!("Cannot convert from JSON to u64: {:?}", n)),
            },
            Some(x) => Err(format!(
                "{} should have been of type Value::Number, not {:?}",
                name, x
            )),
            None => Err(format!("{} field is missing", name)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::ui_gateway::MessagePath::OneWay;
    use crate::sub_lib::ui_gateway::MessageTarget::{AllClients, ClientId};
    use crate::sub_lib::ui_gateway::{MessageBody, MessageTarget};
    use crate::test_utils::logging::{init_test_logging, TestLogHandler};
    use crate::test_utils::recorder::make_recorder;
    use actix::{Actor, System};
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
    fn new_marshaling_and_unmarshaling_works_from_ui_one_way_for_success() {
        let subject = UiTrafficConverterReal::new();
        let ui_msg = NewFromUiMessage {
            client_id: 4321,
            body: MessageBody {
                opcode: "opcode".to_string(),
                path: OneWay,
                payload: Ok(
                    r#"{"null": null, "bool": true, "number": 1.23, "string": "Booga"}"#
                        .to_string(),
                ),
            },
        };

        let json = subject.new_marshal_from_ui(ui_msg);

        let ui_msg = subject.new_unmarshal_from_ui(&json, 1234).unwrap();
        assert_eq!(ui_msg.client_id, 1234);
        assert_eq!(ui_msg.body.opcode, "opcode".to_string());
        assert_eq!(ui_msg.body.path, OneWay);
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
        let subject = UiTrafficConverterReal::new();
        let ui_msg = NewToUiMessage {
            target: MessageTarget::ClientId(4321),
            body: MessageBody {
                opcode: "opcode".to_string(),
                path: OneWay,
                payload: Ok(
                    r#"{"null": null, "bool": true, "number": 1.23, "string": "Booga"}"#
                        .to_string(),
                ),
            },
        };

        let json = subject.new_marshal_to_ui(ui_msg);

        let ui_msg = subject
            .new_unmarshal_to_ui(&json, MessageTarget::ClientId(1234))
            .unwrap();
        assert_eq!(ui_msg.target, MessageTarget::ClientId(1234));
        assert_eq!(ui_msg.body.opcode, "opcode".to_string());
        assert_eq!(ui_msg.body.path, OneWay);
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
        let subject = UiTrafficConverterReal::new();
        let ui_msg = NewFromUiMessage {
            client_id: 4321,
            body: MessageBody {
                opcode: "opcode".to_string(),
                path: OneWay,
                payload: Err((4567, "Moron".to_string())),
            },
        };

        let json = subject.new_marshal_from_ui(ui_msg);

        let ui_msg = subject.new_unmarshal_from_ui(&json, 1234).unwrap();
        assert_eq!(ui_msg.client_id, 1234);
        assert_eq!(ui_msg.body.opcode, "opcode".to_string());
        assert_eq!(ui_msg.body.path, OneWay);
        assert_eq!(
            ui_msg.body.payload.err().unwrap(),
            (4567, "Moron".to_string())
        );
    }

    #[test]
    fn new_marshaling_and_unmarshaling_works_to_ui_one_way_for_failure() {
        let subject = UiTrafficConverterReal::new();
        let ui_msg = NewToUiMessage {
            target: MessageTarget::ClientId(4321),
            body: MessageBody {
                opcode: "opcode".to_string(),
                path: OneWay,
                payload: Err((4567, "Moron".to_string())),
            },
        };

        let json = subject.new_marshal_to_ui(ui_msg);

        let ui_msg = subject
            .new_unmarshal_to_ui(&json, MessageTarget::ClientId(1234))
            .unwrap();
        assert_eq!(ui_msg.target, MessageTarget::ClientId(1234));
        assert_eq!(ui_msg.body.opcode, "opcode".to_string());
        assert_eq!(ui_msg.body.path, OneWay);
        assert_eq!(
            ui_msg.body.payload.err().unwrap(),
            (4567, "Moron".to_string())
        );
    }

    #[test]
    fn new_marshaling_and_unmarshaling_works_from_ui_two_way_for_success() {
        let subject = UiTrafficConverterReal::new();
        let ui_msg = NewFromUiMessage {
            client_id: 4321,
            body: MessageBody {
                opcode: "opcode".to_string(),
                path: TwoWay(2222),
                payload: Ok(
                    r#"{"null": null, "bool": true, "number": 1.23, "string": "Booga"}"#
                        .to_string(),
                ),
            },
        };

        let json = subject.new_marshal_from_ui(ui_msg);

        let ui_msg = subject.new_unmarshal_from_ui(&json, 1234).unwrap();
        assert_eq!(ui_msg.client_id, 1234);
        assert_eq!(ui_msg.body.opcode, "opcode".to_string());
        assert_eq!(ui_msg.body.path, TwoWay(2222));
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
        let subject = UiTrafficConverterReal::new();
        let ui_msg = NewToUiMessage {
            target: MessageTarget::ClientId(4321),
            body: MessageBody {
                opcode: "opcode".to_string(),
                path: TwoWay(2222),
                payload: Ok(
                    r#"{"null": null, "bool": true, "number": 1.23, "string": "Booga"}"#
                        .to_string(),
                ),
            },
        };

        let json = subject.new_marshal_to_ui(ui_msg);

        let ui_msg = subject
            .new_unmarshal_to_ui(&json, MessageTarget::ClientId(1234))
            .unwrap();
        assert_eq!(ui_msg.target, MessageTarget::ClientId(1234));
        assert_eq!(ui_msg.body.opcode, "opcode".to_string());
        assert_eq!(ui_msg.body.path, TwoWay(2222));
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
        let subject = UiTrafficConverterReal::new();
        let ui_msg = NewFromUiMessage {
            client_id: 4321,
            body: MessageBody {
                opcode: "opcode".to_string(),
                path: TwoWay(2222),
                payload: Err((4567, "Moron".to_string())),
            },
        };

        let json = subject.new_marshal_from_ui(ui_msg);

        let ui_msg = subject.new_unmarshal_from_ui(&json, 1234).unwrap();
        assert_eq!(ui_msg.client_id, 1234);
        assert_eq!(ui_msg.body.opcode, "opcode".to_string());
        assert_eq!(ui_msg.body.path, TwoWay(2222));
        assert_eq!(
            ui_msg.body.payload.err().unwrap(),
            (4567, "Moron".to_string())
        );
    }

    #[test]
    fn new_marshaling_and_unmarshaling_works_to_ui_two_way_for_failure() {
        let subject = UiTrafficConverterReal::new();
        let ui_msg = NewToUiMessage {
            target: MessageTarget::ClientId(4321),
            body: MessageBody {
                opcode: "opcode".to_string(),
                path: TwoWay(2222),
                payload: Err((4567, "Moron".to_string())),
            },
        };

        let json = subject.new_marshal_to_ui(ui_msg);

        let ui_msg = subject
            .new_unmarshal_to_ui(&json, MessageTarget::ClientId(1234))
            .unwrap();
        assert_eq!(ui_msg.target, MessageTarget::ClientId(1234));
        assert_eq!(ui_msg.body.opcode, "opcode".to_string());
        assert_eq!(ui_msg.body.path, TwoWay(2222));
        assert_eq!(
            ui_msg.body.payload.err().unwrap(),
            (4567, "Moron".to_string())
        );
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

        assert_eq!(
            result,
            Err("Neither payload nor error field is present".to_string())
        )
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
    fn new_unmarshaling_handles_badly_typed_error() {
        let subject = UiTrafficConverterReal::new();
        let json = r#"{"opcode": "whomp", "error": 1}"#;

        let result = subject.new_unmarshal_to_ui(json, MessageTarget::ClientId(1234));

        assert_eq!(
            result,
            Err("error should have been of type Value::Object, not Number(1)".to_string())
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

    #[test]
    fn reject_error_from_ui_handles_one_way_success() {
        let logger = Logger::new("reject_error_from_ui_handles_one_way_success");
        let msg = NewFromUiMessage {
            client_id: 1234,
            body: MessageBody {
                opcode: "booga".to_string(),
                path: OneWay,
                payload: Ok("{}".to_string()),
            },
        };
        let subject = UiTrafficConverterReal::new();

        let result = subject.reject_error_from_ui(&logger, &msg, None);

        assert_eq!(result, Ok("{}".to_string()));
    }

    #[test]
    fn reject_error_from_ui_handles_one_way_failure() {
        init_test_logging();
        let logger = Logger::new("reject_error_from_ui_handles_one_way_failure");
        let msg = NewFromUiMessage {
            client_id: 1234,
            body: MessageBody {
                opcode: "booga".to_string(),
                path: OneWay,
                payload: Err((2345, "goober".to_string())),
            },
        };
        let subject = UiTrafficConverterReal::new();

        let result = subject.reject_error_from_ui(&logger, &msg, None);

        let expected_msg =
            "Unexpected error request from client 1234 for 'booga' (2345: goober) - discarding"
                .to_string();
        assert_eq!(result, Err(expected_msg.clone()));
        TestLogHandler::new().exists_log_containing(
            format!(
                "ERROR: reject_error_from_ui_handles_one_way_failure: {}",
                expected_msg
            )
            .as_str(),
        );
    }

    #[test]
    fn reject_error_from_ui_handles_two_way_success() {
        let logger = Logger::new("reject_error_from_ui_handles_two_way_success");
        let msg = NewFromUiMessage {
            client_id: 1234,
            body: MessageBody {
                opcode: "booga".to_string(),
                path: TwoWay(4321),
                payload: Ok("{}".to_string()),
            },
        };
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let subject = UiTrafficConverterReal::new();
        let system = System::new("test");
        let ui_gateway_sub = ui_gateway.start().recipient::<NewToUiMessage>();

        let result = subject.reject_error_from_ui(&logger, &msg, Some(&ui_gateway_sub));

        System::current().stop();
        system.run();
        assert_eq!(result, Ok("{}".to_string()));
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(ui_gateway_recording.len(), 0);
    }

    #[test]
    fn reject_error_from_ui_handles_two_way_failure() {
        init_test_logging();
        let logger = Logger::new("reject_error_from_ui_handles_one_way_failure");
        let msg = NewFromUiMessage {
            client_id: 1234,
            body: MessageBody {
                opcode: "booga".to_string(),
                path: TwoWay(4321),
                payload: Err((2345, "goober".to_string())),
            },
        };
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let subject = UiTrafficConverterReal::new();
        let system = System::new("test");
        let ui_gateway_sub = ui_gateway.start().recipient::<NewToUiMessage>();

        let result = subject.reject_error_from_ui(&logger, &msg, Some(&ui_gateway_sub));

        System::current().stop();
        system.run();
        let expected_msg_prefix =
            "Unexpected error request from client 1234 for 'booga' (2345: goober)".to_string();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(
            ui_gateway_recording.get_record::<NewToUiMessage>(0),
            &NewToUiMessage {
                target: ClientId(1234),
                body: MessageBody {
                    opcode: "booga".to_string(),
                    path: TwoWay(4321),
                    payload: Err((UNEXPECTED_ERROR_REQUEST_CODE, expected_msg_prefix.clone()))
                }
            }
        );
        let expected_msg = format!(
            "{} - complaining to sender with context 4321",
            expected_msg_prefix
        );
        assert_eq!(result, Err(expected_msg.clone()));
        TestLogHandler::new().exists_log_containing(
            format!(
                "ERROR: reject_error_from_ui_handles_one_way_failure: {}",
                expected_msg
            )
            .as_str(),
        );
    }

    #[test]
    fn reject_error_to_ui_handles_one_way_success() {
        let logger = Logger::new("reject_error_to_ui_handles_one_way_success");
        let msg = NewToUiMessage {
            target: ClientId(4444), // irrelevant
            body: MessageBody {
                opcode: "booga".to_string(),
                path: OneWay,
                payload: Ok("{}".to_string()),
            },
        };
        let subject = UiTrafficConverterReal::new();

        let result = subject.reject_error_to_ui(&logger, &msg, None);

        assert_eq!(result, Ok("{}".to_string()));
    }

    #[test]
    fn reject_error_to_ui_handles_one_way_failure() {
        init_test_logging();
        let logger = Logger::new("reject_error_to_ui_handles_one_way_failure");
        let msg = NewToUiMessage {
            target: AllClients, // irrelevant
            body: MessageBody {
                opcode: "booga".to_string(),
                path: OneWay,
                payload: Err((2345, "goober".to_string())),
            },
        };
        let subject = UiTrafficConverterReal::new();

        let result = subject.reject_error_to_ui(&logger, &msg, None);

        let expected_msg =
            "Unexpected error request from server for 'booga' (2345: goober) - discarding"
                .to_string();
        assert_eq!(result, Err(expected_msg.clone()));
        TestLogHandler::new().exists_log_containing(
            format!(
                "ERROR: reject_error_to_ui_handles_one_way_failure: {}",
                expected_msg
            )
            .as_str(),
        );
    }

    #[test]
    fn reject_error_to_ui_handles_two_way_success() {
        let logger = Logger::new("reject_error_to_ui_handles_two_way_success");
        let msg = NewToUiMessage {
            target: AllClients, // irrelevant
            body: MessageBody {
                opcode: "booga".to_string(),
                path: TwoWay(4321),
                payload: Ok("{}".to_string()),
            },
        };
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let subject = UiTrafficConverterReal::new();
        let system = System::new("test");
        let ui_gateway_sub = ui_gateway.start().recipient::<NewFromUiMessage>();

        let result = subject.reject_error_to_ui(&logger, &msg, Some(&ui_gateway_sub));

        System::current().stop();
        system.run();
        assert_eq!(result, Ok("{}".to_string()));
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(ui_gateway_recording.len(), 0);
    }

    #[test]
    fn reject_error_to_ui_handles_two_way_failure_with_sub_specified() {
        init_test_logging();
        let logger = Logger::new("reject_error_to_ui_handles_two_way_failure_with_sub_specified");
        let msg = NewToUiMessage {
            target: ClientId(4444), // irrelevant
            body: MessageBody {
                opcode: "booga".to_string(),
                path: TwoWay(4321),
                payload: Err((2345, "goober".to_string())),
            },
        };
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let subject = UiTrafficConverterReal::new();
        let system = System::new("test");
        let ui_gateway_sub = ui_gateway.start().recipient::<NewFromUiMessage>();

        let result = subject.reject_error_to_ui(&logger, &msg, Some(&ui_gateway_sub));

        System::current().stop();
        system.run();
        let expected_msg_prefix =
            "Unexpected error request from server for 'booga' (2345: goober)".to_string();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(
            ui_gateway_recording.get_record::<NewFromUiMessage>(0),
            &NewFromUiMessage {
                client_id: 0, // irrelevant
                body: MessageBody {
                    opcode: "booga".to_string(),
                    path: TwoWay(4321),
                    payload: Err((UNEXPECTED_ERROR_REQUEST_CODE, expected_msg_prefix.clone()))
                }
            }
        );
        let expected_msg = format!(
            "{} - complaining to sender with context 4321",
            expected_msg_prefix
        );
        assert_eq!(result, Err(expected_msg.clone()));
        TestLogHandler::new().exists_log_containing(
            format!(
                "ERROR: reject_error_to_ui_handles_two_way_failure_with_sub_specified: {}",
                expected_msg
            )
            .as_str(),
        );
    }

    #[test]
    fn reject_error_to_ui_handles_two_way_failure_with_sub_unspecified() {
        init_test_logging();
        let logger = Logger::new("reject_error_to_ui_handles_two_way_failure_with_sub_unspecified");
        let msg = NewToUiMessage {
            target: ClientId(4444), // irrelevant
            body: MessageBody {
                opcode: "booga".to_string(),
                path: TwoWay(4321),
                payload: Err((2345, "goober".to_string())),
            },
        };
        let subject = UiTrafficConverterReal::new();

        let result = subject.reject_error_to_ui(&logger, &msg, None);

        let expected_msg_prefix =
            "Unexpected error request from server for 'booga' (2345: goober)".to_string();
        let expected_msg = format!("{} - discarding", expected_msg_prefix);
        assert_eq!(result, Err(expected_msg.clone()));
        TestLogHandler::new().exists_log_containing(
            format!(
                "ERROR: reject_error_to_ui_handles_two_way_failure_with_sub_unspecified: {}",
                expected_msg
            )
            .as_str(),
        );
    }

    #[test]
    fn get_context_id_handles_two_way() {
        let logger = Logger::new("get_context_id_handles_two_way");
        let subject = UiTrafficConverterReal::new();

        let result = subject.get_context_id(
            &logger,
            &MessageBody {
                opcode: "booga".to_string(),
                path: TwoWay(2222),
                payload: Ok("".to_string()),
            },
        );

        assert_eq!(result, Some(2222));
    }

    #[test]
    fn get_context_id_handles_one_way() {
        init_test_logging();
        let logger = Logger::new("get_context_id_handles_one_way");
        let subject = UiTrafficConverterReal::new();

        let result = subject.get_context_id(
            &logger,
            &MessageBody {
                opcode: "booga".to_string(),
                path: OneWay,
                payload: Ok("".to_string()),
            },
        );

        assert_eq!(result, None);
        TestLogHandler::new().exists_log_containing("ERROR: get_context_id_handles_one_way: TwoWay UI message 'booga' was sent as OneWay - discarding");
    }

    #[test]
    fn get_u64_handles_errors() {
        let json = r#"{"bad_u64": -47}"#;
        let map = serde_json::from_str(json).unwrap();

        let result = UiTrafficConverterReal::get_u64(&map, "bad_u64");

        assert_eq!(
            result,
            Err("Cannot convert from JSON to u64: Number(-47)".to_string())
        )
    }
}
