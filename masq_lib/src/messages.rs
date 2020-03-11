// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use crate::messages::UiMessageError::{DeserializationError, PayloadError, UnexpectedMessage};
use crate::ui_gateway::MessagePath::{OneWay, TwoWay};
use crate::ui_gateway::{MessageBody, MessagePath};
use serde::de::DeserializeOwned;
use serde::export::fmt::Error;
use serde::export::Formatter;
use serde_derive::{Deserialize, Serialize};
use std::fmt;

pub const NODE_UI_PROTOCOL: &str = "MASQNode-UIv2";

pub const NODE_LAUNCH_ERROR: u64 = 0x8000_0000_0000_0001;
pub const NODE_NOT_RUNNING_ERROR: u64 = 0x8000_0000_0000_0002;
pub const NODE_ALREADY_RUNNING_ERROR: u64 = 0x8000_0000_0000_0003;
pub const UNMARSHAL_ERROR: u64 = 0x8000_0000_0000_0004;

#[derive(Clone, Debug, PartialEq)]
pub enum UiMessageError {
    UnexpectedMessage(String, MessagePath),
    PayloadError(u64, String),
    DeserializationError(String),
}

impl fmt::Display for UiMessageError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        match self {
            UnexpectedMessage(opcode, OneWay) => {
                write!(f, "Unexpected one-way message with opcode '{}'", opcode)
            }
            UnexpectedMessage(opcode, TwoWay(context_id)) => write!(
                f,
                "Unexpected two-way message from context {} with opcode '{}'",
                context_id, opcode
            ),
            PayloadError(code, message) => write!(
                f,
                "Daemon or Node complained about your command. Error code {}: {}",
                code, message
            ),
            DeserializationError(message) => write!(
                f,
                "Could not deserialize message from Daemon or Node: {}",
                message
            ),
        }
    }
}

pub trait ToMessageBody: serde::Serialize {
    fn tmb(self, context_id: u64) -> MessageBody;
    fn opcode(&self) -> &str;
    fn is_two_way(&self) -> bool;
}

pub trait FromMessageBody: DeserializeOwned {
    fn fmb(body: MessageBody) -> Result<(Self, u64), UiMessageError>;
}

macro_rules! one_way_message {
    ($message_type: ty, $opcode: expr) => {
        impl ToMessageBody for $message_type {
            fn tmb(self, _irrelevant: u64) -> MessageBody {
                let json = serde_json::to_string(&self).expect("Serialization problem");
                MessageBody {
                    opcode: $opcode.to_string(),
                    path: OneWay,
                    payload: Ok(json),
                }
            }

            fn opcode(&self) -> &str {
                $opcode
            }

            fn is_two_way(&self) -> bool {
                false
            }
        }

        impl FromMessageBody for $message_type {
            fn fmb(body: MessageBody) -> Result<(Self, u64), UiMessageError> {
                if body.opcode != $opcode {
                    return Err(UiMessageError::UnexpectedMessage(body.opcode, body.path));
                };
                let payload = match body.payload {
                    Ok(json) => match serde_json::from_str::<Self>(&json) {
                        Ok(item) => item,
                        Err(e) => return Err(DeserializationError(format!("{:?}", e))),
                    },
                    Err((code, message)) => return Err(PayloadError(code, message)),
                };
                if let TwoWay(_) = body.path {
                    return Err(UiMessageError::UnexpectedMessage(body.opcode, body.path));
                }
                Ok((payload, 0))
            }
        }
    };
}

macro_rules! two_way_message {
    ($message_type: ty, $opcode: expr) => {
        impl ToMessageBody for $message_type {
            fn tmb(self, context_id: u64) -> MessageBody {
                let json = serde_json::to_string(&self).expect("Serialization problem");
                MessageBody {
                    opcode: $opcode.to_string(),
                    path: TwoWay(context_id),
                    payload: Ok(json),
                }
            }

            fn opcode(&self) -> &str {
                $opcode
            }

            fn is_two_way(&self) -> bool {
                true
            }
        }

        impl FromMessageBody for $message_type {
            fn fmb(body: MessageBody) -> Result<(Self, u64), UiMessageError> {
                if body.opcode != $opcode {
                    return Err(UiMessageError::UnexpectedMessage(body.opcode, body.path));
                };
                let payload = match body.payload {
                    Ok(json) => match serde_json::from_str::<Self>(&json) {
                        Ok(item) => item,
                        Err(e) => return Err(DeserializationError(format!("{:?}", e))),
                    },
                    Err((code, message)) => return Err(PayloadError(code, message)),
                };
                let context_id = match body.path {
                    TwoWay(context_id) => context_id,
                    OneWay => {
                        return Err(UiMessageError::UnexpectedMessage(body.opcode, body.path))
                    }
                };
                Ok((payload, context_id))
            }
        }
    };
}

///////////////////////////////////////////////////////////////////////
// These messages are sent only to and/or by the Daemon, not the Node
///////////////////////////////////////////////////////////////////////

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct UiSetupValue {
    pub name: String,
    pub value: String,
}

impl UiSetupValue {
    pub fn new(name: &str, value: &str) -> UiSetupValue {
        UiSetupValue {
            name: name.to_string(),
            value: value.to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct UiSetupRequest {
    pub values: Vec<UiSetupValue>,
}
two_way_message!(UiSetupRequest, "setup");
impl UiSetupRequest {
    pub fn new(pairs: Vec<(&str, &str)>) -> UiSetupRequest {
        UiSetupRequest {
            values: pairs
                .into_iter()
                .map(|(name, value)| UiSetupValue {
                    name: name.to_string(),
                    value: value.to_string(),
                })
                .collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct UiSetupResponse {
    pub running: bool,
    pub values: Vec<UiSetupValue>,
}
two_way_message!(UiSetupResponse, "setup");
impl UiSetupResponse {
    pub fn new(running: bool, pairs: Vec<(&str, &str)>) -> UiSetupResponse {
        UiSetupResponse {
            running,
            values: pairs
                .into_iter()
                .map(|(name, value)| UiSetupValue {
                    name: name.to_string(),
                    value: value.to_string(),
                })
                .collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct UiStartOrder {}
two_way_message!(UiStartOrder, "start");

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct UiStartResponse {
    #[serde(rename = "newProcessId")]
    pub new_process_id: u32,
    #[serde(rename = "redirectUiPort")]
    pub redirect_ui_port: u16,
}
two_way_message!(UiStartResponse, "start");

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct UiRedirect {
    pub port: u16,
    pub opcode: String,
    #[serde(rename = "contextId")]
    pub context_id: Option<u64>,
    pub payload: String,
}
one_way_message!(UiRedirect, "redirect");

///////////////////////////////////////////////////////////////////
// These messages are sent to or by both the Daemon and the Node
///////////////////////////////////////////////////////////////////

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct UiUnmarshalError {
    pub message: String,
    #[serde(rename = "badData")]
    pub bad_data: String,
}
one_way_message!(UiUnmarshalError, "unmarshalError");

///////////////////////////////////////////////////////////////////
// These messages are sent to or by the Node only
///////////////////////////////////////////////////////////////////

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct UiPayableAccount {
    pub wallet: String,
    pub age: u64,
    pub amount: u64,
    #[serde(rename = "pendingTransaction")]
    pub pending_transaction: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct UiReceivableAccount {
    pub wallet: String,
    pub age: u64,
    pub amount: u64,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct UiFinancialsRequest {
    #[serde(rename = "payableMinimumAmount")]
    pub payable_minimum_amount: u64,
    #[serde(rename = "payableMaximumAge")]
    pub payable_maximum_age: u64,
    #[serde(rename = "receivableMinimumAmount")]
    pub receivable_minimum_amount: u64,
    #[serde(rename = "receivableMaximumAge")]
    pub receivable_maximum_age: u64,
}
two_way_message!(UiFinancialsRequest, "financials");

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct UiFinancialsResponse {
    pub payables: Vec<UiPayableAccount>,
    #[serde(rename = "totalPayable")]
    pub total_payable: u64,
    pub receivables: Vec<UiReceivableAccount>,
    #[serde(rename = "totalReceivable")]
    pub total_receivable: u64,
}
two_way_message!(UiFinancialsResponse, "financials");

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct UiShutdownRequest {}
two_way_message!(UiShutdownRequest, "shutdown");

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct UiShutdownResponse {}
two_way_message!(UiShutdownResponse, "shutdown");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::UiMessageError::{DeserializationError, PayloadError, UnexpectedMessage};
    use crate::ui_gateway::MessagePath::{OneWay, TwoWay};

    #[test]
    fn ui_message_errors_are_displayable() {
        assert_eq!(
            UnexpectedMessage("opcode".to_string(), OneWay).to_string(),
            "Unexpected one-way message with opcode 'opcode'".to_string()
        );
        assert_eq!(
            UnexpectedMessage("opcode".to_string(), TwoWay(1234)).to_string(),
            "Unexpected two-way message from context 1234 with opcode 'opcode'".to_string()
        );
        assert_eq!(
            PayloadError(1234, "Booga booga".to_string()).to_string(),
            "Daemon or Node complained about your command. Error code 1234: Booga booga"
                .to_string()
        );
        assert_eq!(
            DeserializationError("Booga booga".to_string()).to_string(),
            "Could not deserialize message from Daemon or Node: Booga booga".to_string()
        );
    }

    #[test]
    fn ui_financials_methods_were_correctly_generated() {
        let subject = UiFinancialsResponse {
            payables: vec![],
            total_payable: 0,
            receivables: vec![],
            total_receivable: 0,
        };

        assert_eq!(subject.opcode(), "financials");
        assert_eq!(subject.is_two_way(), true);
    }

    #[test]
    fn can_serialize_ui_financials_response() {
        let subject = UiFinancialsResponse {
            payables: vec![UiPayableAccount {
                wallet: "wallet".to_string(),
                age: 3456,
                amount: 4567,
                pending_transaction: Some("5678".to_string()),
            }],
            total_payable: 1234,
            receivables: vec![UiReceivableAccount {
                wallet: "tellaw".to_string(),
                age: 6789,
                amount: 7890,
            }],
            total_receivable: 2345,
        };
        let subject_json = serde_json::to_string(&subject).unwrap();

        let result: MessageBody = UiFinancialsResponse::tmb(subject, 1357);

        assert_eq!(
            result,
            MessageBody {
                opcode: "financials".to_string(),
                path: TwoWay(1357),
                payload: Ok(subject_json)
            }
        );
    }

    #[test]
    fn can_deserialize_ui_financials_response_with_bad_opcode() {
        let json = r#"
            {
                "payables": [],
                "totalPayable": 1234,
                "receivables": [],
                "totalReceivable": 2345
            }
        "#
        .to_string();
        let message_body = MessageBody {
            opcode: "booga".to_string(),
            path: TwoWay(1234),
            payload: Ok(json),
        };

        let result: Result<(UiFinancialsResponse, u64), UiMessageError> =
            UiFinancialsResponse::fmb(message_body);

        assert_eq!(
            result,
            Err(UnexpectedMessage("booga".to_string(), TwoWay(1234)))
        )
    }

    #[test]
    fn can_deserialize_ui_financials_response_with_bad_path() {
        let json = r#"
            {
                "payables": [],
                "totalPayable": 1234,
                "receivables": [],
                "totalReceivable": 2345
            }
        "#
        .to_string();
        let message_body = MessageBody {
            opcode: "financials".to_string(),
            path: OneWay,
            payload: Ok(json),
        };

        let result: Result<(UiFinancialsResponse, u64), UiMessageError> =
            UiFinancialsResponse::fmb(message_body);

        assert_eq!(
            result,
            Err(UnexpectedMessage("financials".to_string(), OneWay))
        )
    }

    #[test]
    fn can_deserialize_ui_financials_response_with_bad_payload() {
        let message_body = MessageBody {
            opcode: "financials".to_string(),
            path: TwoWay(1234),
            payload: Err((100, "error".to_string())),
        };

        let result: Result<(UiFinancialsResponse, u64), UiMessageError> =
            UiFinancialsResponse::fmb(message_body);

        assert_eq!(result, Err(PayloadError(100, "error".to_string())))
    }

    #[test]
    fn can_deserialize_unparseable_ui_financials_response() {
        let json = "} - unparseable - {".to_string();
        let message_body = MessageBody {
            opcode: "financials".to_string(),
            path: TwoWay(1234),
            payload: Ok(json),
        };

        let result: Result<(UiFinancialsResponse, u64), UiMessageError> =
            UiFinancialsResponse::fmb(message_body);

        assert_eq!(
            result,
            Err(DeserializationError(
                "Error(\"expected value\", line: 1, column: 1)".to_string()
            ))
        )
    }

    #[test]
    fn can_deserialize_ui_financials_response() {
        let json = r#"
            {
                "payables": [{
                    "wallet": "wallet",
                    "age": 3456,
                    "amount": 4567,
                    "pendingTransaction": "transaction"
                }],
                "totalPayable": 1234,
                "receivables": [{
                    "wallet": "tellaw",
                    "age": 6789,
                    "amount": 7890
                }],
                "totalReceivable": 2345
            }
        "#
        .to_string();
        let message_body = MessageBody {
            opcode: "financials".to_string(),
            path: TwoWay(4321),
            payload: Ok(json),
        };

        let result: Result<(UiFinancialsResponse, u64), UiMessageError> =
            UiFinancialsResponse::fmb(message_body);

        assert_eq!(
            result,
            Ok((
                UiFinancialsResponse {
                    payables: vec![UiPayableAccount {
                        wallet: "wallet".to_string(),
                        age: 3456,
                        amount: 4567,
                        pending_transaction: Some("transaction".to_string())
                    }],
                    total_payable: 1234,
                    receivables: vec![UiReceivableAccount {
                        wallet: "tellaw".to_string(),
                        age: 6789,
                        amount: 7890
                    }],
                    total_receivable: 2345
                },
                4321
            ))
        );
    }

    #[test]
    fn ui_unmarshal_error_methods_were_correctly_generated() {
        let subject = UiUnmarshalError {
            message: "".to_string(),
            bad_data: "".to_string(),
        };

        assert_eq!(subject.opcode(), "unmarshalError");
        assert_eq!(subject.is_two_way(), false);
    }

    #[test]
    fn can_serialize_ui_unmarshal_error() {
        let subject = UiUnmarshalError {
            message: "message".to_string(),
            bad_data: "bad_data".to_string(),
        };
        let subject_json = serde_json::to_string(&subject).unwrap();

        let result: MessageBody = subject.tmb(1357);

        assert_eq!(
            result,
            MessageBody {
                opcode: "unmarshalError".to_string(),
                path: OneWay,
                payload: Ok(subject_json)
            }
        );
    }

    #[test]
    fn can_deserialize_ui_unmarshal_error_with_bad_opcode() {
        let json = "{}".to_string();
        let message_body = MessageBody {
            opcode: "booga".to_string(),
            path: OneWay,
            payload: Ok(json),
        };

        let result: Result<(UiUnmarshalError, u64), UiMessageError> =
            UiUnmarshalError::fmb(message_body);

        assert_eq!(result, Err(UnexpectedMessage("booga".to_string(), OneWay)))
    }

    #[test]
    fn can_deserialize_ui_unmarshal_error_with_bad_path() {
        let json = r#"{"message": "message", "badData": "{\"name\": 4}"}"#.to_string();
        let message_body = MessageBody {
            opcode: "unmarshalError".to_string(),
            path: TwoWay(0),
            payload: Ok(json),
        };

        let result: Result<(UiUnmarshalError, u64), UiMessageError> =
            UiUnmarshalError::fmb(message_body);

        assert_eq!(
            result,
            Err(UnexpectedMessage("unmarshalError".to_string(), TwoWay(0)))
        )
    }

    #[test]
    fn can_deserialize_ui_unmarshal_error_with_bad_payload() {
        let message_body = MessageBody {
            opcode: "unmarshalError".to_string(),
            path: OneWay,
            payload: Err((100, "error".to_string())),
        };

        let result: Result<(UiUnmarshalError, u64), UiMessageError> =
            UiUnmarshalError::fmb(message_body);

        assert_eq!(result, Err(PayloadError(100, "error".to_string())))
    }

    #[test]
    fn can_deserialize_unparseable_ui_unmarshal_error() {
        let json = "} - unparseable - {".to_string();
        let message_body = MessageBody {
            opcode: "unmarshalError".to_string(),
            path: OneWay,
            payload: Ok(json),
        };

        let result: Result<(UiUnmarshalError, u64), UiMessageError> =
            UiUnmarshalError::fmb(message_body);

        assert_eq!(
            result,
            Err(DeserializationError(
                "Error(\"expected value\", line: 1, column: 1)".to_string()
            ))
        )
    }

    #[test]
    fn can_deserialize_ui_unmarshal_error() {
        let json = r#"{"message": "message", "badData": "{}"}"#.to_string();
        let message_body = MessageBody {
            opcode: "unmarshalError".to_string(),
            path: OneWay,
            payload: Ok(json),
        };

        let result: Result<(UiUnmarshalError, u64), UiMessageError> =
            UiUnmarshalError::fmb(message_body);

        assert_eq!(
            result,
            Ok((
                UiUnmarshalError {
                    message: "message".to_string(),
                    bad_data: "{}".to_string()
                },
                0
            ))
        );
    }
}
