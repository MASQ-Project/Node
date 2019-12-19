// Copyright (c) 2019, MASQ (https://masq.ai). All rights reserved.


use crate::sub_lib::ui_gateway::MessageBody;
use serde_derive::{Serialize, Deserialize};
use crate::sub_lib::ui_gateway::MessagePath::{OneWay, TwoWay};
use crate::ui_gateway::messages::UiMessageError::{DeserializationError, BadOpcode, PayloadError, BadPath};
use serde::de::DeserializeOwned;

#[derive(Clone, Debug, PartialEq)]
pub enum UiMessageError {
    BadOpcode,
    BadPath,
    PayloadError(u64, String),
    DeserializationError(String),
}

pub trait ToMessageBody: serde::Serialize {
    fn tmb(self, context_id: u64) -> MessageBody;
}

pub trait FromMessageBody: DeserializeOwned {
    fn fmb(body: MessageBody) -> Result<(Self, u64), UiMessageError>;
}

macro_rules! one_way_message {
    ($message_type: ty, $opcode: expr) => {
        impl ToMessageBody for $message_type {
            fn tmb(self, _irrelevant: u64) -> MessageBody {
                let json = serde_json::to_string(&self).expect ("Serialization problem");
                MessageBody {
                    opcode: $opcode.to_string(),
                    path: OneWay,
                    payload: Ok(json)
                }
            }
        }

        impl FromMessageBody for $message_type {
            fn fmb(body: MessageBody) -> Result<(Self, u64), UiMessageError> {
                if body.opcode != $opcode {
                    return Err(BadOpcode)
                };
                let payload = match body.payload {
                    Ok(json) => match serde_json::from_str::<Self>(&json) {
                        Ok(item) => item,
                        Err(e) => return Err(DeserializationError(format!("{:?}", e))),
                    },
                    Err((code, message)) => return Err(PayloadError(code, message)),
                };
                if let TwoWay(_) = body.path {
                    return Err(BadPath)
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
                let json = serde_json::to_string(&self).expect ("Serialization problem");
                MessageBody {
                    opcode: $opcode.to_string(),
                    path: TwoWay(context_id),
                    payload: Ok(json)
                }
            }
        }

        impl FromMessageBody for $message_type {
            fn fmb(body: MessageBody) -> Result<(Self, u64), UiMessageError> {
                if body.opcode != $opcode {
                    return Err(BadOpcode)
                };
                let payload = match body.payload {
                    Ok(json) => match serde_json::from_str::<Self>(&json) {
                        Ok(item) => item,
                        Err(e) => return Err(DeserializationError(format!("{:?}", e))),
                    },
                    Err((code, message)) => return Err(PayloadError(code, message)),
                };
                let context_id = match body.path {
                    TwoWay (context_id) => context_id,
                    OneWay => return Err(BadPath),
                };
                Ok((payload, context_id))
            }
        }
    };
}

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

#[derive(Serialize, Deserialize, Debug, PartialEq)]
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

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct UiSetupValue {
    pub name: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct UiSetup {
    pub values: Vec<UiSetupValue>
}
two_way_message!(UiSetup, "setup");
impl UiSetup {
    pub fn new (pairs: Vec<(&str, &str)>) -> UiSetup {
        UiSetup{
            values: pairs.into_iter().map(|(name, value)| UiSetupValue{name: name.to_string(), value: value.to_string()}).collect()
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct UiStartOrder {}
two_way_message!(UiStartOrder, "start");

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct UiStartResponse {
    pub descriptor: String,
    #[serde(rename = "logFile")]
    pub log_file: String,
    #[serde(rename = "newProcessId")]
    pub new_process_id: i32,
    #[serde(rename = "redirectUiPort")]
    pub redirect_ui_port: u16,
}
two_way_message!(UiStartResponse, "start");

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct UiShutdownOrder {}
one_way_message!(UiShutdownOrder, "shutdownOrder");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::ui_gateway::MessagePath::{TwoWay, OneWay};
    use crate::ui_gateway::messages::UiMessageError::{DeserializationError, BadOpcode, PayloadError, BadPath};

    #[test]
    fn can_serialize_ui_financials_response() {
        let subject = UiFinancialsResponse{
            payables: vec![
                UiPayableAccount {
                    wallet: "wallet".to_string(),
                    age: 3456,
                    amount: 4567,
                    pending_transaction: Some("5678".to_string())
                }
            ],
            total_payable: 1234,
            receivables: vec![
                UiReceivableAccount {
                    wallet: "tellaw".to_string(),
                    age: 6789,
                    amount: 7890
                }
            ],
            total_receivable: 2345,
        };
        let subject_json = serde_json::to_string (&subject).unwrap();

        let result: MessageBody = UiFinancialsResponse::tmb(subject, 1357);

        assert_eq! (result, MessageBody {
            opcode: "financials".to_string(),
            path: TwoWay(1357),
            payload: Ok(subject_json)
        });
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
        "#.to_string();
        let message_body = MessageBody {
            opcode: "booga".to_string(),
            path: TwoWay(1234),
            payload: Ok(json)
        };

        let result: Result<(UiFinancialsResponse, u64), UiMessageError> = UiFinancialsResponse::fmb(message_body);

        assert_eq! (result, Err(BadOpcode))
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
        "#.to_string();
        let message_body = MessageBody {
            opcode: "financials".to_string(),
            path: OneWay,
            payload: Ok(json)
        };

        let result: Result<(UiFinancialsResponse, u64), UiMessageError> = UiFinancialsResponse::fmb(message_body);

        assert_eq! (result, Err(BadPath))
    }

    #[test]
    fn can_deserialize_ui_financials_response_with_bad_payload() {
        let message_body = MessageBody {
            opcode: "financials".to_string(),
            path: TwoWay(1234),
            payload: Err((100, "error".to_string()))
        };

        let result: Result<(UiFinancialsResponse, u64), UiMessageError> = UiFinancialsResponse::fmb(message_body);

        assert_eq! (result, Err(PayloadError(100, "error".to_string())))
    }

    #[test]
    fn can_deserialize_unparseable_ui_financials_response() {
        let json = "} - unparseable - {".to_string();
        let message_body = MessageBody {
            opcode: "financials".to_string(),
            path: TwoWay(1234),
            payload: Ok(json)
        };

        let result: Result<(UiFinancialsResponse, u64), UiMessageError> = UiFinancialsResponse::fmb(message_body);

        assert_eq! (result, Err(DeserializationError("Error(\"expected value\", line: 1, column: 1)".to_string())))
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
        "#.to_string();
        let message_body = MessageBody {
            opcode: "financials".to_string(),
            path: TwoWay(4321),
            payload: Ok(json)
        };

        let result: Result<(UiFinancialsResponse, u64), UiMessageError> = UiFinancialsResponse::fmb(message_body);

        assert_eq! (result, Ok((
            UiFinancialsResponse {
                payables: vec![
                    UiPayableAccount {
                        wallet: "wallet".to_string(),
                        age: 3456,
                        amount: 4567,
                        pending_transaction: Some("transaction".to_string())
                    }
                ],
                total_payable: 1234,
                receivables: vec![
                    UiReceivableAccount {
                        wallet: "tellaw".to_string(),
                        age: 6789,
                        amount: 7890
                    }
                ],
                total_receivable: 2345
            },
            4321
        )));
    }

    #[test]
    fn can_serialize_ui_shutdown_order() {
        let subject = UiShutdownOrder{};
        let subject_json = serde_json::to_string (&subject).unwrap();

        let result: MessageBody = subject.tmb(1357);

        assert_eq! (result, MessageBody {
            opcode: "shutdownOrder".to_string(),
            path: OneWay,
            payload: Ok(subject_json)
        });
    }

    #[test]
    fn can_deserialize_ui_shutdown_order_with_bad_opcode() {
        let json = "{}".to_string();
        let message_body = MessageBody {
            opcode: "booga".to_string(),
            path: OneWay,
            payload: Ok(json)
        };

        let result: Result<(UiShutdownOrder, u64), UiMessageError> = UiShutdownOrder::fmb(message_body);

        assert_eq! (result, Err(BadOpcode))
    }

    #[test]
    fn can_deserialize_ui_shutdown_order_with_bad_path() {
        let json = "{}".to_string();
        let message_body = MessageBody {
            opcode: "shutdownOrder".to_string(),
            path: TwoWay(0),
            payload: Ok(json)
        };

        let result: Result<(UiShutdownOrder, u64), UiMessageError> = UiShutdownOrder::fmb(message_body);

        assert_eq! (result, Err(BadPath))
    }

    #[test]
    fn can_deserialize_ui_shutdown_order_with_bad_payload() {
        let message_body = MessageBody {
            opcode: "shutdownOrder".to_string(),
            path: OneWay,
            payload: Err((100, "error".to_string()))
        };

        let result: Result<(UiShutdownOrder, u64), UiMessageError> = UiShutdownOrder::fmb(message_body);

        assert_eq! (result, Err(PayloadError(100, "error".to_string())))
    }

    #[test]
    fn can_deserialize_unparseable_ui_shutdown_order() {
        let json = "} - unparseable - {".to_string();
        let message_body = MessageBody {
            opcode: "shutdownOrder".to_string(),
            path: OneWay,
            payload: Ok(json)
        };

        let result: Result<(UiShutdownOrder, u64), UiMessageError> = UiShutdownOrder::fmb(message_body);

        assert_eq! (result, Err(DeserializationError("Error(\"expected value\", line: 1, column: 1)".to_string())))
    }

    #[test]
    fn can_deserialize_ui_shutdown_order() {
        let json = "{}".to_string();
        let message_body = MessageBody {
            opcode: "shutdownOrder".to_string(),
            path: OneWay,
            payload: Ok(json)
        };

        let result: Result<(UiShutdownOrder, u64), UiMessageError> = UiShutdownOrder::fmb(message_body);

        assert_eq! (result, Ok((UiShutdownOrder {}, 0)));
    }
}