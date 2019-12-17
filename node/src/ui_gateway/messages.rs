// Copyright (c) 2019, MASQ (https://masq.ai). All rights reserved.


use crate::sub_lib::ui_gateway::MessageBody;
use serde_derive::{Serialize, Deserialize};
use std::convert::{TryInto};
use crate::sub_lib::ui_gateway::MessagePath::{OneWay, TwoWay};
use crate::ui_gateway::messages::UiMessageError::{DeserializationError, BadOpcode, PayloadError, BadPath};

#[derive(Clone, Debug, PartialEq)]
pub enum UiMessageError {
    BadOpcode,
    BadPath,
    PayloadError(u64, String),
    DeserializationError(String),
}

macro_rules! one_way_message {
    ($message_type: ty, $opcode: expr) => {
        impl From<($message_type, u64)> for MessageBody {
            fn from(pair: ($message_type, u64)) -> MessageBody {
                let json = serde_json::to_string(&pair.0).expect ("Serialization problem");
                MessageBody {
                    opcode: $opcode.to_string(),
                    path: OneWay,
                    payload: Ok(json)
                }
            }
        }

        impl TryInto<($message_type, u64)> for MessageBody {
            type Error = UiMessageError;

            fn try_into(self) -> Result<($message_type, u64), Self::Error> {
                if &self.opcode != $opcode {
                    return Err(BadOpcode)
                };
                let payload = match self.payload {
                    Ok(json) => match serde_json::from_str::<$message_type>(&json) {
                        Ok(item) => item,
                        Err(e) => return Err(DeserializationError(format!("{:?}", e))),
                    },
                    Err((code, message)) => return Err(PayloadError(code, message)),
                };
                if let TwoWay(_) = self.path {
                    return Err(BadPath)
                }
                Ok((payload, 0))
            }
        }
    };
}

macro_rules! two_way_message {
    ($message_type: ty, $opcode: expr) => {
        impl From<($message_type, u64)> for MessageBody {
            fn from(pair: ($message_type, u64)) -> MessageBody {
                let json = serde_json::to_string(&pair.0).expect ("Serialization problem");
                MessageBody {
                    opcode: $opcode.to_string(),
                    path: TwoWay(pair.1),
                    payload: Ok(json)
                }
            }
        }

        impl TryInto<($message_type, u64)> for MessageBody {
            type Error = UiMessageError;

            fn try_into(self) -> Result<($message_type, u64), Self::Error> {
                if &self.opcode != $opcode {
                    return Err(BadOpcode)
                };
                let payload = match self.payload {
                    Ok(json) => match serde_json::from_str::<$message_type>(&json) {
                        Ok(item) => item,
                        Err(e) => return Err(DeserializationError(format!("{:?}", e))),
                    },
                    Err((code, message)) => return Err(PayloadError(code, message)),
                };
                let context_id = match self.path {
                    TwoWay (context_id) => context_id,
                    OneWay => return Err(BadPath),
                };
                Ok((payload, context_id))
            }
        }
    };
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[allow(non_snake_case)]
pub struct UiPayableAccount {
    pub wallet: String,
    pub age: u64,
    pub amount: u64,
    pub pendingTransaction: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct UiReceivableAccount {
    pub wallet: String,
    pub age: u64,
    pub amount: u64,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[allow(non_snake_case)]
pub struct UiFinancialsRequest {
    pub payableMinimumAmount: u64,
    pub payableMaximumAge: u64,
    pub receivableMinimumAmount: u64,
    pub receivableMaximumAge: u64,
}
two_way_message!(UiFinancialsRequest, "financials");

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[allow(non_snake_case)]
pub struct UiFinancialsResponse {
    pub payables: Vec<UiPayableAccount>,
    pub totalPayable: u64,
    pub receivables: Vec<UiReceivableAccount>,
    pub totalReceivable: u64,
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
#[allow(non_snake_case)]
pub struct UiStartResponse {
    pub descriptor: String,
    pub logFile: String,
    pub newProcessId: i32,
    pub redirectUiPort: u16,
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
                    pendingTransaction: Some("5678".to_string())
                }
            ],
            totalPayable: 1234,
            receivables: vec![
                UiReceivableAccount {
                    wallet: "tellaw".to_string(),
                    age: 6789,
                    amount: 7890
                }
            ],
            totalReceivable: 2345,
        };
        let subject_json = serde_json::to_string (&subject).unwrap();

        let result: MessageBody = (subject, 1357).into();

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

        let result: Result<(UiFinancialsResponse, u64), UiMessageError> = message_body.try_into();

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

        let result: Result<(UiFinancialsResponse, u64), UiMessageError> = message_body.try_into();

        assert_eq! (result, Err(BadPath))
    }

    #[test]
    fn can_deserialize_ui_financials_response_with_bad_payload() {
        let message_body = MessageBody {
            opcode: "financials".to_string(),
            path: TwoWay(1234),
            payload: Err((100, "error".to_string()))
        };

        let result: Result<(UiFinancialsResponse, u64), UiMessageError> = message_body.try_into();

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

        let result: Result<(UiFinancialsResponse, u64), UiMessageError> = message_body.try_into();

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

        let result: Result<(UiFinancialsResponse, u64), UiMessageError> = message_body.try_into();

        assert_eq! (result, Ok((
            UiFinancialsResponse {
                payables: vec![
                    UiPayableAccount {
                        wallet: "wallet".to_string(),
                        age: 3456,
                        amount: 4567,
                        pendingTransaction: Some("transaction".to_string())
                    }
                ],
                totalPayable: 1234,
                receivables: vec![
                    UiReceivableAccount {
                        wallet: "tellaw".to_string(),
                        age: 6789,
                        amount: 7890
                    }
                ],
                totalReceivable: 2345
            },
            4321
        )));
    }

    #[test]
    fn can_serialize_ui_shutdown_order() {
        let subject = UiShutdownOrder{};
        let subject_json = serde_json::to_string (&subject).unwrap();

        let result: MessageBody = MessageBody::from((subject, 1357));

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

        let result: Result<(UiShutdownOrder, u64), UiMessageError> = message_body.try_into();

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

        let result: Result<(UiShutdownOrder, u64), UiMessageError> = message_body.try_into();

        assert_eq! (result, Err(BadPath))
    }

    #[test]
    fn can_deserialize_ui_shutdown_order_with_bad_payload() {
        let message_body = MessageBody {
            opcode: "shutdownOrder".to_string(),
            path: OneWay,
            payload: Err((100, "error".to_string()))
        };

        let result: Result<(UiShutdownOrder, u64), UiMessageError> = message_body.try_into();

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

        let result: Result<(UiShutdownOrder, u64), UiMessageError> = message_body.try_into();

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

        let result: Result<(UiShutdownOrder, u64), UiMessageError> = message_body.try_into();

        assert_eq! (result, Ok((UiShutdownOrder {}, 0)));
    }
}