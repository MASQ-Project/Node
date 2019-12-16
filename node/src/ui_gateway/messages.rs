// Copyright (c) 2019, MASQ (https://masq.ai). All rights reserved.


use crate::sub_lib::ui_gateway::MessageBody;
use serde_derive::{Serialize, Deserialize};
use std::convert::TryInto;
use crate::sub_lib::ui_gateway::MessagePath::{OneWay, TwoWay};
use crate::ui_gateway::messages::UiMessageError::{DeserializationError, BadOpcode, BadPayload, BadPath};
use serde::de::DeserializeOwned;
use serde::ser::Serialize;

#[derive(Clone, Debug, PartialEq)]
pub enum UiMessageError {
    BadOpcode,
    BadPath,
    BadPayload,
    DeserializationError(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct DesResult<T: Serialize + DeserializeOwned> {
    pub payload: T,
    pub context_id: u64,
}

impl<T: Serialize + DeserializeOwned> DesResult<T> {
    pub fn new (payload: T, context_id: u64) -> DesResult<T> {
        DesResult {
            payload,
            context_id
        }
    }
}

macro_rules! one_way_message {
    ($message_type: ty, $opcode: expr) => {
        impl From<($message_type, u64)> for MessageBody {
            fn from(pair: ($message_type, u64)) -> Self {
                let json = serde_json::to_string(&pair.0).expect ("Serialization problem");
                MessageBody {
                    opcode: $opcode.to_string(),
                    path: OneWay,
                    payload: Ok(json)
                }
            }
        }

        impl TryInto<DesResult<$message_type>> for MessageBody {
            type Error = UiMessageError;

            fn try_into(self) -> Result<DesResult<$message_type>, UiMessageError> {
                if &self.opcode != $opcode {
                    return Err(BadOpcode)
                };
                let payload = match self.payload {
                    Ok(json) => match serde_json::from_str::<$message_type>(&json) {
                        Ok(item) => item,
                        Err(e) => return Err(DeserializationError(format!("{:?}", e))),
                    },
                    Err(_) => return Err(BadPayload),
                };
                if let TwoWay(_) = self.path {
                    return Err(BadPath)
                }
                Ok(DesResult {payload, context_id: 0})
            }
        }
    };
}

macro_rules! two_way_message {
    ($message_type: ty, $opcode: expr) => {
        impl From<($message_type, u64)> for MessageBody {
            fn from(pair: ($message_type, u64)) -> Self {
                let json = serde_json::to_string(&pair.0).expect ("Serialization problem");
                MessageBody {
                    opcode: $opcode.to_string(),
                    path: TwoWay(pair.1),
                    payload: Ok(json)
                }
            }
        }

        impl TryInto<DesResult<$message_type>> for MessageBody {
            type Error = UiMessageError;

            fn try_into(self) -> Result<DesResult<$message_type>, UiMessageError> {
                if &self.opcode != $opcode {
                    return Err(BadOpcode)
                };
                let payload = match self.payload {
                    Ok(json) => match serde_json::from_str::<$message_type>(&json) {
                        Ok(item) => item,
                        Err(e) => return Err(DeserializationError(format!("{:?}", e))),
                    },
                    Err(_) => return Err(BadPayload),
                };
                let context_id = match self.path {
                    TwoWay (context_id) => context_id,
                    OneWay => return Err(BadPath),
                };
                Ok(DesResult {payload, context_id})
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
pub struct UiShutdownOrder {}
one_way_message!(UiShutdownOrder, "shutdownOrder");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::ui_gateway::MessagePath::{TwoWay, OneWay};
    use crate::ui_gateway::messages::UiMessageError::{DeserializationError, BadOpcode, BadPayload, BadPath};

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

        let result: Result<DesResult<UiFinancialsResponse>, UiMessageError> = message_body.try_into();

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

        let result: Result<DesResult<UiFinancialsResponse>, UiMessageError> = message_body.try_into();

        assert_eq! (result, Err(BadPath))
    }

    #[test]
    fn can_deserialize_ui_financials_response_with_bad_payload() {
        let message_body = MessageBody {
            opcode: "financials".to_string(),
            path: TwoWay(1234),
            payload: Err((100, "error".to_string()))
        };

        let result: Result<DesResult<UiFinancialsResponse>, UiMessageError> = message_body.try_into();

        assert_eq! (result, Err(BadPayload))
    }

    #[test]
    fn can_deserialize_unparseable_ui_financials_response() {
        let json = "} - unparseable - {".to_string();
        let message_body = MessageBody {
            opcode: "financials".to_string(),
            path: TwoWay(1234),
            payload: Ok(json)
        };

        let result: Result<DesResult<UiFinancialsResponse>, UiMessageError> = message_body.try_into();

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

        let result: Result<DesResult<UiFinancialsResponse>, UiMessageError> = message_body.try_into();

        assert_eq! (result, Ok(DesResult::new(
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

        let result: MessageBody = (subject, 1357).into();

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

        let result: Result<DesResult<UiShutdownOrder>, UiMessageError> = message_body.try_into();

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

        let result: Result<DesResult<UiShutdownOrder>, UiMessageError> = message_body.try_into();

        assert_eq! (result, Err(BadPath))
    }

    #[test]
    fn can_deserialize_ui_shutdown_order_with_bad_payload() {
        let message_body = MessageBody {
            opcode: "shutdownOrder".to_string(),
            path: OneWay,
            payload: Err((100, "error".to_string()))
        };

        let result: Result<DesResult<UiShutdownOrder>, UiMessageError> = message_body.try_into();

        assert_eq! (result, Err(BadPayload))
    }

    #[test]
    fn can_deserialize_unparseable_ui_shutdown_order() {
        let json = "} - unparseable - {".to_string();
        let message_body = MessageBody {
            opcode: "shutdownOrder".to_string(),
            path: OneWay,
            payload: Ok(json)
        };

        let result: Result<DesResult<UiShutdownOrder>, UiMessageError> = message_body.try_into();

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

        let result: Result<DesResult<UiShutdownOrder>, UiMessageError> = message_body.try_into();

        assert_eq! (result, Ok(DesResult::new(UiShutdownOrder {}, 0)));
    }
}