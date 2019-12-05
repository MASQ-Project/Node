// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::sub_lib::accountant::FinancialStatisticsMessage;
use crate::sub_lib::peer_actors::BindMessage;
use actix::Message;
use actix::Recipient;
use serde_derive::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt::{Debug, Formatter};

pub const DEFAULT_UI_PORT: u16 = 5333;

#[derive(Clone, Debug)]
pub struct UiGatewayConfig {
    pub ui_port: u16,
    pub node_descriptor: String,
}

#[derive(Clone)]
pub struct UiGatewaySubs {
    pub bind: Recipient<BindMessage>,
    pub ui_message_sub: Recipient<UiCarrierMessage>,
    pub from_ui_message_sub: Recipient<FromUiMessage>,
    pub new_ui_message_sub: Recipient<NewUiMessage>,
}

impl Debug for UiGatewaySubs {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "UiGatewaySubs")
    }
}

#[derive(Message, Debug, Serialize, Deserialize, PartialEq)]
pub struct UiCarrierMessage {
    pub client_id: u64,
    pub data: UiMessage,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum UiMessage {
    GetFinancialStatisticsMessage,
    FinancialStatisticsResponse(FinancialStatisticsMessage),
    SetGasPrice(String),
    SetGasPriceResponse(bool),
    SetDbPassword(String),
    SetDbPasswordResponse(bool),
    GetNodeDescriptor,
    NodeDescriptor(String),
    NeighborhoodDotGraphRequest,
    NeighborhoodDotGraphResponse(String),
    ShutdownMessage,
}

#[derive(Message, PartialEq, Debug)]
pub struct FromUiMessage {
    pub client_id: u64,
    pub json: String,
}

#[derive(Message, PartialEq, Clone, Debug)]
pub enum MessageDirection {
    ToUi,
    FromUi,
}

#[derive(Message, PartialEq, Clone, Debug)]
pub struct NewUiMessage {
    pub client_id: u64,
    pub opcode: String,
    pub direction: MessageDirection,
    pub data: serde_json::map::Map<String, Value>,
}

pub struct ParseTools {}

impl ParseTools {
    pub fn get_bool_field(map: &serde_json::map::Map<String, Value>, name: &str) -> Option<bool> {
        let value = map.get(name)?;
        match value {
            Value::Bool(v) => Some(*v),
            _ => None,
        }
    }

    pub fn get_number_field(map: &serde_json::map::Map<String, Value>, name: &str) -> Option<f64> {
        let value = map.get(name)?;
        match value {
            Value::Number(v) => Some(v.as_f64()?),
            _ => None,
        }
    }

    pub fn get_string_field(
        map: &serde_json::map::Map<String, Value>,
        name: &str,
    ) -> Option<String> {
        let value = map.get(name)?;
        match value {
            Value::String(v) => Some(v.clone()),
            _ => None,
        }
    }

    pub fn get_array_field<'a>(
        map: &'a serde_json::map::Map<String, Value>,
        name: &str,
    ) -> Option<&'a Vec<Value>> {
        let value = map.get(name)?;
        match value {
            Value::Array(v) => Some(v),
            _ => None,
        }
    }

    pub fn get_object_field<'a>(
        map: &'a serde_json::map::Map<String, Value>,
        name: &str,
    ) -> Option<&'a serde_json::map::Map<String, Value>> {
        let value = map.get(name)?;
        match value {
            Value::Object(v) => Some(v),
            _ => None,
        }
    }

    pub fn get_bool_element(array: &Vec<Value>, index: usize) -> Option<bool> {
        let value = array.get(index)?;
        match value {
            Value::Bool(v) => Some(*v),
            _ => None,
        }
    }

    pub fn get_number_element(array: &Vec<Value>, index: usize) -> Option<f64> {
        let value = array.get(index)?;
        match value {
            Value::Number(v) => Some(v.as_f64()?),
            _ => None,
        }
    }

    pub fn get_string_element(array: &Vec<Value>, index: usize) -> Option<String> {
        let value = array.get(index)?;
        match value {
            Value::String(v) => Some(v.clone()),
            _ => None,
        }
    }

    pub fn get_array_element<'a>(array: &'a Vec<Value>, index: usize) -> Option<&'a Vec<Value>> {
        let value = array.get(index)?;
        match value {
            Value::Array(v) => Some(v),
            _ => None,
        }
    }

    pub fn get_object_element<'a>(
        array: &'a Vec<Value>,
        index: usize,
    ) -> Option<&'a serde_json::map::Map<String, Value>> {
        let value = array.get(index)?;
        match value {
            Value::Object(v) => Some(v),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::peer_actors::BindMessage;
    use crate::sub_lib::ui_gateway::{FromUiMessage, UiCarrierMessage, UiGatewaySubs};
    use crate::test_utils::recorder::Recorder;
    use actix::Actor;
    use serde_json::Number;

    #[test]
    fn ui_gateway_subs_debug() {
        let recorder = Recorder::new().start();

        let subject = UiGatewaySubs {
            bind: recipient!(recorder, BindMessage),
            ui_message_sub: recipient!(recorder, UiCarrierMessage),
            from_ui_message_sub: recipient!(recorder, FromUiMessage),
            new_ui_message_sub: recipient!(recorder, NewUiMessage),
        };

        assert_eq!(format!("{:?}", subject), "UiGatewaySubs");
    }

    #[test]
    fn get_field_handles_missing_value() {
        let map = serde_json::map::Map::new();

        assert_eq!(ParseTools::get_bool_field(&map, "nonexistent"), None);
        assert_eq!(ParseTools::get_number_field(&map, "nonexistent"), None);
        assert_eq!(ParseTools::get_string_field(&map, "nonexistent"), None);
        assert_eq!(ParseTools::get_array_field(&map, "nonexistent"), None);
        assert_eq!(ParseTools::get_object_field(&map, "nonexistent"), None);
    }

    #[test]
    fn get_field_handles_badly_typed_value_but_bool() {
        let mut map = serde_json::map::Map::new();
        map.insert("badlyTyped".to_string(), Value::Bool(true));

        assert_eq!(ParseTools::get_number_field(&map, "badlyTyped"), None);
        assert_eq!(ParseTools::get_string_field(&map, "badlyTyped"), None);
        assert_eq!(ParseTools::get_array_field(&map, "badlyTyped"), None);
        assert_eq!(ParseTools::get_object_field(&map, "badlyTyped"), None);
    }

    #[test]
    fn get_field_handles_badly_typed_value_bool() {
        let mut map = serde_json::map::Map::new();
        map.insert("badlyTyped".to_string(), Value::String("booga".to_string()));

        assert_eq!(ParseTools::get_bool_field(&map, "badlyTyped"), None);
    }

    #[test]
    fn get_bool_field_handles_good_value() {
        let mut map = serde_json::map::Map::new();
        map.insert("bool".to_string(), Value::Bool(true));
        map.insert(
            "number".to_string(),
            Value::Number(Number::from_f64(1.23).unwrap()),
        );
        map.insert("string".to_string(), Value::String("booga".to_string()));
        map.insert(
            "array".to_string(),
            Value::Array(vec![Value::Bool(true), Value::Bool(false)]),
        );
        let mut obj_map = serde_json::map::Map::new();
        obj_map.insert("true".to_string(), Value::Bool(true));
        obj_map.insert("false".to_string(), Value::Bool(false));
        map.insert("object".to_string(), Value::Object(obj_map.clone()));

        assert_eq!(ParseTools::get_bool_field(&map, "bool"), Some(true));
        assert_eq!(ParseTools::get_number_field(&map, "number"), Some(1.23));
        assert_eq!(
            ParseTools::get_string_field(&map, "string"),
            Some("booga".to_string())
        );
        assert_eq!(
            ParseTools::get_array_field(&map, "array"),
            Some(&vec![Value::Bool(true), Value::Bool(false)])
        );
        assert_eq!(ParseTools::get_object_field(&map, "object"), Some(&obj_map));
    }

    #[test]
    fn get_element_handles_missing_value() {
        let array = vec![];

        assert_eq!(ParseTools::get_bool_element(&array, 0), None);
        assert_eq!(ParseTools::get_number_element(&array, 0), None);
        assert_eq!(ParseTools::get_string_element(&array, 0), None);
        assert_eq!(ParseTools::get_array_element(&array, 0), None);
        assert_eq!(ParseTools::get_object_element(&array, 0), None);
    }

    #[test]
    fn get_element_handles_badly_typed_value_but_bool() {
        let mut array = vec![];
        array.push(Value::Bool(true));

        assert_eq!(ParseTools::get_number_element(&array, 0), None);
        assert_eq!(ParseTools::get_string_element(&array, 0), None);
        assert_eq!(ParseTools::get_array_element(&array, 0), None);
        assert_eq!(ParseTools::get_object_element(&array, 0), None);
    }

    #[test]
    fn get_element_handles_badly_typed_value_bool() {
        let mut array = vec![];
        array.push(Value::String("booga".to_string()));

        assert_eq!(ParseTools::get_bool_element(&array, 0), None);
    }

    #[test]
    fn get_bool_element_handles_good_value() {
        let mut array = vec![];
        array.push(Value::Bool(true));
        array.push(Value::Number(Number::from_f64(1.23).unwrap()));
        array.push(Value::String("booga".to_string()));
        array.push(Value::Array(vec![Value::Bool(true), Value::Bool(false)]));
        let mut obj_map = serde_json::map::Map::new();
        obj_map.insert("true".to_string(), Value::Bool(true));
        obj_map.insert("false".to_string(), Value::Bool(false));
        array.push(Value::Object(obj_map.clone()));

        assert_eq!(ParseTools::get_bool_element(&array, 0), Some(true));
        assert_eq!(ParseTools::get_number_element(&array, 1), Some(1.23));
        assert_eq!(
            ParseTools::get_string_element(&array, 2),
            Some("booga".to_string())
        );
        assert_eq!(
            ParseTools::get_array_element(&array, 3),
            Some(&vec![Value::Bool(true), Value::Bool(false)])
        );
        assert_eq!(ParseTools::get_object_element(&array, 4), Some(&obj_map));
    }
}
