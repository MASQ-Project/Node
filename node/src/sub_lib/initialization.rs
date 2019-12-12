// Copyright (c) 2019, MASQ (https://masq.ai). All rights reserved.

use itertools::Itertools;
use serde_derive::{Deserialize, Serialize};

#[derive (Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct UiSetupRequest {
    pub parameters: Vec<UiSetupParameter>
}

impl UiSetupRequest {
    pub fn new (pairs: Vec<(&str, &str)>) -> UiSetupRequest {
        let parameters = pairs.into_iter()
            .map (|(name, value)| UiSetupParameter::new (name, value))
            .collect_vec();
        UiSetupRequest {parameters}
    }
}

#[derive (Serialize, Deserialize, Clone, PartialEq, Debug)]
#[allow(non_snake_case)]
pub struct UiSetupResponse {
    pub redirectUiPort: u16,
    pub newProcessId: i32,
}

#[derive (Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct UiSetupParameter {
    pub name: String,
    pub value: String,
}

impl UiSetupParameter {
    pub fn new(name: &str, value: &str) -> UiSetupParameter {
        UiSetupParameter {
            name: name.to_string(),
            value: value.to_string(),
        }
    }
}
