// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::sub_lib::ui_gateway::UiMessage;

#[allow(dead_code)]
pub const BROADCAST: u64 = 0xFFFFFFFFFFFFFFFF;

pub trait UiTrafficConverter {
    fn marshal(&self, ui_message: UiMessage) -> Result<String, String>;
    fn unmarshal(&self, json: &str) -> Result<UiMessage, String>;
}

pub struct UiTrafficConverterReal {}

impl UiTrafficConverter for UiTrafficConverterReal {
    fn marshal(&self, _ui_message: UiMessage) -> Result<String, String> {
        unimplemented!()
    }

    fn unmarshal(&self, _json: &str) -> Result<UiMessage, String> {
        Ok(UiMessage::ShutdownMessage)
    }
}

impl UiTrafficConverterReal {
    #[allow(dead_code)]
    pub fn new() -> UiTrafficConverterReal {
        UiTrafficConverterReal {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_shutdown_message_is_properly_unmarshalled() {
        let subject = UiTrafficConverterReal::new();

        let result = subject.unmarshal("{\"message_type\": \"shutdown\"}");

        assert_eq!(result, Ok(UiMessage::ShutdownMessage));
    }
}
