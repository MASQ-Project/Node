// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::sub_lib::ui_gateway::UiMessage;

#[allow(dead_code)]
pub const BROADCAST: u64 = 0xFFFF_FFFF_FFFF_FFFF;

pub trait UiTrafficConverterOld: Send {
    fn marshal(&self, ui_message: UiMessage) -> Result<String, String>;
    fn unmarshal(&self, json: &str) -> Result<UiMessage, String>;
}

#[derive(Default)]
pub struct UiTrafficConverterOldReal {}

impl UiTrafficConverterOld for UiTrafficConverterOldReal {
    // TODO: After these methods are obsoleted and removed, get rid of the trait and make the
    // remaining methods into static functions, or possibly TryFrom and TryInto implementations for
    // NodeFromUiMessage and NodeToUiMessage.
    fn marshal(&self, ui_message: UiMessage) -> Result<String, String> {
        serde_json::to_string(&ui_message).map_err(|e| e.to_string())
    }

    fn unmarshal(&self, _json: &str) -> Result<UiMessage, String> {
        serde_json::from_str(_json).map_err(|e| e.to_string())
    }
}

impl UiTrafficConverterOldReal {
    pub fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_shutdown_message_is_properly_marshalled_and_unmarshalled() {
        let subject = UiTrafficConverterOldReal::new();

        let marshalled = serde_json::to_string(&UiMessage::ShutdownMessage).unwrap();
        let unmarshalled = subject.unmarshal(&marshalled);

        assert_eq!(unmarshalled, Ok(UiMessage::ShutdownMessage));
    }

    #[test]
    fn a_neighborhood_dot_graph_request_is_properly_marshaled_and_unmarshaled() {
        let subject = UiTrafficConverterOldReal::new();

        let marshaled = serde_json::to_string(&UiMessage::NeighborhoodDotGraphRequest).unwrap();
        let unmarshaled = subject.unmarshal(&marshaled);

        assert_eq!(unmarshaled, Ok(UiMessage::NeighborhoodDotGraphRequest));
    }
}
