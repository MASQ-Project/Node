// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::sub_lib::accountant::FinancialStatisticsMessage;
use crate::sub_lib::peer_actors::BindMessage;
use actix::Message;
use actix::Recipient;
use serde_derive::{Deserialize, Serialize};
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
    SetWalletPassword(String),
    SetWalletPasswordResponse(bool),
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

#[cfg(test)]
mod tests {
    use crate::sub_lib::peer_actors::BindMessage;
    use crate::sub_lib::ui_gateway::{FromUiMessage, UiCarrierMessage, UiGatewaySubs};
    use crate::test_utils::recorder::Recorder;
    use actix::Actor;

    #[test]
    fn ui_gateway_subs_debug() {
        let recorder = Recorder::new().start();

        let subject = UiGatewaySubs {
            bind: recipient!(recorder, BindMessage),
            ui_message_sub: recipient!(recorder, UiCarrierMessage),
            from_ui_message_sub: recipient!(recorder, FromUiMessage),
        };

        assert_eq!(format!("{:?}", subject), "UiGatewaySubs");
    }
}
