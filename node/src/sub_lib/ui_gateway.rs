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
    pub new_from_ui_message_sub: Recipient<NewFromUiMessage>,
    pub new_to_ui_message_sub: Recipient<NewToUiMessage>,
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

#[derive(PartialEq, Clone, Debug)]
pub enum MessageTarget {
    ClientId(u64),
    AllClients,
}

#[derive(PartialEq, Clone, Debug)]
pub enum MessagePath {
    OneWay,
    TwoWay(u64), // context_id
}

#[derive(PartialEq, Clone, Debug)]
pub struct MessageBody {
    pub opcode: String,
    pub path: MessagePath,
    pub payload: Result<String, (u64, String)>, // <success payload as JSON, (error code, error message)>
}

#[derive(Message, PartialEq, Clone, Debug)]
pub struct NewFromUiMessage {
    pub client_id: u64,
    pub body: MessageBody,
}

#[derive(Message, PartialEq, Clone, Debug)]
pub struct NewToUiMessage {
    pub target: MessageTarget,
    pub body: MessageBody,
}

#[cfg(test)]
mod tests {
    use super::*;
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
            new_from_ui_message_sub: recipient!(recorder, NewFromUiMessage),
            new_to_ui_message_sub: recipient!(recorder, NewToUiMessage),
        };

        assert_eq!(format!("{:?}", subject), "UiGatewaySubs");
    }
}
