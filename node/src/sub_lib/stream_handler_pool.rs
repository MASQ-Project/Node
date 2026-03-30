// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::sub_lib::dispatcher::Endpoint;
use crate::sub_lib::neighborhood::NodeQueryResponseMetadata;
use actix::Message;

// This message can be sent either to a neighboring Node or to the client, but not to the server.
#[derive(PartialEq, Eq, Debug, Message, Clone)]
pub struct TransmitDataMsg {
    pub endpoint: Endpoint,
    pub last_data: bool,
    pub sequence_number_opt: Option<u64>, // Some implies clear data; None implies clandestine.
    pub data: Vec<u8>,
}

#[derive(Message, Clone, PartialEq, Eq)]
pub struct DispatcherNodeQueryResponse {
    pub result: Option<NodeQueryResponseMetadata>,
    pub context: TransmitDataMsg,
}
