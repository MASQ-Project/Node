// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use dispatcher::Endpoint;
use neighborhood::NodeDescriptor;

#[derive(PartialEq, Debug, Message, Clone)]
pub struct TransmitDataMsg {
    pub endpoint: Endpoint,
    pub last_data: bool,
    pub sequence_number: Option<u64>,
    pub data: Vec<u8>,
}

#[derive(Message, Clone)]
pub struct DispatcherNodeQueryResponse {
    pub result: Option<NodeDescriptor>,
    pub context: TransmitDataMsg,
}
