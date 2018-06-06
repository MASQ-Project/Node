// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use dispatcher::Endpoint;

#[derive (PartialEq, Debug, Message)]
pub struct TransmitDataMsg {
    pub endpoint: Endpoint,
    pub last_data: bool,
    pub data: Vec<u8>
}
