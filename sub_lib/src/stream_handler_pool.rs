// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::io;
use actix::ResponseType;
use dispatcher::Endpoint;

#[derive (PartialEq, Debug)]
pub struct TransmitDataMsg {
    pub endpoint: Endpoint,
    pub last_data: bool,
    pub data: Vec<u8>
}

impl ResponseType for TransmitDataMsg {
    type Item = ();
    type Error = io::Error;
}
