// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::marker::Send;
use main_tools::StdStreams;
use tokio::prelude::Future;

pub trait SocketServer: Send + Future<Item=(), Error=()> {
    fn name (&self) -> String;
    fn initialize_as_privileged(&mut self, args: &Vec<String>, streams: &mut StdStreams);
    fn initialize_as_unprivileged(&mut self);
}
