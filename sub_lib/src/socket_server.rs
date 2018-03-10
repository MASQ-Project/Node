// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::marker::Send;
use main_tools::StdStreams;

pub trait SocketServer: Send {
    fn name (&self) -> String;
    fn initialize_as_root (&mut self, args: &Vec<String>, streams: &mut StdStreams);
    fn serve_without_root (&mut self);
}
