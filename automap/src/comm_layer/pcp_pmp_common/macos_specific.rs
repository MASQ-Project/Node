// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
#![cfg(target_os = "macos")]

use crate::comm_layer::AutomapError;
use std::net::IpAddr;
use crate::comm_layer::pcp_pmp_common::FindRoutersCommand;

pub fn macos_find_routers(command: &dyn FindRoutersCommand) -> Result<Vec<IpAddr>, AutomapError> {
    unimplemented!()
}

pub struct MacOsFindRoutersCommand {

}

impl FindRoutersCommand for MacOsFindRoutersCommand {
    fn execute(&self) -> Result<String, String> {
        unimplemented!()
    }
}

impl MacOsFindRoutersCommand {
    pub fn new() -> Self {
        Self {}
    }
}

