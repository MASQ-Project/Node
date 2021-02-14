// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::comm_layer::AutomapError;
use std::net::IpAddr;
use crate::comm_layer::pcp_pmp_common::FindRoutersCommand;

#[cfg(target_os = "windows")]

pub fn windows_find_routers(command: &dyn FindRoutersCommand) -> Result<Vec<IpAddr>, AutomapError> {
    unimplemented!()
}

pub struct WindowsFindRoutersCommand {

}

impl FindRoutersCommand for WindowsFindRoutersCommand {
    fn execute(&self) -> Result<String, String> {
        unimplemented!()
    }
}

impl WindowsFindRoutersCommand {
    pub fn new() -> Self {
        Self {}
    }
}
