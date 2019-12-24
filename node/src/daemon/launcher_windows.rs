// Copyright (c) 2019, MASQ (https://masq.ai). All rights reserved.
#![cfg(target_os = "windows")]

use std::collections::HashMap;
use std::sync::mpsc::Sender;
use crate::daemon::{LaunchSuccess, LaunchError};

pub trait Launcher {
    fn launch(&self, params: HashMap<String, String>) -> Result<LaunchSuccess, LaunchError>;
}

pub struct LauncherReal {}

impl Launcher for LauncherReal {
    fn launch(&self, params: HashMap<String, String>) -> Result<LaunchSuccess, LaunchError> {
        unimplemented!()
    }
}

impl LauncherReal {
    // _sender is needed for the not-Windows side; it's not used here
    pub fn new(_sender: Sender<HashMap<String, String>>) -> Self {
        Self {}
    }
}
