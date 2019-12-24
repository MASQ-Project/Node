// Copyright (c) 2019, MASQ (https://masq.ai). All rights reserved.
#![cfg(not(target_os = "windows"))]

use std::collections::HashMap;
use std::sync::mpsc::Sender;
use crate::test_utils::find_free_port;
use std::iter::FromIterator;
use itertools::Itertools;
use nix::unistd::{ForkResult, fork};
use crate::sub_lib::main_tools::main_with_args;
use crate::daemon::{LaunchSuccess, LaunchError};

pub trait Launcher {
    fn launch(&self, params: HashMap<String, String>) -> Result<LaunchSuccess, LaunchError>;
}

pub struct LauncherReal {
    _sender: Sender<HashMap<String, String>>
}

impl Launcher for LauncherReal {
    fn launch(&self, params: HashMap<String, String>) -> Result<LaunchSuccess, LaunchError> {
        let ui_port = find_free_port();
        let mut actual_params: HashMap<String, String> =
            HashMap::from_iter(params.clone().into_iter());
        actual_params.insert("ui-port".to_string(), format!("{}", ui_port));
        let sorted_params = actual_params
            .into_iter()
            .sorted_by_key(|pair| pair.0.clone())
            .flat_map(|(name, value)| vec![format!("--{}", name), value])
            .collect_vec();
        match fork() {
            Ok(ForkResult::Parent { child, .. }) => Ok(LaunchSuccess {
                new_process_id: child.as_raw(),
                redirect_ui_port: ui_port,
            }),
            Ok(ForkResult::Child) => {
                // TODO: send shutdown message to UiGateway or actor system or whatever
                let exit_code = main_with_args(&sorted_params);
                std::process::exit(exit_code);
            }
            Err(_e) => unimplemented!(),
        }
    }
}

impl LauncherReal {
    pub fn new(sender: Sender<HashMap<String, String>>) -> Self {
        Self {
            _sender: sender
        }
    }
}
