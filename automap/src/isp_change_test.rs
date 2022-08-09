// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use automap_lib::control_layer::automap_control::{
    AutomapChange, AutomapControl, AutomapControlReal,
};
use std::thread;
use std::time::Duration;

pub fn new_main() {
    let mut control = AutomapControlReal::new(None, Box::new(change_handler));
    let ip_addr = match control.get_public_ip() {
        Ok(ip_addr) => ip_addr,
        Err(e) => {
            eprintln!("Couldn't get external IP address: {:?}", e);
            return;
        }
    };
    eprintln!("External IP address: {:?}", ip_addr);
    eprint!("Waiting for a change from the ISP...");
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}

fn change_handler(change: AutomapChange) {
    match change {
        AutomapChange::Error(e) => eprintln!("\nError: {:?}", e),
        AutomapChange::NewIp(ip) => eprintln!("\nISP changed IP address to {:?}!", ip),
    }
}
