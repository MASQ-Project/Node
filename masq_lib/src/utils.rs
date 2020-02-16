// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use lazy_static::lazy_static;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::Mutex;

const FIND_FREE_PORT_LOWEST: u16 = 32768;
const FIND_FREE_PORT_HIGHEST: u16 = 65535;

lazy_static! {
    static ref FIND_FREE_PORT_NEXT: Arc<Mutex<u16>> = Arc::new(Mutex::new(FIND_FREE_PORT_LOWEST));
}

fn next_port(port: u16) -> u16 {
    match port {
        p if p < FIND_FREE_PORT_HIGHEST => p + 1,
        _ => FIND_FREE_PORT_LOWEST,
    }
}

pub fn find_free_port() -> u16 {
    let mut candidate = FIND_FREE_PORT_NEXT.lock().unwrap();
    loop {
        match TcpListener::bind(SocketAddr::new(localhost(), *candidate)) {
            Err(ref e) if e.kind() == ErrorKind::AddrInUse => *candidate = next_port(*candidate),
            Err(e) => panic!("Couldn't find free port: {:?}", e),
            Ok(_listener) => {
                let result = *candidate;
                *candidate = next_port(*candidate);
                return result;
            }
        }
    }
}

pub fn localhost() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}
