// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::str::FromStr;
use automap_lib::comm_layer::pcp::PcpTransactor;
use automap_lib::comm_layer::pmp::PmpTransactor;
use automap_lib::comm_layer::igdp::IgdpTransactor;
use automap_lib::comm_layer::Transactor;
use masq_lib::utils::{find_free_port};
use std::time::{Instant, Duration};

pub fn main() {
    let args = std::env::args().collect::<Vec<String>>();
    if args.len() != 2 {
        println! ("Usage: automap <IP address of your router>");
        return
    }
    let ip_string = args[1].as_str();
    let router_ip = match IpAddr::from_str(ip_string) {
        Ok(ip) => ip,
        Err(e) => {
            println!(
                "'{}' is not a properly-formatted IP address: {:?}",
                ip_string, e
            );
            return
        },
    };

    test_pcp(router_ip);
    test_pmp(router_ip);
    test_igdp(router_ip);
}

fn test_pcp (router_ip: IpAddr) {
    println! ("\n====== PCP TESTS ======");
    let transactor = PcpTransactor::default();
    test_common (1, router_ip, Box::new (transactor));
}

fn test_pmp (router_ip: IpAddr) {
    println! ("\n====== PMP TESTS ======");
    let transactor = PmpTransactor::default();
    test_common (1, router_ip, Box::new (transactor));
}

fn test_igdp (router_ip: IpAddr) {
    println! ("\n====== IGDP TESTS ======");
    let transactor = IgdpTransactor::default();
    println! ("1. Looking for routers on the subnet...");
    let timer = Timer::new();
    match transactor.find_routers() {
        Ok (list) => {
            let found_router_ip = list[0];
            if found_router_ip == router_ip {
                println! ("...found a router after {} at {}, just like you said.", timer.ms(), found_router_ip);
            }
            else {
                println! ("...found a router after {} at {}, but you said I'd find it at {}.", timer.ms(), found_router_ip, router_ip);
            }
        },
        Err (e) => println! ("...failed after {}: {:?}", timer.ms(), e),
    }
    test_common (2, router_ip, Box::new (transactor));
}

fn test_common (mut step: usize, router_ip: IpAddr, transactor: Box<dyn Transactor>) {
    println! ("{}. Seeking public IP address...", step);
    step += 1;
    let timer = Timer::new();
    match transactor.get_public_ip(router_ip) {
        Ok (public_ip) => println! ("...found after {}: {}  Is that correct? (Maybe don't publish this without redacting it?)", timer.ms(), public_ip),
        Err (e) => println! ("...failed after {}: {:?}", timer.ms(), e),
    }
    let port = find_free_port();
    let _socket = match UdpSocket::bind (SocketAddr::new (IpAddr::V4(Ipv4Addr::new (0, 0, 0, 0)), port)) {
        Ok (s) => s,
        Err (e) => {
            println! ("Failed to open local port {}; giving up. ({:?})", port, e);
            return
        }
    };
    println! ("{}. Poking a 3-second hole in the firewall for port {}...", step, port);
    step += 1;
    let timer = Timer::new();
    match transactor.add_mapping (router_ip, port, 5) {
        Ok (delay) => println! ("...success after {}! Recommended remap delay is {} seconds.", timer.ms(), delay),
        Err (e) => {
            println! ("...failed after {}: {:?}", timer.ms(), e);
            return
        },
    }
    println! ("{}. Removing the port-{} hole in the firewall...", step, port);
    let timer = Timer::new();
    match transactor.delete_mapping (router_ip, port) {
        Ok (_) => println! ("...success after {}!", timer.ms()),
        Err (e) => println! ("...failed after {}: {:?} (Note: the hole will disappear on its own in a few seconds.)", timer.ms(), e)
    }
}

struct Timer {
    began_at: Instant,
}

impl Timer {
    pub fn new() -> Self {
        Self {
            began_at: Instant::now()
        }
    }

    pub fn stop(self) -> Duration {
        let ended_at = Instant::now();
        ended_at.duration_since (self.began_at)
    }

    pub fn ms(self) -> String {
        let interval = self.stop();
        format! ("{}ms", interval.as_millis())
    }
}