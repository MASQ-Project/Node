// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use automap_lib::protocols::igdp::igdp_test::test_igdp;
use automap_lib::protocols::pcp::pcp_test::test_pcp;
use automap_lib::protocols::pmp::pmp_test::test_pmp;
use automap_lib::protocols::utils::MAIN_HEADER;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::str::FromStr;

pub fn main() {
    let args = std::env::args().collect::<Vec<String>>();
    if args.len() != 2 {
        let _: () = abort("Usage: automap <IP address of your router>");
    }
    let ip_string = args[1].as_str();
    let router_ip = match IpAddr::from_str(ip_string) {
        Ok(ip) => ip,
        Err(e) => abort(&format!(
            "'{}' is not a properly-formatted IP address: {:?}",
            ip_string, e
        )),
    };
    let router_address = SocketAddr::new(router_ip, 5351);
    let local_ip = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
    let local_address = SocketAddr::new(local_ip, 5350);

    println!("{}\n", MAIN_HEADER);

    let socket = UdpSocket::bind(local_address).unwrap();
    test_pmp(socket, router_address);
    let socket = UdpSocket::bind(local_address).unwrap();
    test_pcp(socket, router_address, router_ip);
    test_igdp();
}

// struct Tracker {
//     issues: Vec<String>,
// }

// impl Tracker {
//     fn new () -> Self {
//         Self {
//             issues: vec![]
//         }
//     }
//
//     fn fail (&mut self, msg: String) {
//         self.issues.push (msg);
//     }
//
//     fn resolve (self) {
//         if self.issues.is_empty () {
//             ::std::process::exit (0);
//         }
//         else {
//             let _: () = abort (&self.issues.join ("\n"));
//         }
//     }
// }

fn abort<T>(msg: &str) -> T {
    eprintln!("{}", msg);
    ::std::process::exit(1);
}
