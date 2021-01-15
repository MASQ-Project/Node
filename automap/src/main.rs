// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::net::{IpAddr, UdpSocket, SocketAddr};
use std::str::FromStr;
use automap_lib::protocols::pcp::map_packet::{Protocol, MapOpcodeData};
use automap_lib::protocols::pcp::pcp_packet::{Opcode, PcpPacket};
use automap_lib::protocols::utils::{Direction, Packet};
use std::convert::TryFrom;

pub fn main() {
    let args = std::env::args().collect::<Vec<String>>();
    if args.len() != 2 {
        let _: () = abort ("Usage: automap <IP address of your router>");
    }
    let ip_string = args[1].as_str();
    let router_ip = match IpAddr::from_str (ip_string) {
        Ok (ip) => ip,
        Err(e) => abort (&format!("'{}' is not a properly-formatted IP address: {:?}", ip_string, e)),
    };
    let router_address = SocketAddr::new (router_ip, 5351);
    let local_ip = IpAddr::from_str (&local_ipaddress::get().unwrap()).unwrap();
    let local_address = SocketAddr::new (local_ip, 5350);
    let socket = UdpSocket::bind(local_address).unwrap();

    let mut buf = [0u8; 1100];
    let packet_len = {
        let packet = PcpPacket {
            version: 0x2,
            direction: Direction::Request,
            opcode: Opcode::Map,
            result_code_opt: None,
            lifetime: 1,
            client_ip_opt: Some(local_ip),
            epoch_time_opt: None,
            opcode_data: Box::new (MapOpcodeData {
                mapping_nonce: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC],
                protocol: Protocol::Udp,
                internal_port: 50000,
                external_port: 50000,
                external_ip_address: IpAddr::from_str("0.0.0.0").unwrap(),
            }),
            options: vec![]
        };
        packet.marshal(&mut buf).unwrap()
    };

    socket.send_to (&buf[0..packet_len], router_address).unwrap();
    let packet_len = socket.recv_from (&mut buf).unwrap().0;

    let buf_slice = &buf[0..packet_len];
    let packet = PcpPacket::try_from (buf_slice).unwrap();
    let mut tracker = Tracker::new();
    if packet.version != 2 {tracker.fail (format!("Response packet version was {}, not 2", packet.version))};
    if packet.direction != Direction::Response {tracker.fail (format!("Response packet was a request, not a response"))};
    if packet.opcode != Opcode::Other(0xFF) {tracker.fail (format!("Response packet opcode was {:?}, not Other(255)", packet.opcode))};
    if packet.result_code_opt != Some (4) {tracker.fail (format!("Response packet result code was {:?}, not UNSUPP_OPCODE (4)", packet.result_code_opt))};

    println! ("Items of interest:");
    println! ("Error lifetime: {} seconds (expected 1800, but not an error if different)", packet.lifetime);
    println! ("Epoch time: {:?}", packet.epoch_time_opt);

    tracker.resolve();
}

struct Tracker {
    issues: Vec<String>,
}

impl Tracker {
    fn new () -> Self {
        Self {
            issues: vec![]
        }
    }

    fn fail (&mut self, msg: String) {
        self.issues.push (msg);
    }

    fn resolve (self) {
        if self.issues.is_empty () {
            ::std::process::exit (0);
        }
        else {
            let _: () = abort (&self.issues.join ("\n"));
        }
    }
}

fn abort<T> (msg: &str) -> T {
    eprintln! ("{}", msg);
    ::std::process::exit (1);
}
