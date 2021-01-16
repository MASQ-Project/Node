// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::net::{IpAddr, UdpSocket, SocketAddr, Ipv4Addr};
use std::str::FromStr;
use automap_lib::protocols::pcp::map_packet::{Protocol, MapOpcodeData};
use automap_lib::protocols::utils::{Direction, Packet};
use std::convert::TryFrom;
use automap_lib::protocols::pmp::pmp_packet::{PmpPacket, Opcode};
use automap_lib::protocols::pmp::get_packet::GetOpcodeData;

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
    let local_ip = IpAddr::V4(Ipv4Addr::new (0, 0, 0, 0)); //IpAddr::from_str (&local_ipaddress::get().unwrap()).unwrap();
    let local_address = SocketAddr::new (local_ip, 5350);
    let socket = UdpSocket::bind(local_address).unwrap();

    let mut buf = [0u8; 1100];
    let packet_len = {
        let packet = PmpPacket {
            direction: Direction::Request,
            opcode: Opcode::Get,
            result_code_opt: None,
            opcode_data: Box::new(GetOpcodeData {
                epoch_opt: None,
                external_ip_address_opt: None
            })
        };
        packet.marshal(&mut buf).unwrap()
    };

    socket.send_to (&buf[0..packet_len], router_address).unwrap();
    let packet_len = socket.recv_from (&mut buf).unwrap().0;

    let buf_slice = &buf[0..packet_len];
    let packet = PmpPacket::try_from (buf_slice).unwrap();
    let mut tracker = Tracker::new();
    if packet.direction != Direction::Response {tracker.fail (format!("Response packet was a request, not a response"))};
    if packet.opcode != Opcode::Get {tracker.fail (format! ("Response packet opcode was {:?}, not Get", packet.opcode))};
    if packet.result_code_opt != Some (0) {tracker.fail (format!("Response packet result code was {:?}, not 0", packet.result_code_opt))};

    let opcode_data = packet.opcode_data.as_any().downcast_ref::<GetOpcodeData>().unwrap();
    println! ("Items of interest:");
    println! ("Public IP address: {:?}", opcode_data.external_ip_address_opt);
    println! ("Epoch time: {:?}", opcode_data.epoch_opt);

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
