// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved

use crate::protocols::pmp::get_packet::GetOpcodeData;
use crate::protocols::pmp::pmp_packet::{Opcode, PmpPacket};
use crate::protocols::utils::{Direction, Packet, PMP_HEADER};
use std::convert::TryFrom;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

pub fn test_pmp(socket: UdpSocket, router_address: SocketAddr) {
    let mut buf = [0u8; 1100];
    let packet_len = {
        let packet = PmpPacket {
            direction: Direction::Request,
            opcode: Opcode::Get,
            result_code_opt: None,
            opcode_data: Box::new(GetOpcodeData {
                epoch_opt: None,
                external_ip_address_opt: None,
            }),
        };
        packet.marshal(&mut buf).unwrap()
    };

    socket.send_to(&buf[0..packet_len], router_address).unwrap();
    println!("{}", PMP_HEADER);
    socket
        .set_read_timeout(Some(Duration::new(10, 0)))
        .expect("setting socket timeout failed");
    match socket.recv_from(&mut buf) {
        Ok(length) => {
            let packet_len = length.0;
            let buf_slice = &buf[0..packet_len];
            let packet = PmpPacket::try_from(buf_slice).unwrap();
            let mut report = String::new();
            let opcode_data = packet
                .opcode_data
                .as_any()
                .downcast_ref::<GetOpcodeData>()
                .unwrap();
            if packet.direction != Direction::Response {
                report.push_str("Additional issue: Response packet was a request, not a response")
            };
            if packet.opcode != Opcode::Get {
                report.push_str(&format!(
                    "Additional issue: Response packet opcode was {:?}, not Get",
                    packet.opcode
                ))
            };
            if packet.result_code_opt != Some(0) {
                report.push_str(&format!(
                    "Additional issue: Response packet result code was {:?}, not 0",
                    packet.result_code_opt
                ))
            };
            println!("Items of interest:");
            println!(
                "Public IP address: {:?}",
                opcode_data.external_ip_address_opt
            );
            println!("Epoch time: {:?}", opcode_data.epoch_opt);
            println!("{}", report);
        }

        Err(er) => println!(
            "\
Failure
The reason seems to be:
{}\n",
            er
        ),
    };
}
