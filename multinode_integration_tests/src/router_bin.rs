// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.


use std::{env, io, process};
use std::collections::HashMap;
use std::net::SocketAddr;
use masq_lib::command::{Command, StdStreams};

pub const CONTROL_STREAM_PORT: u16 = 42511;

pub fn main() {
    let mut streams: StdStreams<'_> = StdStreams {
        stdin: &mut io::stdin(),
        stdout: &mut io::stdout(),
        stderr: &mut io::stderr(),
    };
    let mut command = Router::new();
    let streams_ref: &mut StdStreams<'_> = &mut streams;
    let args: Vec<String> = env::args().collect();
    let exit_code = command.go(streams_ref, &args);
    process::exit(exit_code as i32);
}

pub struct Router {
    // translation_table: HashMap<SocketAddr, SocketAddr>,
}

impl Command<u8> for Router {
    fn go(&mut self, _streams: &mut StdStreams<'_>, _args: &[String]) -> u8 {
        todo! ();
    }
}

impl Router {
    pub fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
mod tests {
    extern crate pnet;
    extern crate pnet_datalink;

    use pnet::packet::{Packet, MutablePacket};
    use pnet::packet::ethernet::{Ethernet, EthernetPacket, MutableEthernetPacket};
    use pnet_datalink::NetworkInterface;

    #[test]
    fn not_a_test() {
        let interface_name = "localhost";
        let interface_names_match =
            |iface: &NetworkInterface| iface.name == interface_name;

        // Find the network interface with the provided name
        let interfaces = pnet_datalink::interfaces();
        let interface = interfaces.into_iter()
            .filter(interface_names_match)
            .next()
            .unwrap();

        // Create a new channel, dealing with layer 2 packets
        let (mut tx, mut rx) = match pnet_datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unhandled channel type"),
            Err(e) => panic!("An error occurred when creating the datalink channel: {}", e)
        };

        loop {
            match rx.next() {
                Ok(packet) => {
                    let packet = EthernetPacket::new(packet).unwrap();

                    // Constructs a single packet, the same length as the the one received,
                    // using the provided closure. This allows the packet to be constructed
                    // directly in the write buffer, without copying. If copying is not a
                    // problem, you could also use send_to.
                    //
                    // The packet is sent once the closure has finished executing.
                    tx.build_and_send(1, packet.packet().len(),
                                      &mut |mut new_packet| {
                                          let mut new_packet = MutableEthernetPacket::new(new_packet).unwrap();

                                          // Create a clone of the original packet
                                          new_packet.clone_from(&packet);

                                          // Switch the source and destination
                                          new_packet.set_source(packet.get_destination());
                                          new_packet.set_destination(packet.get_source());
                                      });
                },
                Err(e) => {
                    // If an error occurs, we can handle it here
                    panic!("An error occurred while reading: {}", e);
                }
            }
        }
    }
}
