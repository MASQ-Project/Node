// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
#[allow(unused_imports)]
use crossbeam_channel::unbounded;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
#[allow(unused_imports)]
use std::thread;

#[allow(dead_code)]
//multicast IP address must that is shared between any number of subscribers
const MULTICAST_GROUP_ADDRESS_1: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 2);
const MULTICAST_GROUP_ADDRESS_2: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 3);
//port that multicast group subscribers will bind to and communicate with
const MCAST_PORT_1: u16 = 8888;
const MCAST_PORT_2: u16 = 8889;
//unspecified interface here resolves into any available interface, if multiple interfaces are present it will try to select "default" interface first
const MCAST_INTERFACE: Ipv4Addr = Ipv4Addr::UNSPECIFIED;

//abstracted out to have a common creation path
#[allow(dead_code)]
fn create_socket(multicast_address: Ipv4Addr, port: u16) -> UdpSocket {
    //creates new UDP socket on ipv4 address
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .expect("could not create socket!");
    //linux/macos have reuse_port exposed so we can flag it for non-windows systems
    #[cfg(not(target_os = "windows"))]
    socket.set_reuse_port(true).unwrap();
    //windows has reuse_port hidden and implicitly flagged with reuse_address
    socket.set_reuse_address(true).unwrap();
    //subscribes to multicast group on the unspecified interface
    socket
        .join_multicast_v4(&multicast_address, &MCAST_INTERFACE)
        .unwrap();
    //binds to the multicast interface and port
    socket
        .bind(&SockAddr::from(SocketAddr::new(
            IpAddr::from(MCAST_INTERFACE),
            port,
        )))
        .unwrap();
    //converts socket2 socket into a std::net socket, required for correct recv_from method
    let socket: UdpSocket = socket.into();
    socket
}

#[allow(dead_code)]
fn run_receiver() {
    //creates socket
    let socket = create_socket(MULTICAST_GROUP_ADDRESS_1, MCAST_PORT_1);
    //sets buffer type/size, change as needed (64 bytes is fine for a small message, but UDP info from router/app will be much larger)
    let mut buffer = [0; 64];
    //easy way to run 10 receives
    (0..10).for_each(|x| {
        let message = format!("Test message {} for MASQ UDP multicast", x);
        //receives message from socket
        match socket.recv_from(&mut buffer) {
            Ok((len, _remote_addr)) => {
                let data = &buffer[..len];
                let response = std::str::from_utf8(data).unwrap();

                eprintln!("{}: Received on receiver1: {:?}", x, response);
                assert_eq!(response, message)
            }
            Err(err) => {
                println!("client: had a problem: {}", err);
                panic!();
            }
        }
    })
}

#[allow(dead_code)]
fn run_sender() {
    //socket address to use for send_to later on, must be the same multicast group and port we set for the receiver
    let addr = &SockAddr::from(SocketAddr::new(MULTICAST_GROUP_ADDRESS_1.into(), MCAST_PORT_1));
    //creates socket
    let socket = create_socket(MULTICAST_GROUP_ADDRESS_1, MCAST_PORT_1);
    //easy way to send 10 messages
    (0..10).for_each(|x| {
        println!("sending multicast message to group");
        let message = format!("Test message {} for MASQ UDP multicast", x);
        //sends message as bytes to the socket address we set earlier
        socket
            .send_to(message.as_bytes(), &addr.as_socket().unwrap())
            .expect("could not send_to!");
    })
}

//crossbeam_channel is extremely fast and able to confirm that sender/receiver both work correctly, but cannot have multiple receivers
#[test]
fn singlecast_udp_test() {
    let (sender, receiver) = unbounded();
    thread::spawn(move || {
        receiver.recv().unwrap();
        run_sender()
    });
    sender.send(()).unwrap();
    run_receiver()
}

#[test]
fn multicast_udp_test() {
    //creates socket to send
    let socket = create_socket(MULTICAST_GROUP_ADDRESS_2, MCAST_PORT_2);
    //socket address to use for send_to later on, must be the same multicast group and port we set for the receiver
    let socket_addr = SocketAddr::new(MULTICAST_GROUP_ADDRESS_2.into(), MCAST_PORT_2);
    //creates 3 receiver sockets and buffers
    let mut receivers = vec![
        create_socket(MULTICAST_GROUP_ADDRESS_2, MCAST_PORT_2),
        create_socket(MULTICAST_GROUP_ADDRESS_2, MCAST_PORT_2),
        create_socket(MULTICAST_GROUP_ADDRESS_2, MCAST_PORT_2),
    ];
    //easy way to send/receive 10 messages
    (0..10).for_each(|x| {
        let message = format!("Test message {} for MASQ UDP multicast", x);
        println!("Sending multicast message to group: '{}'", message);
        //sends message as bytes to socket address
        socket
            .send_to(message.as_bytes(), socket_addr)
            .expect("could not send_to!");
        let mut buf = [0u8; 64];
        receivers
            .iter()
            .enumerate()
            .for_each (|(idx, receiver)| {
                match receiver.recv_from(&mut buf) {
                    Ok((len, _remote_addr)) => {
                        let data = &buf[..len];
                        let response = std::str::from_utf8(data).unwrap();

                        eprintln!("{}: Received on receiver{}: '{}' when expecting '{}'", (idx + 1), x,
                                  response, message);
                        assert_eq!(response, message)
                    }
                    Err(err) => {
                        println!("receiver{}: had a problem: {}", (idx + 1), err);
                        panic!()
                    }
                }
            });
    })
}
