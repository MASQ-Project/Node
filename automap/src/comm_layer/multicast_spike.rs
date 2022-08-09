// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
#[allow(unused_imports)]
use crossbeam_channel::unbounded;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
#[allow(unused_imports)]
use std::thread;

#[allow(dead_code)]
//multicast IP address must that is shared between any number of subscribers
const MULTICAST_GROUP_ADDRESS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 2);
//port that multicast group subscribers will bind to and communicate with
const MCAST_PORT: u16 = 8888;
//unspecified interface here resolves into any available interface, if multiple interfaces are present it will try to select "default" interface first
const MCAST_INTERFACE: Ipv4Addr = Ipv4Addr::UNSPECIFIED;

//abstracted out to have a common creation path
#[allow(dead_code)]
fn create_socket() -> UdpSocket {
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
        .join_multicast_v4(&MULTICAST_GROUP_ADDRESS, &MCAST_INTERFACE)
        .unwrap();
    //binds to the multicast interface and port
    socket
        .bind(&SockAddr::from(SocketAddr::new(
            IpAddr::from(MCAST_INTERFACE),
            MCAST_PORT,
        )))
        .unwrap();
    //converts socket2 sicket into a std::net socket, required for correct recv_from method
    let socket: UdpSocket = socket.into();
    socket
}

#[allow(dead_code)]
fn run_receiver() {
    //creates socket
    let socket = create_socket();
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
    let addr = &SockAddr::from(SocketAddr::new(MULTICAST_GROUP_ADDRESS.into(), MCAST_PORT));
    //creates socket
    let socket = create_socket();
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
    //creates 3 receiver sockets, probably a more elegant way to do this.
    let receiver1 = create_socket();
    let receiver2 = create_socket();
    let receiver3 = create_socket();
    //creates socket to send
    let socket = create_socket();
    let mut buffer1 = [0; 64];
    let mut buffer2 = [0; 64];
    let mut buffer3 = [0; 64];
    //socket address to use for send_to later on, must be the same multicast group and port we set for the receiver
    let addr = &SockAddr::from(SocketAddr::new(MULTICAST_GROUP_ADDRESS.into(), MCAST_PORT));
    //easy way to send/receive 10 messages
    (0..10).for_each(|x| {
        println!("sending multicast message to group");
        let message = format!("Test message {} for MASQ UDP multicast", x);
        //sends message as bytes to socket address
        socket
            .send_to(message.as_bytes(), &addr.as_socket().unwrap())
            .expect("could not send_to!");
        //receives message from socket for receiver1
        match receiver1.recv_from(&mut buffer1) {
            Ok((len, _remote_addr)) => {
                let data = &buffer1[..len];
                let response = std::str::from_utf8(data).unwrap();

                eprintln!("{}: Received on receiver1: {:?}", x, response);
                assert_eq!(response, message)
            }
            Err(err) => {
                println!("client: had a problem: {}", err);
                panic!()
            }
        }
        //receives message from socket for receiver2
        match receiver2.recv_from(&mut buffer2) {
            Ok((len, _remote_addr)) => {
                let data = &buffer2[..len];
                let response = std::str::from_utf8(data).unwrap();

                eprintln!("{}: Received on receiver2: {:?}", x, response);
                assert_eq!(response, message)
            }
            Err(err) => {
                println!("client: had a problem: {}", err);
                panic!();
            }
        }
        //receives message from socket for receiver3
        match receiver3.recv_from(&mut buffer3) {
            Ok((len, _remote_addr)) => {
                let data = &buffer3[..len];
                let response = std::str::from_utf8(data).unwrap();

                eprintln!("{}: Received on receiver3: {:?}", x, response);
                assert_eq!(response, message)
            }
            Err(err) => {
                println!("client: had a problem: {}", err);
                panic!();
            }
        }
    })
}
