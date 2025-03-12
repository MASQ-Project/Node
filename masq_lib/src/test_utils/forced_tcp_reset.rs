// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::os::fd::AsRawFd;
use std::os::raw::c_int;
use std::os::raw::c_void;

#[cfg(unix)]
use nix::libc::linger;
#[cfg(unix)]
use std::os::fd::RawFd;

#[cfg(windows)]
use std::os::windows::RawSocket;
use tokio::net::TcpStream;

mod sys_call {
    use super::*;

    #[no_mangle]
    extern "C" {
        pub fn setsockopt(
            socket: c_int,
            level: c_int,
            name: c_int,
            value: *const c_void,
            option_len: u32,
        ) -> c_int;
    }
}

pub struct SocketHandle {
    #[cfg(unix)]
    fd: RawFd,
    #[cfg(windows)]
    socket: RawSocket,
}

impl SocketHandle {
    pub fn new(stream: &TcpStream) -> Self {
        Self {
            #[cfg(unix)]
            fd: stream.as_raw_fd(),
            #[cfg(windows)]
            socket: stream.as_raw_socket(),
        }
    }

    #[cfg(unix)]
    pub fn set_socket_to_no_linger(self) {
        // Will cause a sending of TCP RST instead of TCP FIN on a close
        let sol_socket = c_int::from(1);
        let so_linger = c_int::from(13);
        let linger = linger {
            l_onoff: c_int::from(1),
            l_linger: c_int::from(0),
        };
        unsafe {
            sys_call::setsockopt(
                self.fd,
                sol_socket,
                so_linger,
                &linger as *const linger as *const c_void,
                size_of::<linger>() as u32,
            )
        };
    }

    #[cfg(windows)]
    pub fn set_socket_to_no_linger(self) {
        // Will cause a sending of TCP RST instead of TCP FIN on a close
        let ws_sol_socket = c_int::from(65535);
        let ws_so_linger = c_int::from(128);
        let linger = Linger {
            l_onoff: 1,
            l_linger: 0,
        };
        unsafe {
            sys_call::setsockopt(
                self.socket,
                ws_sol_socket,
                ws_so_linger,
                &linger as *const Linger as *const c_void,
                size_of::<Linger>() as u32,
            )
        };
    }
}

#[cfg(windows)]
#[repr(C)]
pub struct Linger {
    pub l_onoff: u16,
    pub l_linger: u16,
}
