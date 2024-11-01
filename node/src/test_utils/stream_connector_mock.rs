// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::sub_lib::stream_connector::ConnectionInfo;
use crate::sub_lib::stream_connector::StreamConnector;
use crate::test_utils::tokio_wrapper_mocks::ReadHalfWrapperMock;
use crate::test_utils::tokio_wrapper_mocks::WriteHalfWrapperMock;
use masq_lib::logger::Logger;
use std::io;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use async_trait::async_trait;
use tokio::net::TcpStream;

#[derive(Default)]
pub struct StreamConnectorMock {
    connect_pair_params: Arc<Mutex<Vec<SocketAddr>>>,
    connect_pair_results: Mutex<Vec<Result<ConnectionInfo, io::Error>>>,
    split_stream_results: Mutex<Vec<Option<ConnectionInfo>>>,
}

#[async_trait]
impl StreamConnector for StreamConnectorMock {
    async fn connect(&self, socket_addr: SocketAddr, _logger: &Logger) -> Result<ConnectionInfo, tokio::io::Error> {
        self.connect_pair_params.lock().unwrap().push(socket_addr);
        let connection_info_result = self.connect_pair_results.lock().unwrap().remove(0);
        connection_info_result
    }

    fn connect_one(
        &self,
        _ip_addrs: Vec<IpAddr>,
        _target_hostname: &str,
        _target_port: u16,
        _logger: &Logger,
    ) -> Result<ConnectionInfo, io::Error> {
        self.connect_pair_results.lock().unwrap().remove(0)
    }

    fn split_stream(&self, _stream: TcpStream, _logger: &Logger) -> Option<ConnectionInfo> {
        self.split_stream_results.lock().unwrap().remove(0)
    }

    fn dup(&self) -> Box<dyn StreamConnector> {
        todo!()
        // Box::new(StreamConnectorMock {
        //     connect_pair_params: self.connect_pair_params.clone(),
        //     connect_pair_results: self.connect_pair_results.clone(),
        //     split_stream_results: self.split_stream_results.clone(),
        // })
    }
}

type StreamConnectorMockRead = (Vec<u8>, Poll<Result<(), io::Error>>);
type StreamConnectorMockWrite = Poll<Result<usize, io::Error>>;

impl StreamConnectorMock {
    pub fn new() -> StreamConnectorMock {
        Self {
            connect_pair_params: Arc::new(Mutex::new(vec![])),
            connect_pair_results: Mutex::new(vec![]),
            split_stream_results: Mutex::new(vec![]),
        }
    }

    pub fn connection(
        self,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        reads: Vec<StreamConnectorMockRead>,
        writes: Vec<StreamConnectorMockWrite>,
    ) -> StreamConnectorMock {
        let read_half = reads
            .into_iter()
            .fold(ReadHalfWrapperMock::new(), |so_far, elem| {
                so_far.poll_read_result(elem.0, elem.1)
            });
        let write_half = writes
            .into_iter()
            .fold(WriteHalfWrapperMock::new(), |so_far, elem| {
                so_far.poll_write_result(elem)
            });
        let connection_info = ConnectionInfo {
            reader: Box::new(read_half),
            writer: Box::new(write_half),
            local_addr,
            peer_addr,
        };
        self.connect_pair_result(Ok(connection_info))
    }

    pub fn with_connection(
        self,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        reader: ReadHalfWrapperMock,
        writer: WriteHalfWrapperMock,
    ) -> StreamConnectorMock {
        let connection_info = ConnectionInfo {
            reader: Box::new(reader),
            writer: Box::new(writer),
            local_addr,
            peer_addr,
        };
        self.connect_pair_result(Ok(connection_info))
    }

    pub fn connect_pair_params(
        mut self,
        params_arc: &Arc<Mutex<Vec<SocketAddr>>>,
    ) -> StreamConnectorMock {
        self.connect_pair_params = params_arc.clone();
        self
    }

    pub fn connect_pair_result(
        self,
        result: Result<ConnectionInfo, io::Error>,
    ) -> StreamConnectorMock {
        self.connect_pair_results.lock().unwrap().push(result);
        self
    }

    pub fn split_stream_result(self, result: Option<ConnectionInfo>) -> StreamConnectorMock {
        self.split_stream_results.lock().unwrap().push(result);
        self
    }
}
