// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
#![allow(proc_macro_derive_resolution_fallback)]
/*
use crate::proxy_client::resolver_wrapper::{
    ResolverWrapper, ResolverWrapperFactory, ResolverWrapperFactoryReal,
};
use crate::proxy_client::stream_establisher::StreamEstablisherFactory;
use crate::stream_messages::PoolBindMessage;
use crate::sub_lib::accountant::ReportExitServiceProvidedMessage;
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::proxy_client::{DnsResolveFailure_0v1, InboundServerData};
use crate::sub_lib::proxy_server::ClientRequestPayload_0v1;
use crate::sub_lib::stream_key::StreamKey;
use crate::sub_lib::wallet::Wallet;
use actix::{Actor, Addr, AsyncContext, Context, Handler, Message, Recipient};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::lookup_ip::LookupIp;
use itertools::Itertools;
use masq_lib::logger::Logger;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{AddrParseError, IpAddr, SocketAddr};
use std::str::FromStr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

#[derive(Message, Debug, Clone)]
#[rtype(result = "()")]
pub struct ProcessPackageMessage {
    payload: ClientRequestPayload_0v1,
    paying_wallet_opt: Option<Wallet>,
}

#[derive(Message, Debug, PartialEq)]
#[rtype(result = "()")]
pub struct DataWriteSuccess {
    stream_key: StreamKey,
    last_data: bool,
    writer: Box<dyn AsyncWrite + Send>,
}

#[derive(Message, Debug, PartialEq)]
#[rtype(result = "()")]
pub struct DataReadSuccess {
    stream_key: StreamKey,
    reader: Box<dyn AsyncRead + Send>,
    data: Vec<u8>,
}

#[derive(Message, Debug)]
#[rtype(result = "()")]
pub struct DataWriteError {
    stream_key: StreamKey,
    last_data: bool,
    writer: Box<dyn AsyncWrite + Send>,
    error: io::Error,
}

impl PartialEq for DataWriteError {
    fn eq(&self, other: &Self) -> bool {
        todo!("Test-drive me");
        self.stream_key == other.stream_key &&
            self.last_data == other.last_data &&
            self.error.kind() == other.error.kind()
    }
}

#[derive(Message, Debug)]
#[rtype(result = "()")]
pub struct DataReadError {
    stream_key: StreamKey,
    reader: Box<dyn AsyncRead + Send>,
    error: io::Error,
}

impl PartialEq for DataReadError {
    fn eq(&self, other: &Self) -> bool {
        todo!("Test-drive me");
        self.stream_key == other.stream_key &&
            self.error.kind() == other.error.kind()
    }
}

#[derive(Message, PartialEq)]
#[rtype(result = "()")]
pub struct AddStreamPair {
    stream_key: StreamKey,
    peer_addr: SocketAddr,
    writer: Box<dyn AsyncWrite + Send>,
    reader: Box<dyn AsyncRead + Send>,
}

#[derive(Message, Debug)]
#[rtype(result = "()")]
pub struct StreamCreationError {
    stream_key: StreamKey,
    error: io::Error,
}

impl PartialEq for StreamCreationError {
    fn eq(&self, other: &Self) -> bool {
        todo!("Test-drive me");
        self.stream_key == other.stream_key && self.error.kind() == other.error.kind()
    }
}

#[derive(Message, Debug, PartialEq)]
#[rtype(result = "()")]
pub struct KillStream {
    stream_key: StreamKey,
}

struct StreamPair {
    peer_addr: SocketAddr,
    pending_data: VecDeque<ProcessPackageMessage>,
    writer_opt: Option<Box<dyn AsyncWrite>>,
    reader_opt: Option<Box<dyn AsyncRead>>,
}

struct PrivateStreamHandlerPoolSubs {
    data_write_success_sub: Recipient<DataWriteSuccess>,
    data_read_success_sub: Recipient<DataReadSuccess>,
    data_write_error_sub: Recipient<DataWriteError>,
    data_read_error_sub: Recipient<DataReadError>,
    add_stream_pair_sub: Recipient<AddStreamPair>,
    stream_creation_error_sub: Recipient<StreamCreationError>,
    kill_stream_sub: Recipient<KillStream>,
}

struct ExternalSubs {
    pub accountant_sub: Recipient<ReportExitServiceProvidedMessage>,
    pub inbound_server_data: Recipient<InboundServerData>,
    pub dns_resolve_failed: Recipient<DnsResolveFailure_0v1>,
}

trait AsyncPairFactory {
    fn make(&self, peer_addr: SocketAddr) -> io::Result<(Box<dyn AsyncWrite>, Box<dyn AsyncRead>)>;
}

struct AsyncPairFactoryReal {}

impl AsyncPairFactory for AsyncPairFactoryReal {
    fn make(&self, peer_addr: SocketAddr) -> io::Result<(Box<dyn AsyncWrite>, Box<dyn AsyncRead>)> {
        todo!()
    }
}

pub struct StreamHandlerPool {
    dns_servers: Vec<SocketAddr>,
    async_pair_factory: Box<dyn AsyncPairFactory>,
    stream_pairs: HashMap<StreamKey, StreamPair>,
    resolver_factory: Box<dyn ResolverWrapperFactory>,
    logger: Logger,
    exit_service_rate: u64,
    exit_byte_rate: u64,
    private_subs_opt: Option<PrivateStreamHandlerPoolSubs>,
    subs_opt: Option<ExternalSubs>,
}

impl Actor for StreamHandlerPool {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        let addr = ctx.address();
        self.set_private_subs_opt(addr);
    }
}

impl Handler<BindMessage> for StreamHandlerPool {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_bind_message(msg)
    }
}

impl Handler<PoolBindMessage> for StreamHandlerPool {
    type Result = ();

    fn handle(&mut self, msg: PoolBindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_pool_bind_message(msg)
    }
}

impl Handler<ProcessPackageMessage> for StreamHandlerPool {
    type Result = ();

    fn handle(&mut self, msg: ProcessPackageMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_process_package(msg)
    }
}

impl Handler<DataWriteSuccess> for StreamHandlerPool {
    type Result = ();

    fn handle(&mut self, msg: DataWriteSuccess, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_data_write_success(msg)
    }
}

impl Handler<DataWriteError> for StreamHandlerPool {
    type Result = ();

    fn handle(&mut self, msg: DataWriteError, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_data_write_error(msg)
    }
}

impl Handler<DataReadSuccess> for StreamHandlerPool {
    type Result = ();

    fn handle(&mut self, msg: DataReadSuccess, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_data_read_success(msg)
    }
}

impl Handler<DataReadError> for StreamHandlerPool {
    type Result = ();

    fn handle(&mut self, msg: DataReadError, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_data_read_error(msg)
    }
}

impl Handler<AddStreamPair> for StreamHandlerPool {
    type Result = ();

    fn handle(&mut self, msg: AddStreamPair, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_add_stream_pair(msg)
    }
}

impl Handler<StreamCreationError> for StreamHandlerPool {
    type Result = ();

    fn handle(&mut self, msg: StreamCreationError, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_stream_creation_error(msg)
    }
}

impl Handler<KillStream> for StreamHandlerPool {
    type Result = ();

    fn handle(&mut self, msg: KillStream, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_kill_stream(msg)
    }
}

impl StreamHandlerPool {
    pub fn new(
        dns_servers: Vec<SocketAddr>,
        exit_service_rate: u64,
        exit_byte_rate: u64,
    ) -> StreamHandlerPool {
        StreamHandlerPool {
            dns_servers,
            async_pair_factory: Box::new(AsyncPairFactoryReal {}),
            stream_pairs: HashMap::new(),
            resolver_factory: Box::new(ResolverWrapperFactoryReal {}),
            logger: Logger::new("ProxyClient"),
            exit_service_rate,
            exit_byte_rate,
            private_subs_opt: None,
            subs_opt: None,
        }
    }

    fn handle_bind_message(&mut self, msg: BindMessage) {
        todo!()
    }

    fn handle_pool_bind_message(&mut self, msg: PoolBindMessage) {
        todo!()
    }

    fn handle_process_package(&mut self, process_package_message: ProcessPackageMessage) {
        let stream_key = process_package_message.payload.stream_key;
        match self.stream_pairs.get_mut(&stream_key) {
            Some(mut stream_pair) => match stream_pair.writer_opt.take() {
                Some(sender) => self.send_payload(process_package_message, sender),
                None => stream_pair.pending_data.push_back(process_package_message),
            },
            None => {
                self.add_stream_pair(process_package_message);
                // if process_package_message.payload.sequenced_packet.data.is_empty() {
                //     debug!(
                //         self.logger,
                //         "Empty request payload received for nonexistent stream {:?} - ignoring",
                //         process_package_message.payload.stream_key
                //     )
                // } else {
                //     let peer_addr =
                //     let future = async move {
                //         let stream = tokio::net::TcpStream::connect()
                //     }
                //     let future = Self::make_stream_with_key(&payload, inner_arc_1.clone())
                //         .and_then(move |sender_wrapper| {
                //             Self::write_and_tend(
                //                 sender_wrapper,
                //                 payload,
                //                 paying_wallet_opt,
                //                 inner_arc,
                //             )
                //         })
                //         .map_err(move |error| {
                //             // TODO: This ends up sending an empty response back to the browser and terminating
                //             // the stream. User deserves better than that. Send back a response from the
                //             // proper ServerImpersonator describing the error.
                //             Self::clean_up_bad_stream(
                //                 inner_arc_1,
                //                 &stream_key,
                //                 error_socket_addr(),
                //                 error,
                //             );
                //         });
                //     actix::spawn(future);
                // }
            }
        };
    }

    // fn clean_up_bad_stream(
    //     inner_arc: Arc<Mutex<StreamHandlerPoolRealInner>>,
    //     stream_key: &StreamKey,
    //     source: SocketAddr,
    //     error: String,
    // ) {
    //     let mut inner = inner_arc.lock().expect("Stream handler pool was poisoned");
    //     error!(
    //         inner.logger,
    //         "Couldn't process request from CORES package: {}", error
    //     );
    //     if let Some(sender_wrapper) = inner.stream_writer_channels.remove(stream_key) {
    //         debug!(
    //             inner.logger,
    //             "Removing stream writer for {}",
    //             sender_wrapper.peer_addr()
    //         );
    //     }
    //     Self::send_terminating_package(
    //         stream_key,
    //         source,
    //         &inner.proxy_client_subs.inbound_server_data,
    //     );
    // }

    fn handle_data_write_success(&self, success: DataWriteSuccess) {
        // Use the stream_key to find the right StreamPair
        // Put the writer back in the StreamPair
        // Inspect the StreamPair's queue; if there is anything in it, take out the first value and call handle_process_package() on it.
        todo!()
    }

    fn handle_data_write_error(&self, error: DataWriteError) {
        // Use the stream_key to find the right StreamPair
        // Put the writer back in the StreamPair
        // Inspect the StreamPair's queue; if there is anything in it, take out the first value and call handle_process_package() on it.
        todo!()
    }

    fn handle_data_read_success(&self, success: DataReadSuccess) {
        // Use the stream_key to find the right StreamPair
        // Pull out the existing sequence number and increment it
        // Transfer the data into an InboundServerData message and send it to the ProxyClient
        todo!()
    }

    fn handle_data_read_error(&self, error: DataReadError) {
        // If the failure is already logged, there's not much to do here
        todo!()
    }

    fn handle_add_stream_pair(&self, add_stream_pair: AddStreamPair) {
        // Use the stream_key to find the right StreamPair
        // Populate it with the rest of the message
        // If the StreamPair's queue isn't empty, pop the head of the queue and call handle_process_package with it
        todo!()
    }

    fn handle_stream_creation_error(&self, error: StreamCreationError) {
        // Use the stream_key to remove the right StreamPair
        // Create a DnsResolveFailure_0v1 message and send it to the ProxyClient.

        // Vulnerability:
        // Given a long barrage of payloads for a particular server...
        // The first payload opens the connect future and goes into the StreamPair queue.
        // The connect takes awhile; meantime, the queue accumulates many more payloads.
        // The connect fails, and the StreamPair--including its queue--is removed.
        // More payloads arrive; the next one will stimulate another connection attempt.
        // This connection attempt succeeds, and its payload and succeeding ones are routed to the server successfully.
        // But: all the data that was in the queue when the first connection failed is lost, even though there's a good
        //    chance it could have been sent if another connection had been attempted earlier.
        todo!()
    }

    fn handle_kill_stream(&self, msg: KillStream) {
        // Use the stream_key to find the correct StreamPair.
        // take() the AsyncRead and cancel it if it exists.
        // take() the AsyncWrite. If you don't get it, put the KillStream message back in the mailbox with a short delay.
        // If you do get it, close it and remove the StreamPair from the map.
        todo!()
    }

    fn add_stream_pair(&mut self, process_package_message: ProcessPackageMessage) {
        // TODO If process_package_member's payload is empty, log and abort here
        // Add null StreamPair to self.stream_pairs, put process_package_message in its queue
        let stream_key = process_package_message.payload.stream_key.clone();
        let host_name = match process_package_message.payload.target_hostname.as_ref() {
            Some(hn) => hn.clone(),
            None => todo!("Why would there be no target hostname?"),
        };
        let port = process_package_message.payload.target_port;
        let mut pending_data = VecDeque::new();
        pending_data.push_back(process_package_message);
        let stream_pair = StreamPair {
            peer_addr: SocketAddr::from_str("255.255.255.255:255").expect("Bad SocketAddr syntax"),
            pending_data,
            writer_opt: None,
            reader_opt: None,
        };
        self.stream_pairs.insert(stream_key, stream_pair);
        let future = async {
            let ip_addrs = match IpAddr::from_str(&host_name) {
                Ok(ip_addr) => {
                    // TODO: Make sure there's something in here rejecting all-zeros, loopback, and localhost addresses
                    todo!("Test-drive me") // vec![ip_addr]
                }
                Err(_) => {
                    let resolver_config = ResolverConfig::default();
                    // TODO: resolver_config.add_name_server(*get from --dns-servers parameter*);
                    let resolver_opts = ResolverOpts::default();
                    let resolver = self.resolver_factory.make(resolver_config, resolver_opts);
                    match resolver.lookup_ip(&host_name).await {
                        Err(e) => todo!("IP resolution error for {}: {:?}", host_name, e),
                        Ok(lookup_ip_x) => {
                            let lookup_ip: LookupIp = lookup_ip_x;
                            lookup_ip.into_iter().collect_vec()
                        }
                    }
                }
            };
            let stream: TcpStream = match Self::connect_to_server(&ip_addrs, port) {
                Err(e) => todo!("Connection to all of {:?} failed: {:?}", ip_addrs, e),
                Ok(stream) => stream,
            };
            let peer_addr = stream
                .peer_addr()
                .expect("Stream is connected, but no peer_addr is available");
            let (reader, writer) = stream.into_split();
            let msg = AddStreamPair {
                stream_key,
                peer_addr,
                writer: Box::new(writer),
                reader: Box::new(reader),
            };
            self.private_subs_opt
                .as_ref()
                .expect("StreamHandlerPool was not properly initialized")
                .add_stream_pair_sub
                .try_send(msg)
                .expect("StreamHandlerPool is dead")
        };
        tokio::spawn(future);
    }

    async fn connect_to_server(ip_addrs: &Vec<IpAddr>, port: u16) -> io::Result<TcpStream> {
        // TODO: This is about going down the list one by one and allowing each connection attempt to fail before
        // trying the next one. Consider whether we'd rather start up connection attempts to all the IP addresses at
        // once, and when one attempt succeeds, abandon all the others.
        for ip_addr in ip_addrs {
            match TcpStream::connect(SocketAddr::new(*ip_addr, port)).await {
                Err(e) => todo!("Connection attempt to {} failed: {:?}", ip_addr, e),
                Ok(stream) => todo!("Test-drive me!"), //return Ok(stream)
            }
        }
        todo!("None of the IP addresses worked. Probably return an error containing a collection of the errors experienced.")
    }

    fn send_payload(
        &mut self,
        process_package_message: ProcessPackageMessage,
        writer: Box<dyn AsyncWrite>,
    ) {
        let future = async {
            // Send the request chunk to the server
            // If there's an error, send a DataWriteError message and stop
            // Tell the Accountant about the exited data
            // Send a DataWriteSuccess message with the sender in it
        };
        todo!()
    }

    // fn write_and_tend(
    //     &mut self,
    //     sender: &mut dyn Write,
    //     peer_addr: SocketAddr,
    //     payload: ClientRequestPayload_0v1,
    //     paying_wallet_opt: Option<Wallet>,
    // ) {
    //     let future = async {
    //         let stream_key = payload.stream_key;
    //         let last_data = payload.sequenced_packet.last_data;
    //         let payload_size = payload.sequenced_packet.data.len();
    //         match sender.write_all(&payload.sequenced_packet.data).await {
    //             Ok(_) => {
    //                 if last_data {
    //                     match self.stream_pairs.remove(&stream_key) {
    //                         Some(channel) => debug!(
    //                     inner.logger,
    //                     "Removing StreamWriter {:?} to {}",
    //                     stream_key,
    //                     channel.peer_addr()
    //                 ),
    //                         None => debug!(
    //                     self.logger,
    //                     "Trying to remove StreamWriter {:?}, but it's already gone", stream_key
    //                 ),
    //                     }
    //                 }
    //                 if payload_size > 0 {
    //                     match paying_wallet_opt {
    //                         Some(wallet) => self
    //                             .accountant_sub
    //                             .try_send(ReportExitServiceProvidedMessage {
    //                                 timestamp: SystemTime::now(),
    //                                 paying_wallet: wallet,
    //                                 payload_size,
    //                                 service_rate: self.exit_service_rate,
    //                                 byte_rate: self.exit_byte_rate,
    //                             })
    //                             .expect("Accountant is dead"),
    //                         // This log is here mostly for testing, to prove that no Accountant message is sent in the no-wallet case
    //                         None => debug!(
    //                     self.logger,
    //                     "Sent {}-byte request without consuming wallet for free", payload_size
    //                 ),
    //                     }
    //                 }
    //             },
    //             Err(e) => (),
    //         }
    //     };
    //
    //
    //
    //     let stream_key = payload.stream_key;
    //     let last_data = payload.sequenced_packet.last_data;
    //     let payload_size = payload.sequenced_packet.data.len();
    //
    //     self.perform_write(payload.sequenced_packet, sender.clone()).and_then(move |_| {
    //         if last_data {
    //             match self.stream_pairs.remove(&stream_key) {
    //                 Some(channel) => debug!(
    //                     inner.logger,
    //                     "Removing StreamWriter {:?} to {}",
    //                     stream_key,
    //                     channel.peer_addr()
    //                 ),
    //                 None => debug!(
    //                     self.logger,
    //                     "Trying to remove StreamWriter {:?}, but it's already gone", stream_key
    //                 ),
    //             }
    //         }
    //         if payload_size > 0 {
    //             match paying_wallet_opt {
    //                 Some(wallet) => self
    //                     .accountant_sub
    //                     .try_send(ReportExitServiceProvidedMessage {
    //                         timestamp: SystemTime::now(),
    //                         paying_wallet: wallet,
    //                         payload_size,
    //                         service_rate: self.exit_service_rate,
    //                         byte_rate: self.exit_byte_rate,
    //                     })
    //                     .expect("Accountant is dead"),
    //                 // This log is here mostly for testing, to prove that no Accountant message is sent in the no-wallet case
    //                 None => debug!(
    //                     self.logger,
    //                     "Sent {}-byte request without consuming wallet for free", payload_size
    //                 ),
    //             }
    //         }
    //         Ok(())
    //     })
    // }

    // fn make_stream_with_key(
    //     &self,
    //     payload: &ClientRequestPayload_0v1,
    // ) -> StreamEstablisherResult {
    //     // TODO: Figure out what to do if a flurry of requests for a particular stream key
    //     // come flooding in so densely that several of them arrive in the time it takes to
    //     // resolve the first one and add it to the stream_writers map.
    //     let logger = self.make_logger_copy();
    //     debug!(
    //         logger,
    //         "No stream to {:?} exists; resolving host", &payload.target_hostname
    //     );
    //
    //     match payload.target_hostname {
    //         Some(ref target_hostname) => match Self::parse_ip(target_hostname) {
    //             Ok(socket_addr) => self.handle_ip(
    //                 payload.clone(),
    //                 socket_addr,
    //                 target_hostname.to_string(),
    //             ),
    //             Err(_) => self.lookup_dns(target_hostname.to_string(), payload.clone()),
    //         },
    //         None => {
    //             error!(
    //                 logger,
    //                 "Cannot open new stream with key {:?}: no hostname supplied",
    //                 payload.stream_key
    //             );
    //             Box::new(err::<
    //                 Box<dyn SenderWrapper<SequencedPacket> + 'static>,
    //                 String,
    //             >("No hostname provided".to_string()))
    //         }
    //     }
    // }

    fn parse_ip(hostname: &str) -> Result<IpAddr, AddrParseError> {
        let socket_ip = SocketAddr::from_str(hostname).map(|sa| sa.ip());
        if socket_ip.is_ok() {
            socket_ip
        } else {
            IpAddr::from_str(hostname)
        }
    }

    // fn make_establisher(&self) -> StreamEstablisher {
    //     self.establisher_factory.make()
    // }

    // fn handle_ip(
    //     &self,
    //     payload: ClientRequestPayload_0v1,
    //     ip_addr: IpAddr,
    //     target_hostname: String,
    // ) -> StreamEstablisherResult {
    //     let mut stream_establisher = self.make_establisher();
    //     Box::new(
    //         future::lazy(move || {
    //             stream_establisher.establish_stream(&payload, vec![ip_addr], target_hostname)
    //         })
    //         .map_err(|io_error| format!("Could not establish stream: {:?}", io_error)),
    //     )
    // }

    // fn lookup_dns(
    //     &self,
    //     target_hostname: String,
    //     payload: ClientRequestPayload_0v1,
    // ) -> StreamEstablisherResult {
    //     let fqdn = Self::make_fqdn(&target_hostname);
    //     let dns_resolve_failed_sub = self
    //         .proxy_client_subs
    //         .dns_resolve_failed
    //         .clone();
    //     let mut establisher = self.make_establisher();
    //     let stream_key = payload.stream_key;
    //     let logger = self.make_logger_copy();
    //     Box::new(
    //         self
    //             .resolver
    //             .lookup_ip(&fqdn)
    //             .map_err(move |err| {
    //                 dns_resolve_failed_sub
    //                     .try_send(DnsResolveFailure_0v1::new(stream_key))
    //                     .expect("ProxyClient is poisoned");
    //                 err
    //             })
    //             .then(move |lookup_result| {
    //                 Self::handle_lookup_ip(
    //                     target_hostname.to_string(),
    //                     &payload,
    //                     lookup_result,
    //                     logger,
    //                     &mut establisher,
    //                 )
    //             })
    //             .map_err(|io_error| format!("Could not establish stream: {:?}", io_error)),
    //     )
    // }

    // fn handle_lookup_ip(
    //     target_hostname: String,
    //     payload: &ClientRequestPayload_0v1,
    //     lookup_result: Result<LookupIp, ResolveError>,
    //     logger: Logger,
    //     establisher: &mut StreamEstablisher,
    // ) -> io::Result<Box<dyn SenderWrapper<SequencedPacket>>> {
    //     let ip_addrs: Vec<IpAddr> = match lookup_result {
    //         Err(e) => {
    //             error!(
    //                 logger,
    //                 "Could not find IP address for host {}: {}", target_hostname, e
    //             );
    //             return Err(io::Error::from(e));
    //         }
    //         Ok(lookup_ip) => lookup_ip.iter().collect(),
    //     };
    //     debug!(
    //         logger,
    //         "Found IP addresses for {}: {:?}", target_hostname, &ip_addrs
    //     );
    //     establisher.establish_stream(payload, ip_addrs, target_hostname)
    // }

    fn make_fqdn(target_hostname: &str) -> String {
        format!("{}.", target_hostname)
    }

    fn find_stream_pair_with_key(&self, stream_key: &StreamKey) -> Option<&StreamPair> {
        self.stream_pairs.get(stream_key)
    }

    fn make_logger_copy(&self) -> Logger {
        self.logger.clone()
    }

    // fn perform_write(
    //     sequenced_packet: SequencedPacket,
    //     sender_wrapper: Box<dyn SenderWrapper<SequencedPacket>>,
    // ) -> FutureResult<(), String> {
    //     match sender_wrapper.unbounded_send(sequenced_packet) {
    //         Ok(_) => ok::<(), String>(()),
    //         Err(_) => {
    //             err::<(), String>("Could not queue write to stream; channel full".to_string())
    //         }
    //     }
    // }

    fn send_terminating_package(
        stream_key: &StreamKey,
        source: SocketAddr,
        proxy_client_sub: &Recipient<InboundServerData>,
    ) {
        proxy_client_sub
            .try_send(InboundServerData {
                stream_key: *stream_key,
                last_data: true,
                sequence_number: 0,
                source,
                data: vec![],
            })
            .expect("ProxyClient is dead");
    }

    fn do_housekeeping(&self) {
        self.clean_up_dead_streams();
        self.add_new_streams();
    }

    // fn clean_up_dead_streams(&self) {
    //     let mut inner = self.inner.lock().expect("Stream handler pool is poisoned");
    //     while let Ok((stream_key, sequence_number)) = self.stream_killer_rx.try_recv() {
    //         match inner.stream_writer_channels.remove(&stream_key) {
    //             Some(writer_channel) => {
    //                 inner
    //                     .proxy_client_subs
    //                     .inbound_server_data
    //                     .try_send(InboundServerData {
    //                         stream_key,
    //                         last_data: true,
    //                         sequence_number,
    //                         source: writer_channel.peer_addr(),
    //                         data: vec![],
    //                     })
    //                     .expect("ProxyClient is dead");
    //                 debug!(
    //                     inner.logger,
    //                     "Killed StreamWriter to {} and sent server-drop report",
    //                     writer_channel.peer_addr()
    //                 )
    //             }
    //             None => debug!(
    //                 inner.logger,
    //                 "Tried to kill StreamWriter for key {:?}, but it was already gone", stream_key
    //             ),
    //         }
    //     }
    // }

    // fn add_new_streams(&self) {
    //     let mut inner = self.inner.lock().expect("Stream handler pool is poisoned");
    //     loop {
    //         match self.stream_adder_rx.try_recv() {
    //             Err(_) => break,
    //             Ok((stream_key, stream_writer_channel)) => {
    //                 debug!(
    //                     inner.logger,
    //                     "Persisting StreamWriter to {} under key {:?}",
    //                     stream_writer_channel.peer_addr(),
    //                     stream_key
    //                 );
    //                 inner
    //                     .stream_writer_channels
    //                     .insert(stream_key, stream_writer_channel)
    //             }
    //         };
    //     }
    // }

    fn set_private_subs_opt(&mut self, addr: Addr<StreamHandlerPool>) {
        self.private_subs_opt = Some(PrivateStreamHandlerPoolSubs {
            data_write_success_sub: addr.clone().recipient(),
            data_read_success_sub: addr.clone().recipient(),
            data_write_error_sub: addr.clone().recipient(),
            data_read_error_sub: addr.clone().recipient(),
            add_stream_pair_sub: addr.clone().recipient(),
            stream_creation_error_sub: addr.clone().recipient(),
            kill_stream_sub: addr.recipient(),
        })
    }
}

// pub trait StreamHandlerPoolFactory {
//     fn make(
//         &self,
//         resolver: Box<dyn ResolverWrapper>,
//         cryptde: &'static dyn CryptDE,
//         accountant_sub: Recipient<ReportExitServiceProvidedMessage>,
//         proxy_client_subs: ProxyClientSubs,
//         exit_service_rate: u64,
//         exit_byte_rate: u64,
//     ) -> Box<dyn StreamHandlerPool>;
// }

// pub struct StreamHandlerPoolFactoryReal {}

// impl StreamHandlerPoolFactory for StreamHandlerPoolFactoryReal {
//     fn make(
//         &self,
//         resolver: Box<dyn ResolverWrapper>,
//         cryptde: &'static dyn CryptDE,
//         accountant_sub: Recipient<ReportExitServiceProvidedMessage>,
//         proxy_client_subs: ProxyClientSubs,
//         exit_service_rate: u64,
//         exit_byte_rate: u64,
//     ) -> Box<dyn StreamHandlerPool> {
//         Box::new(StreamHandlerPoolReal::new(
//             resolver,
//             cryptde,
//             accountant_sub,
//             proxy_client_subs,
//             exit_service_rate,
//             exit_byte_rate,
//         ))
//     }
// }

trait StreamConnector {
    fn connect(addr: SocketAddr) -> io::Result<(dyn AsyncWrite, dyn AsyncRead)>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy_client::local_test_utils::ResolverWrapperFactoryMock;
    use crate::proxy_client::local_test_utils::ResolverWrapperMock;
    use crate::proxy_client::stream_establisher::StreamEstablisher;
    use crate::sub_lib::cryptde::PublicKey;
    use crate::sub_lib::proxy_server::ProxyProtocol;
    use crate::test_utils::make_meaningless_stream_key;
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::recorder::{make_recorder, Recorder};
    use crate::test_utils::unshared_test_utils::AssertionsMessage;
    use actix::System;
    use masq_lib::constants::HTTP_PORT;
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use std::cell::RefCell;
    use std::io::Write;
    use std::net::IpAddr;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::task::Poll;
    use tokio::io::{AsyncRead, AsyncWrite};
    use crate::sub_lib::sequence_buffer::SequencedPacket;

    impl Handler<AssertionsMessage<StreamHandlerPool>> for StreamHandlerPool {
        type Result = ();

        fn handle(
            &mut self,
            msg: AssertionsMessage<StreamHandlerPool>,
            ctx: &mut Self::Context,
        ) -> Self::Result {
            (msg.assertions)(self)
        }
    }

    #[derive(Message)]
    #[rtype(result = "()")]
    struct SetPrivateSubsMessage {
        recorder: Recorder,
    }
    impl Handler<SetPrivateSubsMessage> for StreamHandlerPool {
        type Result = ();

        fn handle(&mut self, msg: SetPrivateSubsMessage, ctx: &mut Self::Context) -> Self::Result {
            let addr = msg.recorder.start();
            self.private_subs_opt = Some(PrivateStreamHandlerPoolSubs {
                data_write_success_sub: addr.clone().recipient::<DataWriteSuccess>(),
                data_read_success_sub: addr.clone().recipient::<DataReadSuccess>(),
                data_write_error_sub: addr.clone().recipient::<DataWriteError>(),
                data_read_error_sub: addr.clone().recipient::<DataReadError>(),
                add_stream_pair_sub: addr.clone().recipient::<AddStreamPair>(),
                stream_creation_error_sub: addr.clone().recipient::<StreamCreationError>(),
                kill_stream_sub: addr.recipient::<KillStream>(),
            })
        }
    }

    struct TestAsyncWrite {
        pub data_arc: Arc<Mutex<Vec<u8>>>,
    }
    impl AsyncWrite for TestAsyncWrite {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.data().poll_write(cx, buf)
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            self.data().poll_flush(cx)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            self.data().poll_shutdown(cx)
        }
    }
    impl TestAsyncWrite {
        pub fn new() -> Self {
            Self {
                data_arc: Arc::new(Mutex::new(vec![])),
            }
        }
        pub fn data(&self) -> MutexGuard<Vec<u8>> {
            self.data_arc.lock().unwrap()
        }
    }

    struct TestAsyncRead {
        data_arc: Arc<Mutex<Vec<Vec<u8>>>>,
    }
    impl AsyncRead for TestAsyncRead {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            mut buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let mut buffers = self.data_arc.lock().unwrap();
            let data = buffers.remove(0);
            buf.write_all(data.as_slice()).unwrap();
            Poll::Ready(Ok(buf.len()))
        }
    }
    impl TestAsyncRead {
        pub fn new(data: Vec<Vec<u8>>) -> Self {
            Self {
                data_arc: Arc::new(Mutex::new(data)),
            }
        }
    }

    struct StreamEstablisherFactoryMock {
        make_results: RefCell<Vec<StreamEstablisher>>,
    }

    impl StreamEstablisherFactory for StreamEstablisherFactoryMock {
        fn make(&self) -> StreamEstablisher {
            self.make_results.borrow_mut().remove(0)
        }
    }

    struct StreamConnectorMock {}

    impl StreamConnector for StreamConnectorMock {
        fn connect(addr: SocketAddr) -> io::Result<(Box<dyn AsyncWrite>, Box<dyn AsyncRead>)> {
            todo!()
        }
    }

    impl StreamConnectorMock {
        pub fn new() -> Self {
            todo!()
        }

        pub fn connect_params(self, params: &Arc<Mutex<Vec<SocketAddr>>>) -> Self {
            todo!()
        }

        pub fn connect_result(self, result: io::Result<StreamKey>) -> Self {
            todo!()
        }

        pub fn receive_chunk(self, stream_key: StreamKey, chunk: Vec<u8>) -> Self {
            todo!()
        }

        pub fn receive_error(self, stream_key: StreamKey, error: io::Error) -> Self {
            todo!()
        }

        pub fn transmitted_chunks(self, chunks: &Arc<Mutex<Vec<TransmittedChunk>>>) -> Self {
            todo!()
        }
    }

    struct AsyncPairFactoryMock {
        incoming_data: Vec<Vec<u8>>,
        outgoing_data: Arc<Mutex<Vec<Arc<Mutex<Vec<u8>>>>>>,
        make_params: Arc<Mutex<Vec<SocketAddr>>>,
        make_results: RefCell<Vec<io::Result<(Box<dyn AsyncWrite>, Box<dyn AsyncRead>)>>>,
    }
    impl AsyncPairFactory for AsyncPairFactoryMock {
        fn make(
            &self,
            peer_addr: SocketAddr,
        ) -> io::Result<(Box<dyn AsyncWrite>, Box<dyn AsyncRead>)> {
            let async_write = TestAsyncWrite::new();
            let outgoing_data = async_write.data_arc.clone();
            self.outgoing_data.lock().unwrap().push(outgoing_data);
            Ok((
                Box::new(async_write),
                Box::new(TestAsyncRead::new(self.incoming_data.clone())),
            ))
        }
    }
    impl AsyncPairFactoryMock {
        pub fn mock_and_outgoing_data(
            incoming_data: Vec<Vec<u8>>,
        ) -> (Self, Arc<Mutex<Vec<Arc<Mutex<Vec<u8>>>>>>) {
            let mock = Self {
                incoming_data,
                outgoing_data: Arc::new(Mutex::new(vec![])),
                make_params: Arc::new(Mutex::new(vec![])),
                make_results: RefCell::new(vec![]),
            };
            let outgoing_data = mock.outgoing_data.clone();
            (mock, outgoing_data)
        }
        pub fn make_params(mut self, params: &Arc<Mutex<Vec<SocketAddr>>>) -> Self {
            self.make_params = params.clone();
            self
        }

        pub fn make_result(
            mut self,
            result: io::Result<(Box<dyn AsyncWrite>, Box<dyn AsyncRead>)>,
        ) -> Self {
            self.make_results.borrow_mut().push(result);
            self
        }
    }

    #[derive(PartialEq, Debug)]
    struct TransmittedChunk {
        pub stream_key: StreamKey,
        pub data: Vec<u8>,
    }

    // fn run_process_package(
    //     subject: StreamHandlerPoolReal,
    //     payload: ClientRequestPayload_0v1,
    //     paying_wallet: Wallet,
    // ) {
    //     let future = subject.process_package(payload, paying_wallet);
    //     tokio::spawn(future).wait().unwrap();
    // }

    fn make_request_payload() -> ClientRequestPayload_0v1 {
        ClientRequestPayload_0v1 {
            stream_key: make_meaningless_stream_key(),
            sequenced_packet: SequencedPacket {
                data: b"These are the times".to_vec(),
                sequence_number: 0,
                last_data: false,
            },
            target_hostname: Some("nowhere.com".to_string()),
            target_port: HTTP_PORT,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: PublicKey::new(&b"men's souls"[..]),
        }
    }

    #[test]
    fn a_connection_for_an_ip_address_is_created_when_necessary() {
        init_test_logging();
        let test_name = "a_connection_for_an_ip_address_is_created_when_necessary";
        let logger = Logger::new(test_name);
        let client_request_payload = make_request_payload();
        let lookup_ip_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = StreamHandlerPool::new(
            vec![
                SocketAddr::from_str("1.1.1.1:53").unwrap(),
                SocketAddr::from_str("2.2.2.2").unwrap(),
            ],
            100,
            200,
        );
        let resolver_wrapper = ResolverWrapperMock::new()
            .lookup_ip_params(&lookup_ip_params_arc)
            .lookup_ip_success(vec![
                IpAddr::from_str("1.2.3.4").unwrap(),
                IpAddr::from_str("2.3.4.5").unwrap(),
            ]);
        let make_params_arc = Arc::new(Mutex::new(vec![]));
        let resolver_factory = ResolverWrapperFactoryMock::new()
            .make_params(&make_params_arc)
            .make_result(Box::new(resolver_wrapper));
        subject.resolver_factory = Box::new(resolver_factory);
        let (async_pair_factory, _) = AsyncPairFactoryMock::mock_and_outgoing_data(vec![]);
        subject.async_pair_factory = Box::new(async_pair_factory);
        subject.logger = logger;
        let system = System::new();
        let (shp_recorder, _, shp_recording_arc) = make_recorder();
        let subject_addr = subject.start();
        subject_addr
            .try_send(SetPrivateSubsMessage {
                recorder: shp_recorder,
            })
            .unwrap();
        let bind_message = BindMessage {
            peer_actors: peer_actors_builder().build(),
        };
        subject_addr.try_send(bind_message).unwrap();
        let stream_key = client_request_payload.stream_key.clone();
        let inner_stream_key = stream_key.clone();
        let data_len = client_request_payload.sequenced_packet.data.len();
        let sequence_number = client_request_payload.sequenced_packet.sequence_number;
        let last_data = client_request_payload.sequenced_packet.last_data;
        let target_hostname = client_request_payload.target_hostname.clone();
        let target_port = client_request_payload.target_port;
        let proxy_protocol = client_request_payload.protocol;
        let originator_public_key = client_request_payload.originator_public_key.clone();
        let paying_wallet = Wallet::new("Customer");
        let process_package_message = ProcessPackageMessage {
            payload: client_request_payload,
            paying_wallet_opt: Some(paying_wallet.clone()),
        };
        let inner_process_package_message = process_package_message.clone();

        subject_addr.try_send(process_package_message).unwrap();

        subject_addr
            .try_send(AssertionsMessage {
                assertions: Box::new(move |mut shp| {
                    let mut stream_pair: &StreamPair =
                        shp.stream_pairs.get_mut(&inner_stream_key).unwrap();
                    assert_eq!(stream_pair.writer_opt, None);
                    assert_eq!(stream_pair.reader_opt, None);
                    assert_eq!(
                        stream_pair.peer_addr,
                        SocketAddr::from_str("255.255.255.255:255").unwrap()
                    );
                    assert_eq!(
                        stream_pair.pending_data,
                        vec![inner_process_package_message]
                    );
                    assert_eq!(shp.stream_pairs.len(), 1);
                }),
            })
            .unwrap();
        system.run().unwrap();
        System::current().stop();
        let shp_recording = shp_recording_arc.lock().unwrap();
        let add_stream_pair_msg = shp_recording.get_record::<AddStreamPair>(0);
        assert_eq!(
            add_stream_pair_msg.peer_addr,
            SocketAddr::from_str("2.3.4.5:80").unwrap()
        );
        assert_eq!(add_stream_pair_msg.stream_key, stream_key);
        let tlh = TestLogHandler {};
        tlh.exists_log_containing(&format!("{} DEBUG Exiting request: Stream key '{}', {}-byte packet {}{}, target {}:{}, protocol {:?}, from {} by {}",
            test_name, stream_key, data_len, sequence_number, if last_data {" (final)"} else {""},
            if let Some(name) = target_hostname.as_ref() {name} else {"<no host>"}, target_port, proxy_protocol, paying_wallet,
            originator_public_key));
        tlh.exists_log_containing(&format!(
            "{} DEBUG Stream key '{}' unknown; creating new stream",
            test_name, stream_key
        ));
        tlh.exists_log_containing(&format!(
            "{} DEBUG Resolving host name {}",
            test_name,
            target_hostname.as_ref().unwrap()
        ));
        tlh.exists_log_containing(&format!(
            "{} INFO Resolved host name {} to [1.2.3.4, 5.6.7.8]",
            test_name,
            target_hostname.as_ref().unwrap()
        ));
        tlh.exists_log_containing(&format!(
            "{} DEBUG Connecting to 1.2.3.4:{}",
            test_name, target_port
        ));
    }

    #[test]
    fn a_dns_failure_is_reported() {
        todo!()
    }

    #[test]
    fn a_connection_failure_is_reported() {
        todo!()
    }

    #[test]
    // TODO: All the process_package_message tests after this one can just call subject.handle_process_package_message()
    fn non_terminal_payload_can_be_sent_over_existing_connection() {
        init_test_logging();
        let test_name = "non_terminal_payload_can_be_sent_over_existing_connection";
        let logger = Logger::new(test_name);
        let client_request_payload = make_request_payload();
        let mut subject = StreamHandlerPool::new(vec![], 100, 200);
        subject.resolver_factory = Box::new(ResolverWrapperFactoryMock::new());
        let (async_pair_factory, outgoing_data) =
            AsyncPairFactoryMock::mock_and_outgoing_data(vec![]);
        subject.async_pair_factory = Box::new(async_pair_factory);
        let async_write = TestAsyncWrite::new();
        let async_write_data_arc = async_write.data_arc.clone();
        let async_read = TestAsyncRead::new(vec![]);
        subject.stream_pairs.insert(
            client_request_payload.stream_key.clone(),
            StreamPair {
                peer_addr: SocketAddr::from_str("1.2.3.4:5").unwrap(),
                pending_data: VecDeque::new(),
                writer_opt: Some(Box::new(async_write)),
                reader_opt: Some(Box::new(async_read)),
            },
        );
        subject.logger = logger;
        let system = System::new();
        let (shp_recorder, _, shp_recording_arc) = make_recorder();
        let subject_addr = subject.start();
        subject_addr
            .try_send(SetPrivateSubsMessage {
                recorder: shp_recorder,
            })
            .unwrap();
        let bind_message = BindMessage {
            peer_actors: peer_actors_builder().build(),
        };
        subject_addr.try_send(bind_message).unwrap();
        let stream_key = client_request_payload.stream_key.clone();
        let inner_stream_key = stream_key.clone();
        let data = client_request_payload.sequenced_packet.data.clone();
        let data_len = data.len();
        let sequence_number = client_request_payload.sequenced_packet.sequence_number;
        let last_data = client_request_payload.sequenced_packet.last_data;
        let target_hostname = client_request_payload.target_hostname.clone();
        let target_port = client_request_payload.target_port;
        let proxy_protocol = client_request_payload.protocol;
        let originator_public_key = client_request_payload.originator_public_key.clone();
        let paying_wallet = Wallet::new("Customer");
        let process_package_message = ProcessPackageMessage {
            payload: client_request_payload,
            paying_wallet_opt: Some(paying_wallet.clone()),
        };

        subject_addr.try_send(process_package_message).unwrap();

        subject_addr
            .try_send(AssertionsMessage {
                assertions: Box::new(move |mut shp| {
                    let mut stream_pair: &StreamPair =
                        shp.stream_pairs.get_mut(&inner_stream_key).unwrap();
                    assert_eq!(stream_pair.writer_opt, None);
                    assert_eq!(stream_pair.reader_opt.is_some(), true);
                    assert_eq!(
                        stream_pair.peer_addr,
                        SocketAddr::from_str("1.2.3.4:5").unwrap()
                    );
                    assert_eq!(stream_pair.pending_data, vec![]);
                    assert_eq!(shp.stream_pairs.len(), 1);
                }),
            })
            .unwrap();
        system.run().unwrap();
        System::current().stop();
        let mut shp_recording = shp_recording_arc.lock().unwrap();
        let mut data_write_success_msg = shp_recording.get_record::<DataWriteSuccess>(0);
        assert_eq!(data_write_success_msg.stream_key, stream_key);
        assert_eq!(data_write_success_msg.last_data, false);
        let outgoing_record = async_write_data_arc.lock().unwrap().remove(0);
        assert_eq!(*outgoing_record, data);
        let tlh = TestLogHandler {};
        tlh.exists_log_containing(&format!("{} DEBUG Exiting request: Stream key '{}', {}-byte packet {}{}, target {}:{}, protocol {:?}, from {} by {}",
            test_name, stream_key, data_len, sequence_number, if last_data {" (final)"} else {""},
            if let Some(name) = target_hostname {&name} else {"<no host>"}, target_port, proxy_protocol, paying_wallet,
            originator_public_key));
        tlh.exists_log_containing(&format!(
            "{} DEBUG Writing {}-byte packet {}{} over stream {} to 1.2.3.4:5",
            test_name,
            data_len,
            sequence_number,
            if last_data { " (final)" } else { "" },
            stream_key,
        ))
    }

    #[test]
    fn terminal_payload_can_be_sent_over_existing_connection() {
        init_test_logging();
        let test_name = "terminal_payload_can_be_sent_over_existing_connection";
        let logger = Logger::new(test_name);
        let mut client_request_payload = make_request_payload();
        client_request_payload.sequenced_packet.last_data = true; // this one is terminal
        let mut subject = StreamHandlerPool::new(vec![], 100, 200);
        subject.resolver_factory = Box::new(ResolverWrapperFactoryMock::new());
        let (async_pair_factory, outgoing_data) =
            AsyncPairFactoryMock::mock_and_outgoing_data(vec![]);
        subject.async_pair_factory = Box::new(async_pair_factory);
        let async_write = TestAsyncWrite::new();
        let async_write_data_arc = async_write.data_arc.clone();
        let async_read = TestAsyncRead::new(vec![]);
        subject.stream_pairs.insert(
            client_request_payload.stream_key.clone(),
            StreamPair {
                peer_addr: SocketAddr::from_str("1.2.3.4:5").unwrap(),
                pending_data: VecDeque::new(),
                writer_opt: Some(Box::new(async_write)),
                reader_opt: Some(Box::new(async_read)),
            },
        );
        subject.logger = logger;
        let system = System::new();
        let (shp_recorder, _, shp_recording_arc) = make_recorder();
        let subject_addr = subject.start();
        subject_addr
            .try_send(SetPrivateSubsMessage {
                recorder: shp_recorder,
            })
            .unwrap();
        let bind_message = BindMessage {
            peer_actors: peer_actors_builder().build(),
        };
        subject_addr.try_send(bind_message).unwrap();
        let stream_key = client_request_payload.stream_key.clone();
        let inner_stream_key = stream_key.clone();
        let data = client_request_payload.sequenced_packet.data.clone();
        let data_len = data.len();
        let sequence_number = client_request_payload.sequenced_packet.sequence_number;
        let last_data = client_request_payload.sequenced_packet.last_data;
        let target_hostname = client_request_payload.target_hostname.clone();
        let target_port = client_request_payload.target_port;
        let proxy_protocol = client_request_payload.protocol;
        let originator_public_key = client_request_payload.originator_public_key.clone();
        let paying_wallet = Wallet::new("Customer");
        let process_package_message = ProcessPackageMessage {
            payload: client_request_payload,
            paying_wallet_opt: Some(paying_wallet.clone()),
        };

        subject_addr.try_send(process_package_message).unwrap();

        subject_addr
            .try_send(AssertionsMessage {
                assertions: Box::new(move |mut shp| {
                    let mut stream_pair: &StreamPair =
                        shp.stream_pairs.get_mut(&inner_stream_key).unwrap();
                    assert_eq!(stream_pair.writer_opt, None);
                    assert_eq!(stream_pair.reader_opt.is_some(), true);
                    assert_eq!(
                        stream_pair.peer_addr,
                        SocketAddr::from_str("1.2.3.4:5").unwrap()
                    );
                    assert_eq!(stream_pair.pending_data, vec![]);
                    assert_eq!(shp.stream_pairs.len(), 1);
                }),
            })
            .unwrap();
        system.run().unwrap();
        System::current().stop();
        let mut shp_recording = shp_recording_arc.lock().unwrap();
        let mut data_write_success_msg = shp_recording.get_record::<DataWriteSuccess>(0);
        assert_eq!(data_write_success_msg.stream_key, stream_key);
        assert_eq!(data_write_success_msg.last_data, true);
        let outgoing_record = async_write_data_arc.lock().unwrap().remove(0);
        assert_eq!(*outgoing_record, data);
        let tlh = TestLogHandler {};
        tlh.exists_log_containing(&format!("{} DEBUG Exiting request: Stream key '{}', {}-byte packet {}{}, target {}:{}, protocol {:?}, from {} by {}",
            test_name, stream_key, data_len, sequence_number, if last_data {" (final)"} else {""},
            if let Some(name) = target_hostname {&name} else {"<no host>"}, target_port, proxy_protocol, paying_wallet,
            originator_public_key));
        tlh.exists_log_containing(&format!(
            "{} DEBUG Writing {}-byte packet {}{} over stream {} to 1.2.3.4:5",
            test_name,
            data_len,
            sequence_number,
            if last_data { " (final)" } else { "" },
            stream_key,
        ))
    }

    #[test]
    fn payload_can_be_queued_if_writer_is_in_use() {
        init_test_logging();
        let test_name = "non_terminal_payload_can_be_queued_if_writer_is_in_use";
        let logger = Logger::new(test_name);
        let client_request_payload = make_request_payload();
        let mut subject = StreamHandlerPool::new(vec![], 100, 200);
        subject.resolver_factory = Box::new(ResolverWrapperFactoryMock::new());
        let (async_pair_factory, outgoing_data) =
            AsyncPairFactoryMock::mock_and_outgoing_data(vec![]);
        subject.async_pair_factory = Box::new(async_pair_factory);
        subject.stream_pairs.insert(
            client_request_payload.stream_key.clone(),
            StreamPair {
                peer_addr: SocketAddr::from_str("1.2.3.4:5").unwrap(),
                pending_data: VecDeque::new(),
                writer_opt: None, // this is important
                reader_opt: None, // this is just convenient
            },
        );
        subject.logger = logger;
        let system = System::new();
        let (shp_recorder, _, shp_recording_arc) = make_recorder();
        let subject_addr = subject.start();
        subject_addr
            .try_send(SetPrivateSubsMessage {
                recorder: shp_recorder,
            })
            .unwrap();
        let bind_message = BindMessage {
            peer_actors: peer_actors_builder().build(),
        };
        subject_addr.try_send(bind_message).unwrap();
        let stream_key = client_request_payload.stream_key.clone();
        let inner_stream_key = stream_key.clone();
        let data = client_request_payload.sequenced_packet.data.clone();
        let data_len = data.len();
        let sequence_number = client_request_payload.sequenced_packet.sequence_number;
        let last_data = client_request_payload.sequenced_packet.last_data;
        let target_hostname = client_request_payload.target_hostname.clone();
        let target_port = client_request_payload.target_port;
        let proxy_protocol = client_request_payload.protocol;
        let originator_public_key = client_request_payload.originator_public_key.clone();
        let paying_wallet = Wallet::new("Customer");
        let process_package_message = ProcessPackageMessage {
            payload: client_request_payload,
            paying_wallet_opt: Some(paying_wallet.clone()),
        };
        let assertion_process_package_message = process_package_message.clone();

        subject_addr.try_send(process_package_message).unwrap();

        subject_addr
            .try_send(AssertionsMessage {
                assertions: Box::new(move |mut shp| {
                    let mut stream_pair: &StreamPair =
                        shp.stream_pairs.get_mut(&inner_stream_key).unwrap();
                    assert_eq!(stream_pair.writer_opt, None);
                    assert_eq!(
                        stream_pair.peer_addr,
                        SocketAddr::from_str("1.2.3.4:5").unwrap()
                    );
                    assert_eq!(
                        stream_pair.pending_data,
                        vec![assertion_process_package_message]
                    );
                    assert_eq!(shp.stream_pairs.len(), 1);
                }),
            })
            .unwrap();
        system.run().unwrap();
        System::current().stop();
        let tlh = TestLogHandler {};
        tlh.exists_log_containing(&format!("{} DEBUG Exiting request: Stream key '{}', {}-byte packet {}{}, target {}:{}, protocol {:?}, from {} by {}",
            test_name, stream_key, data_len, sequence_number, if last_data {" (final)"} else {""},
            if let Some(name) = target_hostname {&name} else {"<no host>"}, target_port, proxy_protocol, paying_wallet,
            originator_public_key));
        tlh.exists_log_containing(&format!(
            "{} DEBUG Stream {} to 1.2.3.4:5 is busy; queuing {}-byte packet {}{}",
            test_name,
            stream_key,
            data_len,
            sequence_number,
            if last_data { " (final)" } else { "" }
        ));
    }

    #[test]
    fn non_terminal_and_terminal_packets_are_properly_read_and_reported() {
        todo!()
    }

    // #[test]
    // fn dns_resolution_failure_sends_a_message_to_proxy_client() {
    //     let stream_key = make_meaningless_stream_key();
    //     let (proxy_client, _, proxy_client_recording) = make_recorder();
    //     let (accountant, _, accountant_recording) = make_recorder();
    //     let peer_actors = peer_actors_builder()
    //         .proxy_client(proxy_client)
    //         .accountant(accountant)
    //         .build();
    //     let transmitted_chunks_arc = Arc::new(Mutex::new(vec![]));
    //     let stream_connector = StreamConnectorMock::new();
    //     let resolver =
    //         ResolverWrapperMock::new().lookup_ip_failure(ResolveErrorKind::Io.into());
    //     let logger = Logger::new("dns_resolution_failure_sends_a_message_to_proxy_client");
    //     let payload = ClientRequestPayload_0v1 {
    //         stream_key,
    //         sequenced_packet: SequencedPacket::new(b"booga".to_vec(), 0, false),
    //         target_hostname: Some("www.example.com".to_string()),
    //         target_port: HTTP_PORT,
    //         protocol: ProxyProtocol::HTTP,
    //         originator_public_key: PublicKey::new(b"Originator"),
    //     };
    //     let system = System::new();
    //     let mut subject = StreamHandlerPoolReal::new (
    //         main_cryptde(),
    //         peer_actors.accountant.report_exit_service_provided.clone(),
    //         peer_actors.proxy_client_opt.clone().unwrap(),
    //         Default::default(),
    //         Default::default()
    //     );
    //     subject.resolver = Box::new(resolver);
    //     subject.stream_connector = Box::new(stream_connector);
    //     subject.logger = logger;
    //
    //     run_process_package(subject, payload, Wallet::new("irrelevant"));
    //
    //     System::current().stop();
    //     system.run().unwrap();
    //     assert_eq!(
    //         proxy_client_recording
    //             .lock()
    //             .unwrap()
    //             .get_record::<DnsResolveFailure_0v1>(0),
    //         &DnsResolveFailure_0v1::new(stream_key),
    //     );
    //     assert_eq!(
    //         accountant_recording.lock().unwrap().len(),
    //         0
    //     );
    // }

    #[test]
    fn read_failure_for_existing_stream_generates_termination_message() {
        todo!()
    }

    // DataWriteSuccess
    #[test]
    fn data_write_success_with_nonterminal_packet_with_nothing_waiting() {
        todo!()
    }

    #[test]
    fn data_write_success_with_terminal_packet_with_nothing_waiting() {
        todo!()
    }

    #[test]
    fn data_write_success_with_nonterminal_packet_with_queued_data() {
        todo!()
    }

    #[test]
    fn data_write_success_with_terminal_packet_with_queued_data() {
        // TODO: How do we deal with this? A new connection, or not?
        todo!()
    }

    #[test]
    fn data_write_success_when_stream_pair_is_gone() {
        todo!()
    }

    // DataWriteError
    #[test]
    fn data_write_error_with_nonterminal_packet_with_nothing_waiting() {
        todo!()
    }

    #[test]
    fn data_write_error_with_terminal_packet_with_nothing_waiting() {
        todo!()
    }

    #[test]
    fn data_write_error_with_nonterminal_packet_with_queued_data() {
        todo!()
    }

    #[test]
    fn data_write_error_with_terminal_packet_with_queued_data() {
        // TODO: How do we deal with this? A new connection, or not?
        todo!()
    }

    #[test]
    fn data_write_error_when_stream_pair_is_gone() {
        todo!()
    }

    // DataReadSuccess
    #[test]
    fn data_read_success_handles_nonterminal_followed_by_terminal() {
        todo!()
    }

    // DataReadError
    #[test]
    fn data_read_error_handles_nonterminal_followed_by_terminal() {
        todo!()
    }

    // AddStreamPair
    #[test]
    fn add_stream_pair_populates_stream_pair_and_sends_first_queue_entry() {
        todo!()
    }

    // StreamCreationError
    #[test]
    fn stream_creation_error_is_reported() {
        todo!()
    }

    // KillStream
    #[test]
    fn kill_stream_works_when_writer_is_present() {
        todo!()
    }

    #[test]
    fn kill_stream_works_when_writer_is_busy() {
        todo!()
    }

    // #[test]
    // fn write_failure_for_nonexistent_stream_generates_termination_message() {
    //     init_test_logging();
    //     let cryptde = main_cryptde();
    //     let (proxy_client, proxy_client_awaiter, proxy_client_recording_arc) = make_recorder();
    //     let originator_key = PublicKey::new(&b"men's souls"[..]);
    //     thread::spawn(move || {
    //         let client_request_payload = ClientRequestPayload_0v1 {
    //             stream_key: make_meaningless_stream_key(),
    //             sequenced_packet: SequencedPacket {
    //                 data: b"These are the times".to_vec(),
    //                 sequence_number: 0,
    //                 last_data: false,
    //             },
    //             target_hostname: Some(String::from("that.try")),
    //             target_port: HTTP_PORT,
    //             protocol: ProxyProtocol::HTTP,
    //             originator_public_key: originator_key,
    //         };
    //         let package = ExpiredCoresPackage::new(
    //             SocketAddr::from_str("1.2.3.4:1234").unwrap(),
    //             Some(make_wallet("consuming")),
    //             make_meaningless_route(),
    //             client_request_payload.clone().into(),
    //             0,
    //         );
    //         let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();
    //         let resolver = ResolverWrapperMock::new()
    //             .lookup_ip_success(vec![IpAddr::from_str("2.3.4.5").unwrap()]);
    //
    //         let tx_to_write = SenderWrapperMock::new(SocketAddr::from_str("2.3.4.5:80").unwrap())
    //             .unbounded_send_result(make_send_error(
    //                 client_request_payload.sequenced_packet.clone(),
    //             ));
    //
    //         let subject = StreamHandlerPoolReal::new(
    //             Box::new(resolver),
    //             cryptde,
    //             peer_actors.accountant.report_exit_service_provided.clone(),
    //             peer_actors.proxy_client_opt.unwrap().clone(),
    //             100,
    //             200,
    //         );
    //         subject
    //             .inner
    //             .lock()
    //             .unwrap()
    //             .stream_writer_channels
    //             .insert(client_request_payload.stream_key, Box::new(tx_to_write));
    //
    //         run_process_package(subject, package);
    //     });
    //     proxy_client_awaiter.await_message_count(1);
    //     let proxy_client_recording = proxy_client_recording_arc.lock().unwrap();
    //     assert_eq!(
    //         proxy_client_recording.get_record::<InboundServerData>(0),
    //         &InboundServerData {
    //             stream_key: make_meaningless_stream_key(),
    //             last_data: true,
    //             sequence_number: 0,
    //             source: SocketAddr::from_str("2.3.4.5:80").unwrap(),
    //             data: vec![],
    //         }
    //     );
    // }

    // #[test]
    // fn when_hostname_is_ip_establish_stream_without_dns_lookup() {
    //     let cryptde = main_cryptde();
    //     let lookup_ip_parameters = Arc::new(Mutex::new(vec![]));
    //     let expected_lookup_ip_parameters = lookup_ip_parameters.clone();
    //     let write_parameters = Arc::new(Mutex::new(vec![]));
    //     let expected_write_parameters = write_parameters.clone();
    //     let (proxy_client, proxy_client_awaiter, proxy_client_recording_arc) = make_recorder();
    //     thread::spawn(move || {
    //         let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();
    //         let client_request_payload = ClientRequestPayload_0v1 {
    //             stream_key: make_meaningless_stream_key(),
    //             sequenced_packet: SequencedPacket {
    //                 data: b"These are the times".to_vec(),
    //                 sequence_number: 0,
    //                 last_data: false,
    //             },
    //             target_hostname: Some(String::from("3.4.5.6:80")),
    //             target_port: HTTP_PORT,
    //             protocol: ProxyProtocol::HTTP,
    //             originator_public_key: PublicKey::new(&b"men's souls"[..]),
    //         };
    //         let package = ExpiredCoresPackage::new(
    //             SocketAddr::from_str("1.2.3.4:1234").unwrap(),
    //             Some(make_wallet("consuming")),
    //             make_meaningless_route(),
    //             client_request_payload.into(),
    //             0,
    //         );
    //         let resolver = ResolverWrapperMock::new()
    //             .lookup_ip_params(&lookup_ip_parameters)
    //             .lookup_ip_success(vec![
    //                 IpAddr::from_str("2.3.4.5").unwrap(),
    //                 IpAddr::from_str("3.4.5.6").unwrap(),
    //             ]);
    //         let peer_addr = SocketAddr::from_str("3.4.5.6:80").unwrap();
    //         let first_read_result = b"HTTP/1.1 200 OK\r\n\r\n";
    //         let reader = ReadHalfWrapperMock {
    //             poll_read_results: vec![
    //                 (
    //                     first_read_result.to_vec(),
    //                     Ok(Async::Ready(first_read_result.len())),
    //                 ),
    //                 (vec![], Err(Error::from(ErrorKind::ConnectionAborted))),
    //             ],
    //         };
    //         let writer = WriteHalfWrapperMock {
    //             poll_write_params: write_parameters,
    //             poll_write_results: vec![Ok(Async::Ready(first_read_result.len()))],
    //             shutdown_results: Arc::new(Mutex::new(vec![])),
    //         };
    //         let mut subject = StreamHandlerPoolReal::new(
    //             Box::new(resolver),
    //             cryptde,
    //             peer_actors.accountant.report_exit_service_provided.clone(),
    //             peer_actors.proxy_client_opt.unwrap().clone(),
    //             100,
    //             200,
    //         );
    //         let (stream_killer_tx, stream_killer_rx) =unbounded_channel();
    //         subject.stream_killer_rx = stream_killer_rx;
    //         let (stream_adder_tx, _stream_adder_rx) =unbounded_channel();
    //         {
    //             let mut inner = subject.inner.lock().unwrap();
    //             let establisher = StreamEstablisher {
    //                 cryptde,
    //                 stream_adder_tx,
    //                 stream_killer_tx,
    //                 stream_connector: Box::new(StreamConnectorMock::new().with_connection(
    //                     peer_addr.clone(),
    //                     peer_addr.clone(),
    //                     reader,
    //                     writer,
    //                 )),
    //                 proxy_client_sub: inner.proxy_client_subs.inbound_server_data.clone(),
    //                 logger: inner.logger.clone(),
    //                 channel_factory: Box::new(FuturesChannelFactoryReal {}),
    //             };
    //
    //             inner.establisher_factory = Box::new(StreamEstablisherFactoryMock {
    //                 make_results: RefCell::new(vec![establisher]),
    //             });
    //         }
    //
    //         run_process_package(subject, package);
    //     });
    //
    //     proxy_client_awaiter.await_message_count(1);
    //     assert_eq!(
    //         expected_lookup_ip_parameters.lock().unwrap().deref(),
    //         &(vec![] as Vec<String>)
    //     );
    //     assert_eq!(
    //         expected_write_parameters.lock().unwrap().remove(0),
    //         b"These are the times".to_vec()
    //     );
    //     let proxy_client_recording = proxy_client_recording_arc.lock().unwrap();
    //     assert_eq!(
    //         proxy_client_recording.get_record::<InboundServerData>(0),
    //         &InboundServerData {
    //             stream_key: make_meaningless_stream_key(),
    //             last_data: false,
    //             sequence_number: 0,
    //             source: SocketAddr::from_str("3.4.5.6:80").unwrap(),
    //             data: b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
    //         }
    //     );
    // }

    // #[test]
    // fn ip_is_parsed_even_without_port() {
    //     let cryptde = main_cryptde();
    //     let lookup_ip_parameters = Arc::new(Mutex::new(vec![]));
    //     let expected_lookup_ip_parameters = lookup_ip_parameters.clone();
    //     let write_parameters = Arc::new(Mutex::new(vec![]));
    //     let expected_write_parameters = write_parameters.clone();
    //     let (proxy_client, proxy_client_awaiter, proxy_client_recording_arc) = make_recorder();
    //     thread::spawn(move || {
    //         let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();
    //         let client_request_payload = ClientRequestPayload_0v1 {
    //             stream_key: make_meaningless_stream_key(),
    //             sequenced_packet: SequencedPacket {
    //                 data: b"These are the times".to_vec(),
    //                 sequence_number: 0,
    //                 last_data: false,
    //             },
    //             target_hostname: Some(String::from("3.4.5.6")),
    //             target_port: HTTP_PORT,
    //             protocol: ProxyProtocol::HTTP,
    //             originator_public_key: PublicKey::new(&b"men's souls"[..]),
    //         };
    //         let package = ExpiredCoresPackage::new(
    //             SocketAddr::from_str("1.2.3.4:1234").unwrap(),
    //             Some(make_wallet("consuming")),
    //             make_meaningless_route(),
    //             client_request_payload.into(),
    //             0,
    //         );
    //         let resolver = ResolverWrapperMock::new()
    //             .lookup_ip_params(&lookup_ip_parameters)
    //             .lookup_ip_success(vec![
    //                 IpAddr::from_str("2.3.4.5").unwrap(),
    //                 IpAddr::from_str("3.4.5.6").unwrap(),
    //             ]);
    //         let peer_addr = SocketAddr::from_str("3.4.5.6:80").unwrap();
    //         let first_read_result = b"HTTP/1.1 200 OK\r\n\r\n";
    //         let reader = ReadHalfWrapperMock {
    //             poll_read_results: vec![
    //                 (
    //                     first_read_result.to_vec(),
    //                     Ok(Async::Ready(first_read_result.len())),
    //                 ),
    //                 (vec![], Err(Error::from(ErrorKind::ConnectionAborted))),
    //             ],
    //         };
    //         let writer = WriteHalfWrapperMock {
    //             poll_write_params: write_parameters,
    //             poll_write_results: vec![Ok(Async::Ready(first_read_result.len()))],
    //             shutdown_results: Arc::new(Mutex::new(vec![])),
    //         };
    //         let mut subject = StreamHandlerPoolReal::new(
    //             Box::new(resolver),
    //             cryptde,
    //             peer_actors.accountant.report_exit_service_provided.clone(),
    //             peer_actors.proxy_client_opt.unwrap().clone(),
    //             100,
    //             200,
    //         );
    //         let (stream_killer_tx, stream_killer_rx) =unbounded_channel();
    //         subject.stream_killer_rx = stream_killer_rx;
    //         let (stream_adder_tx, _stream_adder_rx) =unbounded_channel();
    //         {
    //             let mut inner = subject.inner.lock().unwrap();
    //             let establisher = StreamEstablisher {
    //                 cryptde,
    //                 stream_adder_tx,
    //                 stream_killer_tx,
    //                 stream_connector: Box::new(StreamConnectorMock::new().with_connection(
    //                     peer_addr.clone(),
    //                     peer_addr.clone(),
    //                     reader,
    //                     writer,
    //                 )),
    //                 proxy_client_sub: inner.proxy_client_subs.inbound_server_data.clone(),
    //                 logger: inner.logger.clone(),
    //                 channel_factory: Box::new(FuturesChannelFactoryReal {}),
    //             };
    //
    //             inner.establisher_factory = Box::new(StreamEstablisherFactoryMock {
    //                 make_results: RefCell::new(vec![establisher]),
    //             });
    //         }
    //
    //         run_process_package(subject, package);
    //     });
    //
    //     proxy_client_awaiter.await_message_count(1);
    //     assert_eq!(
    //         expected_lookup_ip_parameters.lock().unwrap().deref(),
    //         &(vec![] as Vec<String>)
    //     );
    //     assert_eq!(
    //         expected_write_parameters.lock().unwrap().remove(0),
    //         b"These are the times".to_vec()
    //     );
    //     let proxy_client_recording = proxy_client_recording_arc.lock().unwrap();
    //     assert_eq!(
    //         proxy_client_recording.get_record::<InboundServerData>(0),
    //         &InboundServerData {
    //             stream_key: make_meaningless_stream_key(),
    //             last_data: false,
    //             sequence_number: 0,
    //             source: SocketAddr::from_str("3.4.5.6:80").unwrap(),
    //             data: b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
    //         }
    //     );
    // }

    // #[test]
    // fn missing_hostname_for_nonexistent_stream_generates_log_and_termination_message() {
    //     init_test_logging();
    //     let cryptde = main_cryptde();
    //     let (proxy_client, proxy_client_awaiter, proxy_client_recording_arc) = make_recorder();
    //     let originator_key = PublicKey::new(&b"men's souls"[..]);
    //     thread::spawn(move || {
    //         let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();
    //         let client_request_payload = ClientRequestPayload_0v1 {
    //             stream_key: make_meaningless_stream_key(),
    //             sequenced_packet: SequencedPacket {
    //                 data: b"These are the times".to_vec(),
    //                 sequence_number: 0,
    //                 last_data: false,
    //             },
    //             target_hostname: None,
    //             target_port: HTTP_PORT,
    //             protocol: ProxyProtocol::HTTP,
    //             originator_public_key: originator_key,
    //         };
    //         let package = ExpiredCoresPackage::new(
    //             SocketAddr::from_str("1.2.3.4:1234").unwrap(),
    //             Some(make_wallet("consuming")),
    //             make_meaningless_route(),
    //             client_request_payload.into(),
    //             0,
    //         );
    //         let resolver =
    //             ResolverWrapperMock::new().lookup_ip_failure(ResolveErrorKind::Io.into());
    //         let subject = StreamHandlerPoolReal::new(
    //             Box::new(resolver),
    //             cryptde,
    //             peer_actors.accountant.report_exit_service_provided.clone(),
    //             peer_actors.proxy_client_opt.unwrap().clone(),
    //             100,
    //             200,
    //         );
    //
    //         run_process_package(subject, package);
    //     });
    //
    //     proxy_client_awaiter.await_message_count(1);
    //     let proxy_client_recording = proxy_client_recording_arc.lock().unwrap();
    //     assert_eq!(
    //         proxy_client_recording.get_record::<InboundServerData>(0),
    //         &InboundServerData {
    //             stream_key: make_meaningless_stream_key(),
    //             last_data: true,
    //             sequence_number: 0,
    //             source: error_socket_addr(),
    //             data: vec![],
    //         }
    //     );
    //     TestLogHandler::new().exists_log_containing(
    //         format!(
    //             "ERROR: ProxyClient: Cannot open new stream with key {:?}: no hostname supplied",
    //             make_meaningless_stream_key()
    //         )
    //         .as_str(),
    //     );
    // }

    // #[test]
    // fn failing_to_make_a_connection_sends_an_error_response() {
    //     let cryptde = main_cryptde();
    //     let stream_key = make_meaningless_stream_key();
    //     let lookup_ip_parameters = Arc::new(Mutex::new(vec![]));
    //     let (proxy_client, proxy_client_awaiter, proxy_client_recording_arc) = make_recorder();
    //     let originator_key = PublicKey::new(&b"men's souls"[..]);
    //     thread::spawn(move || {
    //         let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();
    //         let client_request_payload = ClientRequestPayload_0v1 {
    //             stream_key,
    //             sequenced_packet: SequencedPacket {
    //                 data: b"These are the times".to_vec(),
    //                 sequence_number: 0,
    //                 last_data: false,
    //             },
    //             target_hostname: Some(String::from("that.try")),
    //             target_port: HTTP_PORT,
    //             protocol: ProxyProtocol::HTTP,
    //             originator_public_key: originator_key,
    //         };
    //         let package = ExpiredCoresPackage::new(
    //             SocketAddr::from_str("1.2.3.4:1234").unwrap(),
    //             Some(make_wallet("consuming")),
    //             make_meaningless_route(),
    //             client_request_payload.into(),
    //             0,
    //         );
    //         let resolver = ResolverWrapperMock::new()
    //             .lookup_ip_params(&lookup_ip_parameters)
    //             .lookup_ip_success(vec![
    //                 IpAddr::from_str("2.3.4.5").unwrap(),
    //                 IpAddr::from_str("3.4.5.6").unwrap(),
    //             ]);
    //         let proxy_client_sub = peer_actors
    //             .proxy_client_opt
    //             .clone()
    //             .unwrap()
    //             .inbound_server_data;
    //         let mut subject = StreamHandlerPoolReal::new(
    //             Box::new(resolver),
    //             cryptde,
    //             peer_actors.accountant.report_exit_service_provided.clone(),
    //             peer_actors.proxy_client_opt.clone().unwrap(),
    //             100,
    //             200,
    //         );
    //         let (stream_killer_tx, stream_killer_rx) =unbounded_channel();
    //         subject.stream_killer_rx = stream_killer_rx;
    //         let (stream_adder_tx, _stream_adder_rx) =unbounded_channel();
    //         let establisher = StreamEstablisher {
    //             cryptde,
    //             stream_adder_tx,
    //             stream_killer_tx,
    //             stream_connector: Box::new(
    //                 StreamConnectorMock::new()
    //                     .connect_pair_result(Err(Error::from(ErrorKind::Other))),
    //             ),
    //             proxy_client_sub,
    //             logger: subject.inner.lock().unwrap().logger.clone(),
    //             channel_factory: Box::new(FuturesChannelFactoryReal {}),
    //         };
    //
    //         subject.inner.lock().unwrap().establisher_factory =
    //             Box::new(StreamEstablisherFactoryMock {
    //                 make_results: RefCell::new(vec![establisher]),
    //             });
    //
    //         run_process_package(subject, package);
    //     });
    //
    //     proxy_client_awaiter.await_message_count(1);
    //     let proxy_client_recording = proxy_client_recording_arc.lock().unwrap();
    //     assert_eq!(
    //         proxy_client_recording.get_record::<InboundServerData>(0),
    //         &InboundServerData {
    //             stream_key,
    //             last_data: true,
    //             sequence_number: 0,
    //             source: error_socket_addr(),
    //             data: vec![],
    //         }
    //     );
    // }

    // #[test]
    // fn trying_to_write_to_disconnected_stream_writer_sends_an_error_response() {
    //     let cryptde = main_cryptde();
    //     let stream_key = make_meaningless_stream_key();
    //     let lookup_ip_parameters = Arc::new(Mutex::new(vec![]));
    //     let write_parameters = Arc::new(Mutex::new(vec![]));
    //     let (proxy_client, proxy_client_awaiter, proxy_client_recording_arc) = make_recorder();
    //     let (stream_adder_tx, _stream_adder_rx) =unbounded_channel();
    //
    //     thread::spawn(move || {
    //         let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();
    //
    //         let sequenced_packet = SequencedPacket {
    //             data: b"These are the times".to_vec(),
    //             sequence_number: 0,
    //             last_data: false,
    //         };
    //
    //         let client_request_payload = ClientRequestPayload_0v1 {
    //             stream_key,
    //             sequenced_packet: sequenced_packet.clone(),
    //             target_hostname: Some(String::from("that.try")),
    //             target_port: HTTP_PORT,
    //             protocol: ProxyProtocol::HTTP,
    //             originator_public_key: PublicKey::new(&b"men's souls"[..]),
    //         };
    //
    //         let package = ExpiredCoresPackage::new(
    //             SocketAddr::from_str("1.2.3.4:1234").unwrap(),
    //             Some(make_wallet("consuming")),
    //             make_meaningless_route(),
    //             client_request_payload.into(),
    //             0,
    //         );
    //
    //         let resolver = ResolverWrapperMock::new()
    //             .lookup_ip_params(&lookup_ip_parameters)
    //             .lookup_ip_success(vec![
    //                 IpAddr::from_str("2.3.4.5").unwrap(),
    //                 IpAddr::from_str("3.4.5.6").unwrap(),
    //             ]);
    //
    //         let reader = ReadHalfWrapperMock {
    //             poll_read_results: vec![
    //                 (vec![], Ok(Async::NotReady)),
    //                 (vec![], Err(Error::from(ErrorKind::ConnectionAborted))),
    //             ],
    //         };
    //         let writer = WriteHalfWrapperMock {
    //             poll_write_params: write_parameters,
    //             poll_write_results: vec![Ok(Async::NotReady)],
    //             shutdown_results: Arc::new(Mutex::new(vec![])),
    //         };
    //
    //         let mut subject = StreamHandlerPoolReal::new(
    //             Box::new(resolver),
    //             cryptde,
    //             peer_actors.accountant.report_exit_service_provided.clone(),
    //             peer_actors.proxy_client_opt.clone().unwrap(),
    //             100,
    //             200,
    //         );
    //
    //         let peer_addr = SocketAddr::from_str("3.4.5.6:80").unwrap();
    //         let disconnected_sender = Box::new(
    //             SenderWrapperMock::new(peer_addr)
    //                 .unbounded_send_result(make_send_error(sequenced_packet)),
    //         );
    //
    //         let (stream_killer_tx, stream_killer_rx) =unbounded_channel();
    //         subject.stream_killer_rx = stream_killer_rx;
    //
    //         {
    //             let mut inner = subject.inner.lock().unwrap();
    //             let establisher = StreamEstablisher {
    //                 cryptde,
    //                 stream_adder_tx,
    //                 stream_killer_tx,
    //                 stream_connector: Box::new(
    //                     StreamConnectorMock::new()
    //                         .with_connection(peer_addr, peer_addr, reader, writer),
    //                 ),
    //                 proxy_client_sub: peer_actors
    //                     .proxy_client_opt
    //                     .clone()
    //                     .unwrap()
    //                     .inbound_server_data,
    //                 logger: inner.logger.clone(),
    //                 channel_factory: Box::new(FuturesChannelFactoryMock {
    //                     results: vec![(
    //                         disconnected_sender,
    //                         Box::new(ReceiverWrapperMock {
    //                             poll_results: vec![Ok(Async::Ready(None))],
    //                         }),
    //                     )],
    //                 }),
    //             };
    //
    //             inner.establisher_factory = Box::new(StreamEstablisherFactoryMock {
    //                 make_results: RefCell::new(vec![establisher]),
    //             });
    //         }
    //         run_process_package(subject, package);
    //     });
    //
    //     proxy_client_awaiter.await_message_count(1);
    //     let proxy_client_recording = proxy_client_recording_arc.lock().unwrap();
    //     assert_eq!(
    //         proxy_client_recording.get_record::<InboundServerData>(0),
    //         &InboundServerData {
    //             stream_key,
    //             last_data: true,
    //             sequence_number: 0,
    //             source: error_socket_addr(),
    //             data: vec![],
    //         }
    //     );
    // }

    // #[test]
    // fn bad_dns_lookup_produces_log_and_sends_error_response() {
    //     todo!("Convert me");
    //     init_test_logging();
    //     let cryptde = main_cryptde();
    //     let stream_key = make_meaningless_stream_key();
    //     let (proxy_client, proxy_client_awaiter, proxy_client_recording_arc) = make_recorder();
    //     let originator_key = PublicKey::new(&b"men's souls"[..]);
    //     thread::spawn(move || {
    //         let client_request_payload = ClientRequestPayload_0v1 {
    //             stream_key,
    //             sequenced_packet: SequencedPacket {
    //                 data: b"These are the times".to_vec(),
    //                 sequence_number: 0,
    //                 last_data: true,
    //             },
    //             target_hostname: Some(String::from("that.try")),
    //             target_port: HTTP_PORT,
    //             protocol: ProxyProtocol::HTTP,
    //             originator_public_key: originator_key,
    //         };
    //         let package = ExpiredCoresPackage::new(
    //             SocketAddr::from_str("1.2.3.4:1234").unwrap(),
    //             Some(make_wallet("consuming")),
    //             make_meaningless_route(),
    //             client_request_payload.into(),
    //             0,
    //         );
    //         let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();
    //         let mut lookup_ip_parameters = Arc::new(Mutex::new(vec![]));
    //         let resolver = ResolverWrapperMock::new()
    //             .lookup_ip_params(&mut lookup_ip_parameters)
    //             .lookup_ip_failure(ResolveErrorKind::Io.into());
    //         let subject = StreamHandlerPoolReal::new(
    //             Box::new(resolver),
    //             cryptde,
    //             peer_actors.accountant.report_exit_service_provided.clone(),
    //             peer_actors.proxy_client_opt.unwrap().clone(),
    //             100,
    //             200,
    //         );
    //         subject.inner.lock().unwrap().logger =
    //             Logger::new("bad_dns_lookup_produces_log_and_sends_error_response");
    //         run_process_package(subject, package);
    //     });
    //     proxy_client_awaiter.await_message_count(2);
    //     let recording = proxy_client_recording_arc.lock().unwrap();
    //     assert_eq!(
    //         recording.get_record::<InboundServerData>(1),
    //         &InboundServerData {
    //             stream_key,
    //             last_data: true,
    //             sequence_number: 0,
    //             source: error_socket_addr(),
    //             data: vec![],
    //         }
    //     );
    //     TestLogHandler::new().exists_log_containing(
    //         "ERROR: bad_dns_lookup_produces_log_and_sends_error_response: Could not find IP address for host that.try: io error",
    //     );
    // }

    // #[test]
    // fn error_from_tx_to_writer_removes_stream() {
    //     init_test_logging();
    //     let cryptde = main_cryptde();
    //     let stream_key = make_meaningless_stream_key();
    //     let (proxy_client, _, _) = make_recorder();
    //     let (hopper, _, _) = make_recorder();
    //     let (accountant, _, _) = make_recorder();
    //     let sequenced_packet = SequencedPacket {
    //         data: b"These are the times".to_vec(),
    //         sequence_number: 0,
    //         last_data: true,
    //     };
    //     let client_request_payload = ClientRequestPayload_0v1 {
    //         stream_key: stream_key.clone(),
    //         sequenced_packet: sequenced_packet.clone(),
    //         target_hostname: Some(String::from("that.try")),
    //         target_port: HTTP_PORT,
    //         protocol: ProxyProtocol::HTTP,
    //         originator_public_key: PublicKey::new(&b"men's souls"[..]),
    //     };
    //     let package = ExpiredCoresPackage::new(
    //         SocketAddr::from_str("1.2.3.4:1234").unwrap(),
    //         Some(make_wallet("consuming")),
    //         make_meaningless_route(),
    //         client_request_payload.into(),
    //         0,
    //     );
    //     let send_params = Arc::new(Mutex::new(vec![]));
    //     let sender_wrapper = SenderWrapperMock::new(SocketAddr::from_str("1.2.3.4:5678").unwrap())
    //         .unbounded_send_params(&send_params)
    //         .unbounded_send_result(make_send_error(sequenced_packet.clone()));
    //     thread::spawn(move || {
    //         let resolver = ResolverWrapperMock::new();
    //         let peer_actors = peer_actors_builder()
    //             .hopper(hopper)
    //             .accountant(accountant)
    //             .proxy_client(proxy_client)
    //             .build();
    //
    //         let subject = StreamHandlerPoolReal::new(
    //             Box::new(resolver),
    //             cryptde,
    //             peer_actors.accountant.report_exit_service_provided.clone(),
    //             peer_actors.proxy_client_opt.unwrap().clone(),
    //             100,
    //             200,
    //         );
    //         subject
    //             .inner
    //             .lock()
    //             .unwrap()
    //             .stream_writer_channels
    //             .insert(stream_key, Box::new(sender_wrapper));
    //
    //         run_process_package(subject, package);
    //     });
    //
    //     await_messages(1, &send_params);
    //     assert_eq!(*send_params.lock().unwrap(), vec!(sequenced_packet));
    //
    //     let tlh = TestLogHandler::new();
    //     tlh.await_log_containing("Removing stream writer for 1.2.3.4:5678", 1000);
    // }

    // #[test]
    // fn process_package_does_not_create_new_connection_for_zero_length_data_with_unfamiliar_stream_key(
    // ) {
    //     init_test_logging();
    //     let cryptde = main_cryptde();
    //     let (hopper, _, hopper_recording_arc) = make_recorder();
    //     let (accountant, _, accountant_recording_arc) = make_recorder();
    //     thread::spawn(move || {
    //         let peer_actors = peer_actors_builder()
    //             .hopper(hopper)
    //             .accountant(accountant)
    //             .build();
    //         let client_request_payload = ClientRequestPayload_0v1 {
    //             stream_key: make_meaningless_stream_key(),
    //             sequenced_packet: SequencedPacket {
    //                 data: vec![],
    //                 sequence_number: 0,
    //                 last_data: false,
    //             },
    //             target_hostname: None,
    //             target_port: HTTP_PORT,
    //             protocol: ProxyProtocol::HTTP,
    //             originator_public_key: PublicKey::new(&b"booga"[..]),
    //         };
    //         let package = ExpiredCoresPackage::new(
    //             SocketAddr::from_str("1.2.3.4:1234").unwrap(),
    //             Some(make_wallet("consuming")),
    //             make_meaningless_route(),
    //             client_request_payload.into(),
    //             0,
    //         );
    //         let resolver = ResolverWrapperMock::new();
    //         let subject = StreamHandlerPoolReal::new(
    //             Box::new(resolver),
    //             cryptde,
    //             peer_actors.accountant.report_exit_service_provided.clone(),
    //             peer_actors.proxy_client_opt.unwrap().clone(),
    //             100,
    //             200,
    //         );
    //
    //         subject.inner.lock().unwrap().establisher_factory =
    //             Box::new(StreamEstablisherFactoryMock {
    //                 make_results: RefCell::new(vec![]),
    //             });
    //
    //         run_process_package(subject, package);
    //     });
    //
    //     let tlh = TestLogHandler::new();
    //     tlh.await_log_containing(
    //         &format!(
    //             "Empty request payload received for nonexistent stream {:?} - ignoring",
    //             make_meaningless_stream_key()
    //         )[..],
    //         2000,
    //     );
    //     let accountant_recording = accountant_recording_arc.lock().unwrap();
    //     assert_eq!(accountant_recording.len(), 0);
    //     let hopper_recording = hopper_recording_arc.lock().unwrap();
    //     assert_eq!(hopper_recording.len(), 0);
    // }

    // #[test]
    // fn clean_up_dead_streams_sends_server_drop_report_if_dead_stream_is_in_map() {
    //     let system = System::new();
    //     let (proxy_client, _, proxy_client_recording_arc) = make_recorder();
    //     let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();
    //     let mut subject = StreamHandlerPoolReal::new(
    //         Box::new(ResolverWrapperMock::new()),
    //         main_cryptde(),
    //         peer_actors.accountant.report_exit_service_provided,
    //         peer_actors.proxy_client_opt.unwrap(),
    //         0,
    //         0,
    //     );
    //     let (stream_killer_tx, stream_killer_rx) =unbounded_channel();
    //     subject.stream_killer_rx = stream_killer_rx;
    //     let stream_key = make_meaningless_stream_key();
    //     let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
    //     {
    //         let mut inner = subject.inner.lock().unwrap();
    //         inner
    //             .stream_writer_channels
    //             .insert(stream_key, Box::new(SenderWrapperMock::new(peer_addr)));
    //     }
    //     stream_killer_tx.send((stream_key, 47)).unwrap();
    //
    //     subject.clean_up_dead_streams();
    //
    //     System::current().stop_with_code(0);
    //     system.run();
    //     let proxy_client_recording = proxy_client_recording_arc.lock().unwrap();
    //     let report = proxy_client_recording.get_record::<InboundServerData>(0);
    //     assert_eq!(
    //         report,
    //         &InboundServerData {
    //             stream_key,
    //             last_data: true,
    //             sequence_number: 47,
    //             source: peer_addr,
    //             data: vec![]
    //         }
    //     );
    // }

    // #[test]
    // fn clean_up_dead_streams_does_not_send_server_drop_report_if_dead_stream_is_gone_already() {
    //     let system = System::new();
    //     let (proxy_client, _, proxy_client_recording_arc) = make_recorder();
    //     let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();
    //     let mut subject = StreamHandlerPoolReal::new(
    //         Box::new(ResolverWrapperMock::new()),
    //         main_cryptde(),
    //         peer_actors.accountant.report_exit_service_provided,
    //         peer_actors.proxy_client_opt.unwrap(),
    //         0,
    //         0,
    //     );
    //     let (stream_killer_tx, stream_killer_rx) =unbounded_channel();
    //     subject.stream_killer_rx = stream_killer_rx;
    //     let stream_key = make_meaningless_stream_key();
    //     stream_killer_tx.send((stream_key, 47)).unwrap();
    //
    //     subject.clean_up_dead_streams();
    //
    //     System::current().stop_with_code(0);
    //     system.run();
    //     let proxy_client_recording = proxy_client_recording_arc.lock().unwrap();
    //     assert_eq!(proxy_client_recording.len(), 0);
    // }
}
*/
