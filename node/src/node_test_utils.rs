// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
#![cfg (test)]
use std::io;
use std::io::Error;
use std::io::Write;
use std::time::SystemTime;
use std::time::Duration;
use std::cell::RefCell;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use actix::Actor;
use actix::Addr;
use actix::Handler;
use actix::Syn;
use futures::sync::mpsc::SendError;
use tokio::prelude::Async;
use sub_lib::channel_wrappers::FuturesChannelFactory;
use sub_lib::channel_wrappers::SenderWrapper;
use sub_lib::channel_wrappers::ReceiverWrapper;
use sub_lib::tokio_wrappers::ReadHalfWrapper;
use sub_lib::tokio_wrappers::WriteHalfWrapper;
use sub_lib::framer::Framer;
use sub_lib::framer::FramedChunk;
use sub_lib::stream_handler_pool::TransmitDataMsg;
use test_utils::recorder::Recorder;
use test_utils::test_utils::TestLog;
use discriminator::Discriminator;
use discriminator::DiscriminatorFactory;
use discriminator::UnmaskedChunk;
use masquerader::Masquerader;
use masquerader::MasqueradeError;
use null_masquerader::NullMasquerader;
use stream_messages::*;
use stream_handler_pool::StreamHandlerPoolSubs;

pub trait TestLogOwner {
    fn get_test_log (&self) -> Arc<Mutex<TestLog>>;
}

pub fn extract_log<T> (owner: T) -> (T, Arc<Mutex<TestLog>>) where T: TestLogOwner {
    let test_log = owner.get_test_log ();
    (owner, test_log)
}

pub struct ReadHalfWrapperMock {
    pub poll_read_results: Vec<(Vec<u8>, Result<Async<usize>, io::Error>)>,
}

impl ReadHalfWrapper for ReadHalfWrapperMock {
    fn poll_read(&mut self, buf: &mut [u8]) -> Result<Async<usize>, Error> {
        let (to_buf, ret_val) = self.poll_read_results.remove(0);
        buf.as_mut(). write(to_buf.as_slice()).is_ok();
        ret_val
    }
}

pub struct WriteHalfWrapperMock {
    pub poll_write_params: Arc<Mutex<Vec<Vec<u8>>>>,
    pub poll_write_results: Vec<(Result<Async<usize>, io::Error>)>,
}

impl WriteHalfWrapper for WriteHalfWrapperMock {
    fn poll_write(&mut self, buf: &[u8]) -> Result<Async<usize>, io::Error> {
        self.poll_write_params.lock().unwrap().push(buf.to_vec());
        self.poll_write_results.remove (0)
    }
}

pub struct ReceiverWrapperMock {
    pub poll_results: Vec<Result<Async<Option<Vec<u8>>>, ()>>
}

impl ReceiverWrapper for ReceiverWrapperMock {
    fn poll(&mut self) -> Result<Async<Option<Vec<u8>>>, ()> {
        self.poll_results.remove(0)
    }
}

impl ReceiverWrapperMock {
    pub fn new() -> ReceiverWrapperMock {
        ReceiverWrapperMock {
            poll_results: vec!()
        }
    }
}

pub struct SenderWrapperMock {
    pub unbounded_send_params: Arc<Mutex<Vec<Vec<u8>>>>,
    pub unbounded_send_results: Vec<Result<(), SendError<Vec<u8>>>>
}

impl SenderWrapper for SenderWrapperMock {
    fn unbounded_send(&mut self, data: Vec<u8>) -> Result<(), SendError<Vec<u8>>> {
        self.unbounded_send_params.lock().unwrap().push(data);
        self.unbounded_send_results.remove(0)
    }
}

impl SenderWrapperMock {
    pub fn new() -> SenderWrapperMock {
        SenderWrapperMock {
            unbounded_send_params: Arc::new(Mutex::new(vec!())),
            unbounded_send_results: vec!()
        }
    }
}

pub struct FuturesChannelFactoryMock {
    pub results: Vec<(Box<SenderWrapper>, Box<ReceiverWrapper>)>
}

impl FuturesChannelFactory for FuturesChannelFactoryMock {
    fn make(&mut self) -> (Box<SenderWrapper>, Box<ReceiverWrapper>) {
        if self.results.is_empty() {
            (Box::new(SenderWrapperMock::new()), Box::new(ReceiverWrapperMock::new()))
        } else {
            self.results.remove(0)
        }
    }
}

pub struct MasqueraderMock {
    log: Arc<Mutex<TestLog>>,
    try_unmask_results: RefCell<Vec<Option<UnmaskedChunk>>>,
    mask_results: RefCell<Vec<Result<Vec<u8>, MasqueradeError>>>
}

impl Masquerader for MasqueraderMock {
    fn try_unmask(&self, item: &[u8]) -> Option<UnmaskedChunk> {
        self.log.lock ().unwrap ().log (format! ("try_unmask (\"{}\")", String::from_utf8 (Vec::from (item)).unwrap ()));
        self.try_unmask_results.borrow_mut ().remove (0)
    }

    fn mask(&self, data: &[u8]) -> Result<Vec<u8>, MasqueradeError> {
        self.log.lock ().unwrap ().log (format! ("mask (\"{}\")", String::from_utf8 (Vec::from (data)).unwrap ()));
        self.mask_results.borrow_mut ().remove (0)
    }
}

impl TestLogOwner for MasqueraderMock {
    fn get_test_log(&self) -> Arc<Mutex<TestLog>> {
        self.log.clone ()
    }
}

impl MasqueraderMock {
    #[allow (dead_code)]
    pub fn new () -> MasqueraderMock {
        MasqueraderMock {
            log: Arc::new (Mutex::new (TestLog::new ())),
            try_unmask_results: RefCell::new (Vec::new ()),
            mask_results: RefCell::new (Vec::new ())
        }
    }

    #[allow (dead_code)]
    pub fn add_try_unmask_result (&mut self, result: Option<UnmaskedChunk>) {
        self.try_unmask_results.borrow_mut ().push (result);
    }

    #[allow (dead_code)]
    pub fn add_mask_result (&mut self, result: Result<Vec<u8>, MasqueradeError>) {
        self.mask_results.borrow_mut ().push (result);
    }
}

#[allow (dead_code)]
pub fn wait_until<F> (check: F) where F: Fn() -> bool {
    let now = SystemTime::now ();
    while !check () {
        if now.elapsed ().unwrap ().as_secs () >= 1 {
            panic! ("Waited for more than a second")
        }
        thread::sleep (Duration::from_millis (10))
    }
}

pub struct NullFramer {
    data: Vec<Vec<u8>>
}

impl Framer for NullFramer {
    fn add_data(&mut self, data: &[u8]) {
        self.data.push (Vec::from (data));
    }

    fn take_frame(&mut self) -> Option<FramedChunk> {
        if self.data.is_empty () {None} else {Some (FramedChunk {chunk: self.data.remove (0), last_chunk: true})}
    }
}

pub fn make_null_discriminator (data: Vec<Vec<u8>>) -> Discriminator {
    let framer = NullFramer {data};
    let masquerader = NullMasquerader::new ();
    Discriminator::new (Box::new (framer), vec! (Box::new (masquerader)))
}

#[derive (Debug, Clone)]
pub struct NullDiscriminatorFactory {
    discriminator_natures: RefCell<Vec<Vec<Vec<u8>>>>
}

impl DiscriminatorFactory for NullDiscriminatorFactory {
    fn make(&self) -> Discriminator {
        let data = self.discriminator_natures.borrow_mut ().remove (0);
        make_null_discriminator(data)
    }

    fn duplicate(&self) -> Box<DiscriminatorFactory> {
        Box::new (NullDiscriminatorFactory {
            discriminator_natures: self.discriminator_natures.clone ()
        })
    }
}

impl NullDiscriminatorFactory {
    pub fn new () -> NullDiscriminatorFactory {
        NullDiscriminatorFactory {
            discriminator_natures: RefCell::new (vec! ())
        }
    }

    pub fn discriminator_nature (self, data: Vec<Vec<u8>>) -> NullDiscriminatorFactory {
        self.discriminator_natures.borrow_mut ().push (data);
        self
    }
}

impl Handler<AddStreamMsg> for Recorder {
    type Result = ();

    fn handle(&mut self, msg: AddStreamMsg, _ctx: &mut Self::Context) {
        self.record (msg);
    }
}

impl Handler<RemoveStreamMsg> for Recorder {
    type Result = ();

    fn handle(&mut self, msg: RemoveStreamMsg, _ctx: &mut Self::Context) {
        self.record (msg);
    }
}

impl Handler<PoolBindMessage> for Recorder {
    type Result = ();

    fn handle(&mut self, msg: PoolBindMessage, _ctx: &mut Self::Context) {
        self.record (msg);
    }
}

pub fn make_stream_handler_pool_subs_from(stream_handler_pool_opt: Option<Recorder>) -> StreamHandlerPoolSubs {
    let stream_handler_pool = match stream_handler_pool_opt {
        Some(stream_handler_pool) => stream_handler_pool,
        None => Recorder::new()
    };

    let addr: Addr<Syn, Recorder> = stream_handler_pool.start();

    StreamHandlerPoolSubs {
        add_sub: addr.clone ().recipient::<AddStreamMsg>(),
        transmit_sub: addr.clone ().recipient::<TransmitDataMsg>(),
        remove_sub: addr.clone ().recipient::<RemoveStreamMsg>(),
        bind: addr.clone ().recipient::<PoolBindMessage>(),
    }
}
