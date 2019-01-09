// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
#![cfg (test)]
use actix::Actor;
use actix::Addr;
use actix::Handler;
use actix::Syn;
use discriminator::Discriminator;
use discriminator::DiscriminatorFactory;
use discriminator::UnmaskedChunk;
use masquerader::MasqueradeError;
use masquerader::Masquerader;
use null_masquerader::NullMasquerader;
use std::cell::RefCell;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use std::time::SystemTime;
use stream_handler_pool::StreamHandlerPoolSubs;
use stream_messages::*;
use sub_lib::framer::FramedChunk;
use sub_lib::framer::Framer;
use sub_lib::stream_handler_pool::DispatcherNodeQueryResponse;
use sub_lib::stream_handler_pool::TransmitDataMsg;
use test_utils::logging::TestLog;
use test_utils::recorder::Recorder;

pub trait TestLogOwner {
    fn get_test_log(&self) -> Arc<Mutex<TestLog>>;
}

pub fn extract_log<T>(owner: T) -> (T, Arc<Mutex<TestLog>>)
where
    T: TestLogOwner,
{
    let test_log = owner.get_test_log();
    (owner, test_log)
}

pub struct MasqueraderMock {
    log: Arc<Mutex<TestLog>>,
    try_unmask_results: RefCell<Vec<Option<UnmaskedChunk>>>,
    mask_results: RefCell<Vec<Result<Vec<u8>, MasqueradeError>>>,
}

impl Masquerader for MasqueraderMock {
    fn try_unmask(&self, item: &[u8]) -> Option<UnmaskedChunk> {
        self.log.lock().unwrap().log(format!(
            "try_unmask (\"{}\")",
            String::from_utf8(Vec::from(item)).unwrap()
        ));
        self.try_unmask_results.borrow_mut().remove(0)
    }

    fn mask(&self, data: &[u8]) -> Result<Vec<u8>, MasqueradeError> {
        self.log.lock().unwrap().log(format!(
            "mask (\"{}\")",
            String::from_utf8(Vec::from(data)).unwrap()
        ));
        self.mask_results.borrow_mut().remove(0)
    }
}

impl TestLogOwner for MasqueraderMock {
    fn get_test_log(&self) -> Arc<Mutex<TestLog>> {
        self.log.clone()
    }
}

impl MasqueraderMock {
    #[allow(dead_code)]
    pub fn new() -> MasqueraderMock {
        MasqueraderMock {
            log: Arc::new(Mutex::new(TestLog::new())),
            try_unmask_results: RefCell::new(Vec::new()),
            mask_results: RefCell::new(Vec::new()),
        }
    }

    #[allow(dead_code)]
    pub fn add_try_unmask_result(&mut self, result: Option<UnmaskedChunk>) {
        self.try_unmask_results.borrow_mut().push(result);
    }

    #[allow(dead_code)]
    pub fn add_mask_result(&mut self, result: Result<Vec<u8>, MasqueradeError>) {
        self.mask_results.borrow_mut().push(result);
    }
}

#[allow(dead_code)]
pub fn wait_until<F>(check: F)
where
    F: Fn() -> bool,
{
    let now = SystemTime::now();
    while !check() {
        if now.elapsed().unwrap().as_secs() >= 1 {
            panic!("Waited for more than a second")
        }
        thread::sleep(Duration::from_millis(10))
    }
}

pub struct NullFramer {
    data: Vec<Vec<u8>>,
}

impl Framer for NullFramer {
    fn add_data(&mut self, data: &[u8]) {
        self.data.push(Vec::from(data));
    }

    fn take_frame(&mut self) -> Option<FramedChunk> {
        if self.data.is_empty() {
            None
        } else {
            Some(FramedChunk {
                chunk: self.data.remove(0),
                last_chunk: true,
            })
        }
    }
}

pub fn make_null_discriminator(data: Vec<Vec<u8>>) -> Discriminator {
    let framer = NullFramer { data };
    let masquerader = NullMasquerader::new();
    Discriminator::new(Box::new(framer), vec![Box::new(masquerader)])
}

#[derive(Debug, Clone)]
pub struct NullDiscriminatorFactory {
    discriminator_natures: RefCell<Vec<Vec<Vec<u8>>>>,
}

impl DiscriminatorFactory for NullDiscriminatorFactory {
    fn make(&self) -> Discriminator {
        let data = self.discriminator_natures.borrow_mut().remove(0);
        make_null_discriminator(data)
    }

    fn duplicate(&self) -> Box<DiscriminatorFactory> {
        Box::new(NullDiscriminatorFactory {
            discriminator_natures: self.discriminator_natures.clone(),
        })
    }
}

impl NullDiscriminatorFactory {
    pub fn new() -> NullDiscriminatorFactory {
        NullDiscriminatorFactory {
            discriminator_natures: RefCell::new(vec![]),
        }
    }

    pub fn discriminator_nature(self, data: Vec<Vec<u8>>) -> NullDiscriminatorFactory {
        self.discriminator_natures.borrow_mut().push(data);
        self
    }
}

impl Handler<AddStreamMsg> for Recorder {
    type Result = ();

    fn handle(&mut self, msg: AddStreamMsg, _ctx: &mut Self::Context) {
        self.record(msg);
    }
}

impl Handler<RemoveStreamMsg> for Recorder {
    type Result = ();

    fn handle(&mut self, msg: RemoveStreamMsg, _ctx: &mut Self::Context) {
        self.record(msg);
    }
}

impl Handler<PoolBindMessage> for Recorder {
    type Result = ();

    fn handle(&mut self, msg: PoolBindMessage, _ctx: &mut Self::Context) {
        self.record(msg);
    }
}

pub fn make_stream_handler_pool_subs_from(
    stream_handler_pool_opt: Option<Recorder>,
) -> StreamHandlerPoolSubs {
    let stream_handler_pool = match stream_handler_pool_opt {
        Some(stream_handler_pool) => stream_handler_pool,
        None => Recorder::new(),
    };

    let addr: Addr<Syn, Recorder> = stream_handler_pool.start();

    StreamHandlerPoolSubs {
        add_sub: addr.clone().recipient::<AddStreamMsg>(),
        transmit_sub: addr.clone().recipient::<TransmitDataMsg>(),
        remove_sub: addr.clone().recipient::<RemoveStreamMsg>(),
        bind: addr.clone().recipient::<PoolBindMessage>(),
        node_query_response: addr.clone().recipient::<DispatcherNodeQueryResponse>(),
    }
}

pub struct FailingMasquerader {}

impl Masquerader for FailingMasquerader {
    fn try_unmask(&self, _item: &[u8]) -> Option<UnmaskedChunk> {
        unimplemented!()
    }

    fn mask(&self, _data: &[u8]) -> Result<Vec<u8>, MasqueradeError> {
        Err(MasqueradeError::LowLevelDataError(
            String::from_str("don't care").unwrap(),
        ))
    }
}
