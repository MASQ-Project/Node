// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
#![cfg(test)]

use crate::discriminator::Discriminator;
use crate::discriminator::DiscriminatorFactory;
use crate::discriminator::UnmaskedChunk;
use crate::masquerader::MasqueradeError;
use crate::masquerader::Masquerader;
use crate::node_configurator::DirsWrapper;
use crate::null_masquerader::NullMasquerader;
use crate::privilege_drop::IdWrapper;
use crate::stream_handler_pool::StreamHandlerPoolSubs;
use crate::stream_messages::*;
use crate::sub_lib::framer::FramedChunk;
use crate::sub_lib::framer::Framer;
use crate::sub_lib::stream_handler_pool::DispatcherNodeQueryResponse;
use crate::sub_lib::stream_handler_pool::TransmitDataMsg;
use crate::sub_lib::utils::MessageScheduler;
use crate::test_utils::recorder::Recorder;
use actix::Actor;
use actix::Addr;
use masq_lib::test_utils::logging::TestLog;
use masq_lib::ui_gateway::NodeFromUiMessage;
use std::cell::RefCell;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::time::SystemTime;

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

#[derive(Clone, Debug, Default)]
pub struct IdWrapperMock {
    getuid_results: RefCell<Vec<i32>>,
    setuid_params: Arc<Mutex<Vec<i32>>>,
    setuid_results: RefCell<Vec<i32>>,
    getgid_results: RefCell<Vec<i32>>,
    setgid_params: Arc<Mutex<Vec<i32>>>,
    setgid_results: RefCell<Vec<i32>>,
}

impl IdWrapper for IdWrapperMock {
    fn getuid(&self) -> i32 {
        self.getuid_results.borrow_mut().remove(0)
    }
    fn getgid(&self) -> i32 {
        self.getgid_results.borrow_mut().remove(0)
    }
    fn setuid(&self, uid: i32) -> i32 {
        self.setuid_params.lock().unwrap().push(uid);
        self.setuid_results.borrow_mut().remove(0)
    }
    fn setgid(&self, gid: i32) -> i32 {
        self.setgid_params.lock().unwrap().push(gid);
        self.setgid_results.borrow_mut().remove(0)
    }
}

#[allow(dead_code)]
impl IdWrapperMock {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn getuid_result(self, uid: i32) -> Self {
        self.getuid_results.borrow_mut().push(uid);
        self
    }

    pub fn setuid_params(mut self, params: &Arc<Mutex<Vec<i32>>>) -> Self {
        self.setuid_params = params.clone();
        self
    }

    pub fn setuid_result(self, uid_result: i32) -> Self {
        self.setuid_results.borrow_mut().push(uid_result);
        self
    }

    pub fn getgid_result(self, gid: i32) -> Self {
        self.getgid_results.borrow_mut().push(gid);
        self
    }

    pub fn setgid_params(mut self, params: &Arc<Mutex<Vec<i32>>>) -> Self {
        self.setgid_params = params.clone();
        self
    }

    pub fn setgid_result(self, gid_result: i32) -> Self {
        self.setgid_results.borrow_mut().push(gid_result);
        self
    }
}

pub struct DirsWrapperMock {
    pub(crate) data_dir_result: Option<PathBuf>,
    pub(crate) home_dir_result: Option<PathBuf>,
}

impl DirsWrapper for DirsWrapperMock {
    fn data_dir(&self) -> Option<PathBuf> {
        self.data_dir_result.clone()
    }

    fn home_dir(&self) -> Option<PathBuf> {
        self.home_dir_result.clone()
    }

    fn dup(&self) -> Box<dyn DirsWrapper> {
        Box::new(Self {
            data_dir_result: self.data_dir_result.clone(),
            home_dir_result: self.home_dir_result.clone(),
        })
    }
}

impl DirsWrapperMock {
    pub fn new() -> Self {
        DirsWrapperMock {
            data_dir_result: None,
            home_dir_result: None,
        }
    }

    pub fn data_dir_result(mut self, result: Option<PathBuf>) -> Self {
        self.data_dir_result = result;
        self
    }

    pub fn home_dir_result(mut self, result: Option<PathBuf>) -> Self {
        self.home_dir_result = result;
        self
    }
}

pub struct MasqueraderMock {
    log: Arc<Mutex<TestLog>>,
    try_unmask_results: RefCell<Vec<Result<UnmaskedChunk, MasqueradeError>>>,
    mask_results: RefCell<Vec<Result<Vec<u8>, MasqueradeError>>>,
}

impl Masquerader for MasqueraderMock {
    fn try_unmask(&self, item: &[u8]) -> Result<UnmaskedChunk, MasqueradeError> {
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
    pub fn try_unmask_result(&mut self, result: Result<UnmaskedChunk, MasqueradeError>) {
        self.try_unmask_results.borrow_mut().push(result);
    }

    #[allow(dead_code)]
    pub fn mask_result(&mut self, result: Result<Vec<u8>, MasqueradeError>) {
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

pub fn check_timestamp(before: SystemTime, timestamp: SystemTime, after: SystemTime) {
    timestamp.duration_since(before).unwrap_or_else(|_| {
        panic!(
            "Timestamp should have been on or after {:?}, but was {:?}",
            before, timestamp
        )
    });
    after.duration_since(timestamp).unwrap_or_else(|_| {
        panic!(
            "Timestamp should have been on or before {:?}, but was {:?}",
            after, timestamp
        )
    });
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
    discriminator_natures: Arc<Mutex<Vec<Vec<Vec<u8>>>>>,
}

impl DiscriminatorFactory for NullDiscriminatorFactory {
    fn make(&self) -> Discriminator {
        let mut natures = self.discriminator_natures.lock().unwrap();
        let data = natures.remove(0);
        make_null_discriminator(data)
    }

    fn duplicate(&self) -> Box<dyn DiscriminatorFactory> {
        Box::new(NullDiscriminatorFactory {
            discriminator_natures: self.discriminator_natures.clone(),
        })
    }
}

impl NullDiscriminatorFactory {
    pub fn new() -> NullDiscriminatorFactory {
        NullDiscriminatorFactory {
            discriminator_natures: Arc::new(Mutex::new(vec![])),
        }
    }

    pub fn discriminator_nature(self, data: Vec<Vec<u8>>) -> NullDiscriminatorFactory {
        self.discriminator_natures.lock().unwrap().push(data);
        self
    }
}

pub fn start_recorder_refcell_opt(recorder: &RefCell<Option<Recorder>>) -> Addr<Recorder> {
    recorder.borrow_mut().take().unwrap().start()
}

pub fn make_stream_handler_pool_subs_from_recorder(addr: &Addr<Recorder>) -> StreamHandlerPoolSubs {
    StreamHandlerPoolSubs {
        add_sub: recipient!(addr, AddStreamMsg),
        transmit_sub: recipient!(addr, TransmitDataMsg),
        remove_sub: recipient!(addr, RemoveStreamMsg),
        bind: recipient!(addr, PoolBindMessage),
        node_query_response: recipient!(addr, DispatcherNodeQueryResponse),
        node_from_ui_sub: recipient!(addr, NodeFromUiMessage),
        scheduled_node_query_response_sub: recipient!(
            addr,
            MessageScheduler<DispatcherNodeQueryResponse>
        ),
    }
}

pub struct FailingMasquerader {}

impl Masquerader for FailingMasquerader {
    fn try_unmask(&self, _item: &[u8]) -> Result<UnmaskedChunk, MasqueradeError> {
        unimplemented!()
    }

    fn mask(&self, _data: &[u8]) -> Result<Vec<u8>, MasqueradeError> {
        Err(MasqueradeError::LowLevelDataError(
            String::from_str("don't care").unwrap(),
        ))
    }
}
