// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::actor_system_factory::AutomapControlFactory;
use automap_lib::comm_layer::AutomapError;
use automap_lib::control_layer::automap_control::{AutomapControl, ChangeHandler};
use masq_lib::utils::AutomapProtocol;
use std::cell::RefCell;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

#[allow(clippy::type_complexity)]
pub struct AutomapControlFactoryMock {
    make_params: Arc<Mutex<Vec<(Option<AutomapProtocol>, ChangeHandler)>>>,
    make_results: Arc<Mutex<Vec<Box<dyn AutomapControl>>>>,
}

impl AutomapControlFactory for AutomapControlFactoryMock {
    fn make(
        &self,
        usual_protocol_opt: Option<AutomapProtocol>,
        change_handler: ChangeHandler,
    ) -> Box<dyn AutomapControl> {
        self.make_params
            .lock()
            .unwrap()
            .push((usual_protocol_opt, change_handler));
        self.make_results.lock().unwrap().remove(0)
    }
}

impl Default for AutomapControlFactoryMock {
    fn default() -> Self {
        Self::new()
    }
}

impl AutomapControlFactoryMock {
    pub fn new() -> Self {
        Self {
            make_params: Arc::new(Mutex::new(vec![])),
            make_results: Arc::new(Mutex::new(vec![])),
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn make_params(
        mut self,
        params: &Arc<Mutex<Vec<(Option<AutomapProtocol>, ChangeHandler)>>>,
    ) -> Self {
        self.make_params = params.clone();
        self
    }

    pub fn make_result(self, result: Box<dyn AutomapControl>) -> Self {
        self.make_results.lock().unwrap().push(result);
        self
    }
}

pub struct AutomapControlMock {
    get_public_ip_results: RefCell<Vec<Result<IpAddr, AutomapError>>>,
    add_mapping_params: Arc<Mutex<Vec<u16>>>,
    add_mapping_results: RefCell<Vec<Result<(), AutomapError>>>,
    delete_mappings_results: RefCell<Vec<Result<(), AutomapError>>>,
    get_mapping_protocol_results: RefCell<Vec<Option<AutomapProtocol>>>,
}

impl AutomapControl for AutomapControlMock {
    fn get_public_ip(&mut self) -> Result<IpAddr, AutomapError> {
        self.get_public_ip_results.borrow_mut().remove(0)
    }

    fn add_mapping(&mut self, hole_port: u16) -> Result<(), AutomapError> {
        self.add_mapping_params.lock().unwrap().push(hole_port);
        self.add_mapping_results.borrow_mut().remove(0)
    }

    fn delete_mappings(&mut self) -> Result<(), AutomapError> {
        self.delete_mappings_results.borrow_mut().remove(0)
    }

    fn get_mapping_protocol(&self) -> Option<AutomapProtocol> {
        self.get_mapping_protocol_results.borrow_mut().remove(0)
    }
}

impl Default for AutomapControlMock {
    fn default() -> Self {
        Self::new()
    }
}

impl AutomapControlMock {
    pub fn new() -> Self {
        Self {
            get_public_ip_results: RefCell::new(vec![]),
            add_mapping_params: Arc::new(Mutex::new(vec![])),
            add_mapping_results: RefCell::new(vec![]),
            delete_mappings_results: RefCell::new(vec![]),
            get_mapping_protocol_results: RefCell::new(vec![]),
        }
    }

    pub fn get_public_ip_result(self, result: Result<IpAddr, AutomapError>) -> Self {
        self.get_public_ip_results.borrow_mut().push(result);
        self
    }

    pub fn add_mapping_params(mut self, params: &Arc<Mutex<Vec<u16>>>) -> Self {
        self.add_mapping_params = params.clone();
        self
    }

    pub fn add_mapping_result(self, result: Result<(), AutomapError>) -> Self {
        self.add_mapping_results.borrow_mut().push(result);
        self
    }

    pub fn delete_mappings_result(self, result: Result<(), AutomapError>) -> Self {
        self.delete_mappings_results.borrow_mut().push(result);
        self
    }

    pub fn get_mapping_protocol_result(self, result: Option<AutomapProtocol>) -> Self {
        self.get_mapping_protocol_results.borrow_mut().push(result);
        self
    }
}
