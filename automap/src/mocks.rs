// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.


use std::cell::RefCell;
use std::net::IpAddr;
use crate::comm_layer::{AutomapError, LocalIpFinder};

pub struct LocalIpFinderMock {
    find_results: RefCell<Vec<Result<IpAddr, AutomapError>>>,
}

impl LocalIpFinder for LocalIpFinderMock {
    fn find(&self) -> Result<IpAddr, AutomapError> {
        self.find_results.borrow_mut().remove(0)
    }
}

impl LocalIpFinderMock {
    pub fn new() -> Self {
        Self {
            find_results: RefCell::new(vec![]),
        }
    }

    pub fn find_result(self, result: Result<IpAddr, AutomapError>) -> Self {
        self.find_results.borrow_mut().push(result);
        self
    }
}
