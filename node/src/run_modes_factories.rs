// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::server_initializer::test_utils::ServerInitializerMock;
use masq_lib::command::Command;
use masq_lib::shared_schema::ConfiguratorError;
use std::cell::{Cell, RefCell};

pub struct DumpConfigRunnerFactoryReal;
pub struct ServerInitializerFactoryReal;
pub struct DaemonInitializerFactoryReal;

pub trait DumpConfigRunnerFactory {
    fn make(&self) -> &dyn DumpConfigRunner;
}
pub trait ServerInitializerFactory {
    fn make(&self) -> Box<dyn ServerInitializer<Item = (), Error = ()>>;
}
pub trait DaemonInitializerFactory {
    fn make(&self) -> &dyn DaemonInitializer;
}

pub trait DumpConfigRunner {}

pub trait ServerInitializer: Command<ConfiguratorError> + futures::Future {}

pub trait DaemonInitializer {}

impl DumpConfigRunnerFactory for DumpConfigRunnerFactoryReal {
    fn make(&self) -> &dyn DumpConfigRunner {
        todo!()
    }
}

impl ServerInitializerFactory for ServerInitializerFactoryReal {
    fn make(&self) -> Box<dyn ServerInitializer<Item = (), Error = ()>> {
        todo!()
    }
}

impl DaemonInitializerFactory for DaemonInitializerFactoryReal {
    fn make(&self) -> &dyn DaemonInitializer {
        todo!()
    }
}

pub struct ServerInitializerFactoryMock {
    server_initializer: RefCell<ServerInitializerMock>,
}

impl ServerInitializerFactoryMock {
    pub fn new(server_initializer: ServerInitializerMock) -> Self {
        Self {
            server_initializer: RefCell::new(server_initializer),
        }
    }
}

impl ServerInitializerFactory for ServerInitializerFactoryMock {
    fn make(&self) -> Box<dyn ServerInitializer<Item = (), Error = ()>> {
        Box::new(self.server_initializer.take())
    }
}
