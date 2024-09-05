// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_factory::CommandFactory;

pub trait CommandFactoryFactory {
    fn make(&self) -> Box<dyn CommandFactory>;
}

#[derive(Default)]
pub struct CommandFactoryFactoryReal {}

impl CommandFactoryFactory for CommandFactoryFactoryReal {
    fn make(&self) -> Box<dyn CommandFactory> {
        todo!()
    }
}
