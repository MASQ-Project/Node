// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use async_trait::async_trait;
use crate::command_context::CommandContext;
use crate::command_processor::CommandProcessor;
use crate::commands::commands_common::CommandError;
use crate::terminal::terminal_interface::WTermInterface;

#[async_trait]
pub trait CommandContextFactory{

    async fn make(&self, ui_port: u16, term_interface_opt: Option<Box<dyn WTermInterface>>)-> Result<Box<dyn CommandContext>, CommandError>;
}


pub struct CommandContextFactoryReal{

}

impl Default for CommandContextFactoryReal{
    fn default() -> Self {
        todo!()
    }
}

#[async_trait]
impl CommandContextFactory for CommandContextFactoryReal{
    async fn make(&self, ui_port: u16, term_interface_opt: Option<Box<dyn WTermInterface>>) -> Result<Box<dyn CommandContext>, CommandError> {
        todo!()
    }
}