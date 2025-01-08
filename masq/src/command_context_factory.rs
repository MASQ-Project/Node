// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::command_processor::CommandProcessor;
use crate::commands::commands_common::CommandError;
use crate::terminal::{WTermInterface, WTermInterfaceDupAndSend};
use async_trait::async_trait;

#[async_trait(?Send)]
pub trait CommandContextFactory {
    async fn make(
        &self,
        ui_port: u16,
        term_interface_opt: Option<Box<dyn WTermInterfaceDupAndSend>>,
    ) -> Result<Box<dyn CommandContext>, CommandError>;
}

pub struct CommandContextFactoryReal {}

impl Default for CommandContextFactoryReal {
    fn default() -> Self {
        todo!()
    }
}

#[async_trait(?Send)]
impl CommandContextFactory for CommandContextFactoryReal {
    async fn make(
        &self,
        ui_port: u16,
        term_interface_opt: Option<Box<dyn WTermInterfaceDupAndSend>>,
    ) -> Result<Box<dyn CommandContext>, CommandError> {
        todo!()
    }
}
