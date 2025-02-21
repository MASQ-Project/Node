// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::{CommandContext, CommandContextReal};
use crate::commands::commands_common::CommandError;
use crate::communications::connection_manager::CMBootstrapper;
use crate::terminal::WTermInterfaceDupAndSend;
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
        Self {}
    }
}

#[async_trait(?Send)]
impl CommandContextFactory for CommandContextFactoryReal {
    async fn make(
        &self,
        ui_port: u16,
        term_interface_opt: Option<Box<dyn WTermInterfaceDupAndSend>>,
    ) -> Result<Box<dyn CommandContext>, CommandError> {
        match CommandContextReal::new(ui_port, term_interface_opt, CMBootstrapper::default()).await
        {
            Ok(cc) => Ok(Box::new(cc) as Box<dyn CommandContext>),
            Err(e) => Err(e.into()),
        }
    }
}
