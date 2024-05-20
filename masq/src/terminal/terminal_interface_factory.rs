// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::terminal::async_streams::AsyncStdStreams;
use crate::terminal::terminal_interface::{RWTermInterface, WTermInterface};
use itertools::Either;

pub trait TerminalInterfaceFactory: Send + Sync {
    fn make(
        &self,
        is_interactive: bool,
        streams: AsyncStdStreams,
    ) -> Either<Box<dyn WTermInterface>, Box<dyn RWTermInterface>>;
}

#[derive(Default)]
pub struct TerminalInterfaceFactoryReal {}

impl TerminalInterfaceFactory for TerminalInterfaceFactoryReal {
    fn make(
        &self,
        is_interactive: bool,
        streams: AsyncStdStreams,
    ) -> Either<Box<dyn WTermInterface>, Box<dyn RWTermInterface>> {
        todo!()
    }
}
