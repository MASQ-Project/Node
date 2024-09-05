// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::terminal::async_streams::{AsyncStdStreams, AsyncStdStreamsFactory};
use crate::terminal::{RWTermInterface, WTermInterface};
use itertools::Either;

pub trait TerminalInterfaceFactory {
    fn make(
        &self,
        is_interactive: bool,
        streams_factory: &dyn AsyncStdStreamsFactory,
    ) -> Either<Box<dyn WTermInterface>, Box<dyn RWTermInterface>>;
}

#[derive(Default)]
pub struct TerminalInterfaceFactoryReal {}

impl TerminalInterfaceFactory for TerminalInterfaceFactoryReal {
    fn make(
        &self,
        is_interactive: bool,
        streams_factory: &dyn AsyncStdStreamsFactory,
    ) -> Either<Box<dyn WTermInterface>, Box<dyn RWTermInterface>> {
        todo!()
    }
}
