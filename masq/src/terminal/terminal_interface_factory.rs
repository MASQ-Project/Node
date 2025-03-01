// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::terminal::interactive_terminal_interface::InteractiveRWTermInterface;
use crate::terminal::liso_wrappers::{LisoInputWrapperReal, LisoOutputWrapperReal};
use crate::terminal::non_interactive_terminal_interface::NonInteractiveWTermInterface;
use crate::terminal::{RWTermInterface, WTermInterface};
use itertools::Either;
use masq_lib::async_streams::AsyncStdStreamsFactory;
use std::sync::Arc;

pub trait TerminalInterfaceFactory {
    fn make(
        &self,
        is_interactive: bool,
        streams_factory: Arc<dyn AsyncStdStreamsFactory>,
    ) -> Either<Box<dyn WTermInterface>, Box<dyn RWTermInterface>>;
}

#[derive(Default)]
pub struct TerminalInterfaceFactoryReal {}

impl TerminalInterfaceFactory for TerminalInterfaceFactoryReal {
    fn make(
        &self,
        is_interactive: bool,
        streams_factory: Arc<dyn AsyncStdStreamsFactory>,
    ) -> Either<Box<dyn WTermInterface>, Box<dyn RWTermInterface>> {
        if !is_interactive {
            Either::Left(Box::new(NonInteractiveWTermInterface::new(Arc::from(
                streams_factory,
            ))))
        } else {
            let read_liso = liso::InputOutput::new();
            let write_liso = read_liso.clone_output();
            Either::Right(Box::new(InteractiveRWTermInterface::new(
                Box::new(LisoInputWrapperReal::new(read_liso)),
                Box::new(LisoOutputWrapperReal::new(write_liso)),
            )))
        }
    }
}
