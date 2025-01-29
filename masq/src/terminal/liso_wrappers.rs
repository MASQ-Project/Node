// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use async_trait::async_trait;
use core::any::Any;
use liso::{InputOutput, Response};
use std::sync::Arc;

#[async_trait(?Send)]
pub trait LisoInputWrapper {
    async fn read_async(&mut self) -> Response;
}

pub trait LisoOutputWrapper: Send + Sync {
    fn println(&self, formatted_text: &str);
    fn prompt(&self, appearance: &str, input_allowed: bool, clear_input: bool);
    fn clone_output(&self) -> Box<dyn LisoOutputWrapper>;
}

pub struct LisoInputWrapperReal {
    handle: InputOutput,
}

impl LisoInputWrapperReal {
    fn new() -> Self {
        todo!()
    }
}

#[async_trait(?Send)]
impl LisoInputWrapper for LisoInputWrapperReal {
    async fn read_async(&mut self) -> Response {
        todo!()
    }
}

pub struct LisoOutputWrapperReal {}

impl LisoOutputWrapper for LisoOutputWrapperReal {
    fn println(&self, formatted_text: &str) {
        todo!()
    }

    fn prompt(&self, appearance: &str, input_allowed: bool, clear_input: bool) {
        todo!()
    }

    fn clone_output(&self) -> Box<dyn LisoOutputWrapper> {
        todo!()
    }
}
