// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use async_trait::async_trait;
use liso::{InputOutput, OutputOnly, Response};

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
    pub fn new(handle: InputOutput) -> Self {
        Self { handle }
    }
}

#[async_trait(?Send)]
impl LisoInputWrapper for LisoInputWrapperReal {
    async fn read_async(&mut self) -> Response {
        //self.handle.read_async().await
        todo!("drive in by integration tests")
    }
}

pub struct LisoOutputWrapperReal {
    handle: OutputOnly,
}

impl LisoOutputWrapperReal {
    pub fn new(handle: OutputOnly) -> Self {
        Self { handle }
    }
}

impl LisoOutputWrapper for LisoOutputWrapperReal {
    fn println(&self, formatted_text: &str) {
        //self.handle.println(formatted_text)
        todo!("drive in by integration tests")
    }

    fn prompt(&self, appearance: &str, input_allowed: bool, clear_input: bool) {
        //self.handle.prompt(appearance, input_allowed, clear_input)
        todo!()
    }

    fn clone_output(&self) -> Box<dyn LisoOutputWrapper> {
        //self.handle.clone_output();
        todo!("drive in by integration tests")
    }
}
