// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use async_trait::async_trait;
use liso::Response;

#[async_trait(?Send)]
pub trait LisoInputOutputWrapper: LisoOutputWrapper{
    async fn read_async(&mut self)->Response;
}


pub trait LisoOutputWrapper{
    fn println(&self, formatted_text: &str);
    fn prompt(&self, appearance: &str, input_allowed: bool, clear_input: bool);
    fn clone_output(&self) -> Box<dyn LisoOutputWrapper>;
}

pub struct LisoInputOutputWrapperReal{}

#[async_trait(?Send)]
impl LisoInputOutputWrapper for LisoInputOutputWrapperReal{
    async fn read_async(&mut self) -> Response {
        todo!()
    }
}

impl LisoOutputWrapper for LisoInputOutputWrapperReal{
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

struct LisoOutputWrapperReal{}

impl LisoOutputWrapper for LisoOutputWrapperReal{
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