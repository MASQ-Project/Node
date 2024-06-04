// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use tokio::io::{AsyncRead, AsyncWrite};

pub struct AsyncStdStreams {
    pub stdin: Box<dyn AsyncRead + Send + Sync + Unpin>,
    pub stdout: Box<dyn AsyncWrite + Send + Sync + Unpin>,
    pub stderr: Box<dyn AsyncWrite + Send + Sync + Unpin>,
}

pub trait AsyncStdStreamsFactory {
    fn make(&self) -> AsyncStdStreams;
}

#[derive(Default)]
pub struct AsyncStdStreamsFactoryReal {}

impl AsyncStdStreamsFactory for AsyncStdStreamsFactoryReal {
    fn make(&self) -> AsyncStdStreams {
        todo!()
    }
}
