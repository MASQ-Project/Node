// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use tokio::io::{AsyncRead, AsyncWrite, stdin, stdout, stderr};

pub struct AsyncStdStreams {
    pub stdin: Box<dyn AsyncRead + Send + Sync + Unpin>,
    pub stdout: Box<dyn AsyncWrite + Send + Sync + Unpin>,
    pub stderr: Box<dyn AsyncWrite + Send + Sync + Unpin>,
}

impl Default for AsyncStdStreams {
    fn default() -> Self {
        Self {
            stdin: Box::new(stdin()),
            stdout: Box::new(stdout()),
            stderr: Box::new(stderr()),
        }
    }
}

pub trait AsyncStdStreamsFactory {
    fn make(&self) -> AsyncStdStreams;
}

#[derive(Default)]
pub struct AsyncStdStreamsFactoryReal {}

impl AsyncStdStreamsFactory for AsyncStdStreamsFactoryReal {
    fn make(&self) -> AsyncStdStreams {
        AsyncStdStreams::default()
    }
}

#[macro_export]
macro_rules! write_async_stream_and_flush {
    ( $stream: expr, $($arg:tt)*) => {
         {
             $stream.write(format!($($arg)*).as_bytes()).await.expect("Write failed");
             $stream.flush().await.expect("Flush failed");
         };
    }
}
