// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::arbitrary_id_stamp_in_trait;
use crate::intentionally_blank;
use crate::test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
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

#[macro_export]
macro_rules! write_async_stream_and_flush {
    ( $stream: expr, $($arg:tt)*) => {
         {
             $stream.write(format!($($arg)*).as_bytes()).await.expect("Write failed");
             $stream.flush().await.expect("Flush failed");
         };
    }
}
