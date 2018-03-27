// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::marker::Send;

pub trait LoggerInitializerWrapper: Send {
    fn init (&mut self) -> bool;
}