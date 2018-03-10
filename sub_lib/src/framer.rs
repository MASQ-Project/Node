// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

pub trait Framer: Send {
    fn add_data (&mut self, data: &[u8]);
    fn take_frame (&mut self) -> Option<Vec<u8>>;
}
