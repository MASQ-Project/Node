// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use std::io;

pub trait DnsModifier {
    fn type_name (&self) -> &'static str;
    fn subvert (&self) -> Result<(), String>;
    fn revert (&self) -> Result<(), String>;
    fn inspect (&self, stdout: &mut (io::Write + Send)) -> Result<(), String>;
}
