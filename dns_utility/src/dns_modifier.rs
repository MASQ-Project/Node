// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::io;

pub trait DnsModifier {
    fn type_name(&self) -> &'static str;
    fn subvert(&self) -> Result<(), String>;
    fn revert(&self) -> Result<(), String>;
    fn inspect(&self, stdout: &mut (dyn io::Write + Send)) -> Result<(), String>;
}
