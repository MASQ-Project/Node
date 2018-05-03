// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

pub trait DnsModifier {
    fn type_name (&self) -> &'static str;
    fn subvert (&self) -> Result<(), String>;
    fn revert (&self) -> Result<(), String>;
}
