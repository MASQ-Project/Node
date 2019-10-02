// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use std::fmt::Debug;

pub trait AdapterWrapper: Debug {
    fn adapter_name(&self) -> &str;
    fn friendly_name(&self) -> &str;
}

#[derive(Debug)]
pub struct AdapterWrapperReal {
    pub adapter: ipconfig::Adapter,
}

impl AdapterWrapper for AdapterWrapperReal {
    fn adapter_name(&self) -> &str {
        self.adapter.adapter_name()
    }

    fn friendly_name(&self) -> &str {
        self.adapter.friendly_name()
    }
}

#[cfg(test)]
pub mod test_utils {
    use super::*;

    #[derive(Debug)]
    pub struct AdapterWrapperStub {
        pub adapter_name: String,
        pub friendly_name: String,
    }

    impl Default for AdapterWrapperStub {
        fn default() -> Self {
            Self {
                adapter_name: "interface".to_string(),
                friendly_name: "Ethernet".to_string(),
            }
        }
    }

    impl AdapterWrapperStub {
        pub fn new() -> Self {
            Default::default()
        }
    }

    impl AdapterWrapper for AdapterWrapperStub {
        fn adapter_name(&self) -> &str {
            &self.adapter_name
        }

        fn friendly_name(&self) -> &str {
            &self.friendly_name
        }
    }
}
