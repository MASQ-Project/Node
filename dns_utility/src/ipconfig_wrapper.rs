// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::adapter_wrapper::{AdapterWrapper, AdapterWrapperReal};

pub trait IpconfigWrapper {
    fn get_adapters(&self) -> Result<Vec<Box<dyn AdapterWrapper>>, ipconfig::error::Error>;
}

pub struct IpconfigWrapperReal {}

impl IpconfigWrapper for IpconfigWrapperReal {
    fn get_adapters(&self) -> Result<Vec<Box<dyn AdapterWrapper>>, ipconfig::error::Error> {
        Ok(ipconfig::get_adapters()?
            .into_iter()
            .map(|adapter| Box::new(AdapterWrapperReal { adapter }) as Box<dyn AdapterWrapper>)
            .collect::<Vec<Box<dyn AdapterWrapper>>>())
    }
}

#[cfg(test)]
pub mod test_utils {
    use super::*;
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    pub struct IpconfigWrapperMock {
        get_adapters_parameters: Arc<Mutex<Vec<()>>>,
        get_adapters_results:
            RefCell<Vec<Result<Vec<Box<dyn AdapterWrapper>>, ipconfig::error::Error>>>,
    }

    impl IpconfigWrapperMock {
        pub fn new() -> Self {
            Default::default()
        }

        pub fn get_adapters_result(
            self,
            result: Result<Vec<Box<dyn AdapterWrapper>>, ipconfig::error::Error>,
        ) -> Self {
            self.get_adapters_results.borrow_mut().insert(0, result);
            self
        }
    }

    impl IpconfigWrapper for IpconfigWrapperMock {
        fn get_adapters(&self) -> Result<Vec<Box<dyn AdapterWrapper>>, ipconfig::error::Error> {
            self.get_adapters_parameters.lock().unwrap().push(());
            self.get_adapters_results
                .borrow_mut()
                .pop()
                .unwrap_or_else(|| panic!("get_adapters was called without a stub"))
        }
    }
}
