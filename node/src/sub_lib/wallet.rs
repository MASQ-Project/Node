// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use serde_derive::{Deserialize, Serialize};
use std::fmt::{Display, Error, Formatter};
use web3::types::{H160, H256};

#[derive(Clone, Debug, Deserialize, Serialize, Eq, Hash, PartialEq)]
pub struct Wallet {
    pub address: String,
}

impl Wallet {
    pub fn new(address: &str) -> Wallet {
        Wallet {
            address: String::from(address),
        }
    }
}

impl From<H256> for Wallet {
    fn from(address: H256) -> Self {
        Wallet::new(&format!("{:?}", H160::from(address)))
    }
}

impl Display for Wallet {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "{}", self.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_create_with_str_address() {
        let subject = Wallet::new("totally valid eth address");

        assert_eq!("totally valid eth address", subject.address);
    }

    #[test]
    fn can_create_from_an_h256() {
        let result = Wallet::from(H256::from(
            "0000000000000000000000003f69f9efd4f2592fd70be8c32ecd9dce71c472fc",
        ));

        assert_eq!("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc", result.address);
    }

    #[test]
    fn display_works() {
        let subject = Wallet::new("The quick brown fox jumps over the lazy dog");

        let result = format!("|{}|", subject);

        assert_eq!(
            "|The quick brown fox jumps over the lazy dog|".to_string(),
            result
        );
    }
}
