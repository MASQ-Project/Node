// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_create_with_str_address() {
        let subject = Wallet::new("totally valid eth address");

        assert_eq!("totally valid eth address", subject.address);
    }
}
