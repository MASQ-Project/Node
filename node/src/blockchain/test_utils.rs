// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use bip39::{Language, Mnemonic, Seed};

pub fn make_meaningless_phrase() -> String {
    "phrase donate agent satoshi burst end company pear obvious achieve depth advice".to_string()
}

pub fn make_meaningless_seed() -> Seed {
    let mnemonic = Mnemonic::from_phrase(&make_meaningless_phrase(), Language::English).unwrap();
    Seed::new(&mnemonic, "passphrase")
}
