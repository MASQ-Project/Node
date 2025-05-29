// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::sub_lib::cryptde;
use crate::sub_lib::cryptde::CryptData;
use crate::sub_lib::cryptde::CryptdecError;
use crate::sub_lib::cryptde::PlainData;
use crate::sub_lib::cryptde::PrivateKey;
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::cryptde::{CryptDE, SymmetricKey};
use masq_lib::blockchains::chains::Chain;
use masq_lib::utils::ExpectValue;
use rand::prelude::*;
use rustc_hex::ToHex;
use std::any::Any;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone)]
pub struct NullCryptDE {}

impl CryptDE for NullCryptDE {
    fn encode(&self, public_key: &PublicKey, data: &PlainData) -> Result<CryptData, CryptdecError> {
        unimplemented!("NullCryptDE doesn't do this");
    }

    fn decode(&self, data: &CryptData) -> Result<PlainData, CryptdecError> {
        unimplemented!("NullCryptDE doesn't do this");
    }

    fn encode_sym(&self, key: &SymmetricKey, data: &PlainData) -> Result<CryptData, CryptdecError> {
        unimplemented!("NullCryptDE doesn't do this");
    }

    fn decode_sym(&self, key: &SymmetricKey, data: &CryptData) -> Result<PlainData, CryptdecError> {
        unimplemented!("NullCryptDE doesn't do this");
    }

    fn gen_key_sym(&self) -> SymmetricKey {
        unimplemented!("NullCryptDE doesn't do this");
    }

    fn random(&self, dest: &mut [u8]) {
        unimplemented!("NullCryptDE doesn't do this");
    }

    fn private_key(&self) -> &PrivateKey {
        unimplemented!("NullCryptDE doesn't do this");
    }

    fn public_key(&self) -> &PublicKey {
        unimplemented!("NullCryptDE doesn't do this");
    }

    // This is dup instead of clone because it returns a Box<CryptDE> instead of a NullCryptDE.
    fn dup(&self) -> Box<dyn CryptDE> {
        Box::new(NullCryptDE{})
    }

    fn sign(&self, data: &PlainData) -> Result<CryptData, CryptdecError> {
        unimplemented!("NullCryptDE doesn't do this");
    }

    fn verify_signature(
        &self,
        data: &PlainData,
        signature: &CryptData,
        public_key: &PublicKey,
    ) -> bool {
        unimplemented!("NullCryptDE doesn't do this");
    }

    fn hash(&self, data: &PlainData) -> CryptData {
        unimplemented!("NullCryptDE doesn't do this");
    }

    fn public_key_to_descriptor_fragment(&self, public_key: &PublicKey) -> String {
        unimplemented!("NullCryptDE doesn't do this");
    }

    fn descriptor_fragment_to_first_contact_public_key(
        &self,
        descriptor_fragment: &str,
    ) -> Result<PublicKey, String> {
        unimplemented!("NullCryptDE doesn't do this");
    }

    fn digest(&self) -> [u8; 32] {
        unimplemented!("NullCryptDE doesn't do this");
    }

    fn make_from_str(&self, value: &str, chain: Chain) -> Result<Box<dyn CryptDE>, String> {
        unimplemented!("NullCryptDE doesn't do this");
    }

    fn to_string(&self) -> String {
        unimplemented!("NullCryptDE doesn't do this");
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl<'a> From<&'a dyn CryptDE> for &'a NullCryptDE {
    fn from(cryptde_generic: &'a dyn CryptDE) -> Self {
        unimplemented!("NullCryptDE doesn't do this");
    }
}

impl NullCryptDE {
    pub fn new() -> Self {
        Self{}
    }
}
