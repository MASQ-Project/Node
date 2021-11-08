// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use ethsign::{SecretKey, PublicKey};
use secp256k1;
use std::convert::TryFrom;

#[derive(Debug)]
pub struct DualSecret{
    pub ethsign_secret: SecretKey,
    pub secp256k1_secret: secp256k1::key::SecretKey
}

impl DualSecret{
    pub fn public(&self) ->PublicKey{
        self.ethsign_secret.public()
    }
}

impl TryFrom<&[u8]> for DualSecret{
    type Error = String;

    fn try_from(raw_secret: &[u8]) -> Result<Self, Self::Error> {
        let ethsign_secret = match SecretKey::from_raw(raw_secret) {
            Ok(secret) => secret,
            Err(e) => unimplemented!(), //   return Err(format!("{:?}", e)), //TODO check that this is under tests
        };
        let secp256k1_secret = match secp256k1::key::SecretKey::from_slice(raw_secret)
        {
            Ok(secret)=> secret,
            Err(e) => unimplemented!("{}",e)
        };
        Ok(Self{ ethsign_secret, secp256k1_secret})
    }
}

impl From<(SecretKey,secp256k1::key::SecretKey)> for DualSecret{
    fn from(secrets: (SecretKey, secp256k1::SecretKey)) -> Self {
        let (ethsign_secret,secp256k1_secret) = secrets;
        Self{ ethsign_secret, secp256k1_secret }
    }
}