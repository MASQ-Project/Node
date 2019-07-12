// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::blockchain::signature::SerializableSignature;
use crate::sub_lib::cryptde::PublicKey as SubPublicKey;
use crate::sub_lib::wallet::Wallet;
use ethsign::Signature;
use ethsign_crypto::Keccak256;
use serde_derive::{Deserialize, Serialize};

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct Payer {
    #[serde(flatten)]
    pub wallet: Wallet,
    #[serde(with = "SerializableSignature")]
    pub proof: Signature,
}

impl Payer {
    pub fn new(wallet: &Wallet, proof: &Signature) -> Self {
        Self {
            wallet: wallet.clone(),
            proof: Signature {
                v: proof.v,
                r: proof.r,
                s: proof.s,
            },
        }
    }

    pub fn owns_secret_key(&self, public_key: &SubPublicKey) -> bool {
        let digest = public_key.as_slice().keccak256();
        match &self.proof.recover(&digest) {
            Ok(payer_public_key) => match payer_public_key.verify(&self.proof, &digest) {
                Ok(result) => result && payer_public_key.address() == &self.wallet.address().0,
                Err(_) => false,
            },
            Err(_) => false,
        }
    }
}

impl Clone for Payer {
    fn clone(&self) -> Self {
        Self {
            wallet: self.wallet.clone(),
            proof: Signature {
                v: self.proof.v,
                r: self.proof.r,
                s: self.proof.s,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::make_payer;
    use rustc_hex::FromHex;

    #[test]
    fn can_pay_validates_payer_owns_wallet_secret_key() {
        let secret = "abacadaba0deadbeefcafefeedbabeface812deadbeefcafefeedbabefaceea7"
            .from_hex::<Vec<u8>>()
            .unwrap();

        let public_key = SubPublicKey::new(&b"sign these bytessign these bytes".to_vec());
        let payer: Payer = make_payer(&secret, &public_key);
        assert!(payer.owns_secret_key(&public_key));
    }

    #[test]
    fn can_pay_cant_verify_payer_owns_wallet_secret_key_with_wrong_public_key() {
        let secret = "abacadaba0deadbeefcafefeedbabeface812deadbeefcafefeedbabefaceea7"
            .from_hex::<Vec<u8>>()
            .unwrap();

        let public_key = SubPublicKey::new(&b"sign these bytessign these bytes".to_vec());
        let payer: Payer = make_payer(&secret, &public_key);
        assert_eq!(
            payer.owns_secret_key(&SubPublicKey::new(&b"wrong key"[..])),
            false
        );
    }

    #[test]
    fn roundtrip_payer_works_with_cbor() {
        let secret = "abacadaba0deadbeefcafefeedbabeface812deadbeefcafefeedbabefaceea7"
            .from_hex::<Vec<u8>>()
            .unwrap();

        let public_key = SubPublicKey::new(&b"sign these bytessign these bytes".to_vec());
        let expected: Payer = make_payer(&secret, &public_key);

        let result = serde_cbor::to_vec(&expected).unwrap();
        let actual = serde_cbor::from_slice::<Payer>(&result[..]).unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn roundtrip_payer_works_with_json() {
        let secret = "abacadaba0deadbeefcafefeedbabeface812deadbeefcafefeedbabefaceea7"
            .from_hex::<Vec<u8>>()
            .unwrap();

        let public_key = SubPublicKey::new(&b"sign these bytessign these bytes".to_vec());
        let expected: Payer = make_payer(&secret, &public_key);

        let result = serde_json::to_string(&expected).unwrap();
        let actual = serde_json::from_str::<Payer>(&result[..]).unwrap();

        assert_eq!(actual, expected);
    }
}
