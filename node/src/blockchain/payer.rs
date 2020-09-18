// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::banned_dao::BAN_CACHE;
use crate::blockchain::signature::SerializableSignature;
use crate::sub_lib::wallet::Wallet;
use ethsign::Signature;
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
            wallet: wallet.as_address_wallet(),
            proof: Signature {
                v: proof.v,
                r: proof.r,
                s: proof.s,
            },
        }
    }

    pub fn congruent(&self, other: &Payer) -> bool {
        (self.wallet.congruent(&other.wallet)) && (self.proof == other.proof)
    }

    pub fn owns_secret_key(&self, digest: &dyn AsRef<[u8]>) -> bool {
        match &self.proof.recover(&digest.as_ref()) {
            Ok(payer_public_key) => match payer_public_key.verify(&self.proof, &digest.as_ref()) {
                Ok(result) => result && payer_public_key.address() == &self.wallet.address().0,
                Err(_) => false,
            },
            Err(_) => false,
        }
    }

    pub fn is_delinquent(&self) -> bool {
        BAN_CACHE.is_banned(&self.wallet)
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
    use crate::blockchain::blockchain_interface::contract_address;
    use crate::sub_lib::cryptde;
    use crate::sub_lib::cryptde::PublicKey as SubPublicKey;
    use crate::test_utils::make_payer;
    use masq_lib::test_utils::utils::DEFAULT_CHAIN_ID;
    use rustc_hex::FromHex;

    #[test]
    fn can_pay_validates_payer_owns_wallet_secret_key() {
        let secret = "abacadaba0deadbeefcafefeedbabeface812deadbeefcafefeedbabefaceea7"
            .from_hex::<Vec<u8>>()
            .unwrap();

        let public_key = SubPublicKey::new(&b"sign these bytessign these bytes".to_vec());
        let payer: Payer = make_payer(&secret, &public_key);
        let digest = cryptde::create_digest(&public_key, &contract_address(DEFAULT_CHAIN_ID));
        assert!(payer.owns_secret_key(&digest));
    }

    #[test]
    fn can_pay_cant_verify_payer_owns_wallet_secret_key_with_wrong_public_key() {
        let secret = "abacadaba0deadbeefcafefeedbabeface812deadbeefcafefeedbabefaceea7"
            .from_hex::<Vec<u8>>()
            .unwrap();

        let public_key = SubPublicKey::new(&b"sign these bytessign these bytes".to_vec());
        let payer: Payer = make_payer(&secret, &public_key);
        let digest = cryptde::create_digest(
            &SubPublicKey::new(&b"wrong key"[..]),
            &contract_address(DEFAULT_CHAIN_ID),
        );
        assert_eq!(payer.owns_secret_key(&digest), false);
    }

    #[test]
    fn is_delinquent_says_no_for_non_delinquent_payer() {
        let secret = "812deadbeefcafefeedbabefaceea7abacadaba0deadbeefcafefeedbabeface"
            .from_hex::<Vec<u8>>()
            .unwrap();
        let public_key = SubPublicKey::new(&b"sign these bytessign these bytes".to_vec());
        let subject = make_payer(&secret, &public_key);
        BAN_CACHE.remove(&subject.wallet);

        let result = subject.is_delinquent();

        assert_eq!(result, false);
    }

    #[test]
    fn is_delinquent_says_yes_for_delinquent_payer() {
        let secret = "abacadaba0deadbeefcafefeedbabeface812deadbeefcafefeedbabefaceea7"
            .from_hex::<Vec<u8>>()
            .unwrap();
        let public_key = SubPublicKey::new(&b"sign these bytessign these bytes".to_vec());
        let subject = make_payer(&secret, &public_key);
        BAN_CACHE.insert(subject.wallet.clone());

        let result = subject.is_delinquent();

        assert_eq!(result, true);
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

        assert!(actual.congruent(&expected));
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

        assert!(actual.congruent(&expected));
    }
}
