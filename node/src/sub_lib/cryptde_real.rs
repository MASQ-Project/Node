// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::blockchain::blockchain_interface::contract_address;
use crate::sub_lib::cryptde;
use crate::sub_lib::cryptde::{
    CryptDE, CryptData, CryptdecError, PlainData, PrivateKey, PublicKey,
};
use lazy_static::lazy_static;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305 as cxsp;
use sodiumoxide::crypto::sealedbox::curve25519blake2bxsalsa20poly1305::SEALBYTES;
use sodiumoxide::crypto::sealedbox::{open, seal};
use sodiumoxide::crypto::sign as signing;
use sodiumoxide::crypto::{box_ as encryption, hash};
use sodiumoxide::randombytes::randombytes_into;

lazy_static! {
    static ref INITIALIZED: bool = {
        match sodiumoxide::init() {
            Ok(_) => true,
            Err(_) => panic!("sodiumoxide initialization failed"),
        }
    };
}

pub struct CryptDEReal {
    public_key: PublicKey,
    encryption_secret_key: encryption::SecretKey,
    signing_secret_key: signing::SecretKey,
    digest: [u8; 32],
}

impl CryptDE for CryptDEReal {
    fn encode(&self, key: &PublicKey, data: &PlainData) -> Result<CryptData, CryptdecError> {
        if key.len() != cxsp::PUBLICKEYBYTES + signing::PUBLICKEYBYTES {
            return Err(CryptdecError::InvalidKey(format!("{:?}", key.as_slice())));
        }
        let remote_public_key = Self::encryption_public_key_from(key);
        Ok(CryptData::from(seal(data.as_slice(), &remote_public_key)))
    }

    fn decode(&self, data: &CryptData) -> Result<PlainData, CryptdecError> {
        if data.len() < SEALBYTES {
            return Err(CryptdecError::EmptyData);
        }
        match open(
            data.as_slice(),
            &Self::encryption_public_key_from(self.public_key()),
            &self.encryption_secret_key,
        ) {
            Ok(data) => Ok(PlainData::from(data)),
            Err(()) => Err(CryptdecError::OpeningFailed),
        }
    }

    fn random(&self, dest: &mut [u8]) {
        randombytes_into(dest);
    }

    fn private_key(&self) -> &PrivateKey {
        // Hypothesis: private_key() is unused and unnecessary in production code. Consider making it #[cfg(test)].
        unimplemented!()
    }

    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    fn dup(&self) -> Box<dyn CryptDE> {
        Box::new(CryptDEReal {
            public_key: self.public_key.clone(),
            encryption_secret_key: encryption::SecretKey(self.encryption_secret_key.0),
            signing_secret_key: signing::SecretKey(self.signing_secret_key.0),
            digest: self.digest,
        })
    }

    fn sign(&self, data: &PlainData) -> Result<CryptData, CryptdecError> {
        Ok(CryptData::new(
            &signing::sign_detached(data.as_slice(), &self.signing_secret_key).0,
        ))
    }

    fn verify_signature(
        &self,
        data: &PlainData,
        signature: &CryptData,
        public_key: &PublicKey,
    ) -> bool {
        if signature.len() != signing::SIGNATUREBYTES {
            return false;
        }
        let mut signature_data = [0u8; signing::SIGNATUREBYTES];
        signature_data.copy_from_slice(signature.as_slice());
        signing::verify_detached(
            &signing::Signature(signature_data),
            data.as_slice(),
            &Self::signing_public_key_from(public_key),
        )
    }

    fn hash(&self, data: &PlainData) -> CryptData {
        let digest = hash::hash(data.as_slice());
        CryptData::new(&digest.0)
    }

    fn public_key_to_descriptor_fragment(&self, public_key: &PublicKey) -> String {
        let encryption_public_key = &public_key.as_slice()[..cxsp::PUBLICKEYBYTES];
        base64::encode_config(encryption_public_key, base64::STANDARD_NO_PAD)
    }

    fn descriptor_fragment_to_first_contact_public_key(
        &self,
        descriptor_fragment: &str,
    ) -> Result<PublicKey, String> {
        let mut encryption_public_key =
            match base64::decode_config(descriptor_fragment, base64::STANDARD_NO_PAD) {
                Ok(v) => v,
                Err(_) => {
                    return Err(format!(
                        "Invalid Base64 value for public key: {}",
                        descriptor_fragment
                    ))
                }
            };
        if encryption_public_key.len() != cxsp::PUBLICKEYBYTES {
            return Err(format!(
                "Public key must decode to {} bytes, not {}: {}",
                cxsp::PUBLICKEYBYTES,
                encryption_public_key.len(),
                descriptor_fragment
            ));
        }
        encryption_public_key.extend(&[0u8; signing::PUBLICKEYBYTES]);
        Ok(PublicKey::from(encryption_public_key))
    }

    fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

impl CryptDEReal {
    pub fn new(chain_id: u8) -> Self {
        let (e_public, e_secret) = encryption::gen_keypair();
        let (s_public, s_secret) = signing::gen_keypair();
        let public_key = Self::local_public_key_from(&e_public, &s_public);
        let digest = cryptde::create_digest(&public_key, &contract_address(chain_id));

        Self {
            public_key,
            encryption_secret_key: e_secret,
            signing_secret_key: s_secret,
            digest,
        }
    }

    fn local_public_key_from(
        encryption_public_key: &encryption::PublicKey,
        signing_public_key: &signing::PublicKey,
    ) -> PublicKey {
        let e_part = &encryption_public_key.0[..cxsp::PUBLICKEYBYTES];
        let s_part = &signing_public_key.0[..signing::PUBLICKEYBYTES];
        let mut both_parts: Vec<u8> =
            Vec::with_capacity(cxsp::PUBLICKEYBYTES + signing::PUBLICKEYBYTES);
        both_parts.extend(e_part);
        both_parts.extend(s_part);
        PublicKey::from(both_parts)
    }

    fn encryption_public_key_from(local_public_key: &PublicKey) -> encryption::PublicKey {
        let mut data = [0u8; cxsp::PUBLICKEYBYTES];
        data.copy_from_slice(&local_public_key.as_slice()[..cxsp::PUBLICKEYBYTES]);
        encryption::PublicKey(data)
    }

    fn signing_public_key_from(local_public_key: &PublicKey) -> signing::PublicKey {
        let mut data = [0u8; signing::PUBLICKEYBYTES];
        data.copy_from_slice(&local_public_key.as_slice()[cxsp::PUBLICKEYBYTES..]);
        signing::PublicKey(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::DEFAULT_CHAIN_ID;
    use ethsign_crypto::Keccak256;

    impl Default for CryptDEReal {
        fn default() -> Self {
            Self::new(DEFAULT_CHAIN_ID)
        }
    }

    #[test]
    fn construction_generates_different_keys() {
        let first_subject = CryptDEReal::default();
        let second_subject = CryptDEReal::default();

        assert_ne!(first_subject.public_key(), second_subject.public_key());
    }

    #[test]
    fn dup_produces_identical_keys() {
        let subject = CryptDEReal::default();

        let dup = subject.dup();

        assert_eq!(subject.public_key(), dup.public_key());
    }

    #[test]
    fn random_produces_different_fields_of_data() {
        let subject = CryptDEReal::default();
        let mut first_field = [0u8; 100];
        let mut second_field = [0u8; 100];

        subject.random(&mut first_field);
        subject.random(&mut second_field);

        assert_ne!(&first_field[..], &second_field[..]);
    }

    #[test]
    fn same_value_hashed_produces_same_hash() {
        let subject = CryptDEReal::default();
        let value = PlainData::new(&[0u8; 100]);

        let first_hash = subject.hash(&value);
        let second_hash = subject.hash(&value);

        assert_eq!(first_hash, second_hash);
    }

    #[test]
    fn different_values_hashed_produce_different_hashes() {
        let subject = CryptDEReal::default();
        let first_value = PlainData::new(&[0u8; 100]);
        let second_value = PlainData::new(&[1u8; 100]);

        let first_hash = subject.hash(&first_value);
        let second_hash = subject.hash(&second_value);

        assert_ne!(first_hash, second_hash);
        assert_eq!(first_hash.len(), second_hash.len());
    }

    #[test]
    fn encode_with_invalid_key() {
        let subject = CryptDEReal::default();

        let result = subject.encode(
            &PublicKey::new(b"not long enough"),
            &PlainData::new(b"data"),
        );

        assert_eq!(
            CryptdecError::InvalidKey(String::from(
                "[110, 111, 116, 32, 108, 111, 110, 103, 32, 101, 110, 111, 117, 103, 104]"
            )),
            result.err().unwrap()
        );
    }

    #[test]
    fn decode_with_empty_data() {
        let subject = CryptDEReal::default();

        let result = subject.decode(&CryptData::new(b""));

        assert_eq!(CryptdecError::EmptyData, result.err().unwrap());
    }

    #[test]
    fn decode_with_data_too_short_to_be_valid() {
        let data = CryptData::new(b"short");
        let subject = CryptDEReal::default();

        let result = subject.decode(&data);

        assert_eq!(CryptdecError::EmptyData, result.err().unwrap());
    }

    #[test]
    fn encode_and_then_decode_with_the_wrong_key() {
        let subject1 = CryptDEReal::default();
        let subject2 = CryptDEReal::default();
        let data = PlainData::new(&[4u8; 100]);
        let crypt_data = subject1.encode(subject1.public_key(), &data).unwrap();

        let result = subject2.decode(&crypt_data);

        assert_eq!(result, Err(CryptdecError::OpeningFailed))
    }

    #[test]
    fn encoding_the_same_data_twice_with_the_same_key_produces_different_results() {
        let subject = CryptDEReal::default();
        let data = PlainData::new(&[10u8; 100]);

        let crypt_data1 = subject.encode(subject.public_key(), &data);
        let crypt_data2 = subject.encode(subject.public_key(), &data);

        assert_ne!(crypt_data1, crypt_data2);
    }

    #[test]
    fn encode_decode_round_trip_works() {
        let subject = CryptDEReal::default();

        let data = PlainData::new(b"Let me out!");
        let encoded = subject.encode(subject.public_key(), &data).unwrap();
        let decoded = subject.decode(&encoded).unwrap();

        assert_eq!(decoded, data);
    }

    #[test]
    fn stringifies_public_key_properly() {
        let subject = CryptDEReal::default();
        let public_encryption_key = &subject.public_key.as_slice()[..cxsp::PUBLICKEYBYTES];

        let result = subject.public_key_to_descriptor_fragment(subject.public_key());

        assert_eq!(
            result,
            base64::encode_config(public_encryption_key, base64::STANDARD_NO_PAD)
        );
    }

    #[test]
    fn destringifies_public_key_properly() {
        let subject = CryptDEReal::default();
        let public_encryption_key = &subject.public_key.as_slice()[..cxsp::PUBLICKEYBYTES];
        let half_key_string = base64::encode_config(public_encryption_key, base64::STANDARD_NO_PAD);

        let result = subject
            .descriptor_fragment_to_first_contact_public_key(&half_key_string)
            .unwrap();

        let encryption_half = &result.as_slice()[..cxsp::PUBLICKEYBYTES];
        let signing_half = &result.as_slice()[cxsp::PUBLICKEYBYTES..];
        assert_eq!(encryption_half, public_encryption_key);
        assert_eq!(signing_half, &[0u8; signing::PUBLICKEYBYTES]);
    }

    #[test]
    fn fails_to_destringify_bad_base64_public_key_string_properly() {
        let subject = CryptDEReal::default();
        let half_key_string = "((]--$";

        let result = subject.descriptor_fragment_to_first_contact_public_key(half_key_string);

        assert_eq!(
            result,
            Err(String::from("Invalid Base64 value for public key: ((]--$"))
        );
    }

    #[test]
    fn fails_to_destringify_short_public_key_string_properly() {
        let subject = CryptDEReal::default();
        let short_public_encryption_key =
            &subject.public_key.as_slice()[..cxsp::PUBLICKEYBYTES - 1];
        let short_half_key_string =
            base64::encode_config(short_public_encryption_key, base64::STANDARD_NO_PAD);

        let result =
            subject.descriptor_fragment_to_first_contact_public_key(&short_half_key_string);

        assert_eq!(
            result,
            Err(format!(
                "Public key must decode to 32 bytes, not 31: {}",
                short_half_key_string
            ))
        );
    }

    #[test]
    fn fails_to_destringify_long_public_key_string_properly() {
        let subject = CryptDEReal::default();
        let mut long_public_encryption_key =
            subject.public_key.as_slice()[..cxsp::PUBLICKEYBYTES].to_vec();
        long_public_encryption_key.push(0);
        let long_half_key_string =
            base64::encode_config(&long_public_encryption_key, base64::STANDARD_NO_PAD);

        let result = subject.descriptor_fragment_to_first_contact_public_key(&long_half_key_string);

        assert_eq!(
            result,
            Err(format!(
                "Public key must decode to 32 bytes, not 33: {}",
                long_half_key_string
            ))
        );
    }

    #[test]
    fn verifying_a_good_signature_works() {
        let hashable_data = &[121u8; 100];
        let data = PlainData::new(hashable_data);
        let subject = CryptDEReal::default();

        let signature = subject.sign(&data).unwrap();
        let result = subject.verify_signature(&data, &signature, &subject.public_key());

        assert_eq!(true, result);
    }

    #[test]
    fn verifying_an_invalid_signature_fails() {
        let hashable_data = &[122u8; 100];
        let data = PlainData::new(hashable_data);
        let subject = CryptDEReal::default();
        let signature = subject.sign(&data).unwrap();
        let short_signature = CryptData::new(&signature.as_slice()[1..]);

        let result = subject.verify_signature(&data, &short_signature, &subject.public_key());

        assert_eq!(false, result);
    }

    #[test]
    fn verifying_a_modified_signature_fails() {
        let hashable_data = &[122u8; 100];
        let data = PlainData::new(hashable_data);
        let subject = CryptDEReal::default();
        let signature = subject.sign(&data).unwrap();
        let mut signature_data: Vec<u8> = signature.into();
        signature_data[0] = signature_data[0].wrapping_add(1);
        let modified_signature = CryptData::from(signature_data);

        let result = subject.verify_signature(&data, &modified_signature, &subject.public_key());

        assert_eq!(false, result);
    }

    #[test]
    fn verifying_a_signature_on_modified_data_fails() {
        let hashable_data = &[122u8; 100];
        let data = PlainData::new(hashable_data);
        let subject = CryptDEReal::default();
        let mut modified = hashable_data.to_vec();
        modified[0] = modified[0].wrapping_add(1);
        let different_data = PlainData::from(modified);
        let signature = subject.sign(&data).unwrap();

        let result = subject.verify_signature(&different_data, &signature, &subject.public_key());

        assert_eq!(false, result);
    }

    #[test]
    fn hashing_produces_a_digest_with_the_smart_contract_address() {
        let subject = &CryptDEReal::default();
        let merged = [
            subject.public_key().as_ref(),
            contract_address(DEFAULT_CHAIN_ID).as_ref(),
        ]
        .concat();
        let expected_digest = merged.keccak256();

        let actual_digest = subject.digest();

        assert_eq!(expected_digest, actual_digest);
    }
}
