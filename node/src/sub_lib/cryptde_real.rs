// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::sub_lib::cryptde;
use crate::sub_lib::cryptde::{
    CryptDE, CryptData, CryptdecError, PlainData, PrivateKey, PublicKey, SymmetricKey,
};
use lazy_static::lazy_static;
use masq_lib::blockchains::chains::Chain;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305 as cxsp;
use sodiumoxide::crypto::sealedbox::curve25519blake2bxsalsa20poly1305::SEALBYTES;
use sodiumoxide::crypto::sealedbox::{open, seal};
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::sign as signing;
use sodiumoxide::crypto::{box_ as encryption, hash};
use sodiumoxide::randombytes::randombytes_into;
use std::any::Any;

lazy_static! {
    static ref INITIALIZED: bool = {
        match sodiumoxide::init() {
            Ok(_) => true,
            Err(e) => panic!("sodiumoxide initialization failed: {:?}", e),
        }
    };
}

#[allow(clippy::upper_case_acronyms)]
pub struct CryptDEReal {
    public_key: PublicKey,
    encryption_secret_key: encryption::SecretKey,
    signing_secret_key: signing::SecretKey,
    digest: [u8; 32],
    pre_shared_data: [u8; 20],
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

    fn encode_sym(&self, key: &SymmetricKey, data: &PlainData) -> Result<CryptData, CryptdecError> {
        let nonce = secretbox::gen_nonce();
        let cipher_data = {
            match secretbox::Key::from_slice(key.as_slice()) {
                None => return Err(CryptdecError::InvalidKey(format!("{:?}", key.as_slice()))),
                Some(secretbox_key) => secretbox::seal(data.as_slice(), &nonce, &secretbox_key),
            }
        };
        let mut result: Vec<u8> = nonce[..].to_vec();
        result.extend(cipher_data);
        Ok(CryptData::new(&result))
    }

    fn decode_sym(&self, key: &SymmetricKey, data: &CryptData) -> Result<PlainData, CryptdecError> {
        if data.len() <= secretbox::NONCEBYTES {
            return Err(CryptdecError::EmptyData);
        }
        let nonce_data = &data.as_slice()[0..secretbox::NONCEBYTES];
        let secret_key = match secretbox::Key::from_slice(key.as_slice()) {
            None => return Err(CryptdecError::InvalidKey(format!("{:?}", key.as_slice()))),
            Some(secret_key) => secret_key,
        };
        let crypt_data = &data.as_slice()[secretbox::NONCEBYTES..];
        let nonce = match secretbox::Nonce::from_slice(nonce_data) {
            None => return Err(CryptdecError::EmptyData),
            Some(nonce) => nonce,
        };
        let plain_data = match secretbox::open(crypt_data, &nonce, &secret_key) {
            Err(_) => return Err(CryptdecError::OpeningFailed),
            Ok(data) => data,
        };
        Ok(PlainData::new(&plain_data))
    }

    fn gen_key_sym(&self) -> SymmetricKey {
        SymmetricKey::new(&secretbox::gen_key()[..])
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
            pre_shared_data: self.pre_shared_data,
        })
    }

    fn sign(&self, data: &PlainData) -> Result<CryptData, CryptdecError> {
        let data_to_sign = [data.as_slice(), &self.pre_shared_data[..]].concat();
        Ok(CryptData::new(
            &signing::sign_detached(data_to_sign.as_slice(), &self.signing_secret_key).0,
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
        let data_to_verify = [data.as_slice(), &self.pre_shared_data[..]].concat();
        signing::verify_detached(
            &signing::Signature(signature_data),
            data_to_verify.as_slice(),
            &Self::signing_public_key_from(public_key),
        )
    }

    fn hash(&self, data: &PlainData) -> CryptData {
        let digest = hash::hash(data.as_slice());
        CryptData::new(&digest.0)
    }

    fn public_key_to_descriptor_fragment(&self, public_key: &PublicKey) -> String {
        let encryption_public_key = &public_key.as_slice()[..cxsp::PUBLICKEYBYTES];
        base64::encode_config(encryption_public_key, base64::URL_SAFE_NO_PAD)
    }

    fn descriptor_fragment_to_first_contact_public_key(
        &self,
        descriptor_fragment: &str,
    ) -> Result<PublicKey, String> {
        let mut encryption_public_key =
            match base64::decode_config(descriptor_fragment, base64::URL_SAFE_NO_PAD) {
                Ok(v) => v,
                Err(_) => {
                    return Err(format!(
                        "Invalid Base64 value for public key: {}",
                        descriptor_fragment,
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

    fn make_from_str(&self, value: &str, chain: Chain) -> Result<Box<dyn CryptDE>, String> {
        let parts = value.split(',').collect::<Vec<_>>();
        if parts.len() != 2 {
            return Err(format!(
                "Serialized CryptDE must have 2 comma-separated parts, not {}",
                parts.len()
            ));
        }
        let convert = |s: &str| -> Result<Vec<u8>, String> {
            match base64::decode_config(s, base64::URL_SAFE_NO_PAD) {
                Ok(v) => Ok(v),
                Err(_) => Err(format!(
                    "Serialized CryptDE must have valid Base64, not '{}'",
                    s
                )),
            }
        };
        let encryption_secret_key = match convert(parts[0]) {
            Ok(v) => encryption::SecretKey(match v.clone().try_into() {
                Ok(vi) => vi,
                Err(_) => {
                    return Err(format!(
                        "Serialized CryptDE must have {}-byte encryption key, not {}",
                        cxsp::SECRETKEYBYTES,
                        v.len()
                    ))
                }
            }),
            Err(e) => return Err(e),
        };
        let signing_secret_key = match convert(parts[1]) {
            Ok(v) => signing::SecretKey(match v.clone().try_into() {
                Ok(vi) => vi,
                Err(_) => {
                    return Err(format!(
                        "Serialized CryptDE must have {}-byte signing key, not {}",
                        signing::SECRETKEYBYTES,
                        v.len()
                    ))
                }
            }),
            Err(e) => return Err(e),
        };
        let public_key = Self::local_public_key_from(
            &encryption_secret_key.public_key(),
            &signing_secret_key.public_key(),
        );
        let digest = cryptde::create_digest(&public_key, &chain.rec().contract);
        let pre_shared_data = chain.rec().contract.0;
        Ok(Box::new(CryptDEReal {
            public_key,
            encryption_secret_key,
            signing_secret_key,
            digest,
            pre_shared_data,
        }))
    }

    fn to_string(&self) -> String {
        let encryption_secret_data = self.encryption_secret_key.as_ref().to_vec();
        let signing_secret_data = self.signing_secret_key.as_ref().to_vec();
        format!(
            "{},{}",
            base64::encode_config(&encryption_secret_data, base64::URL_SAFE_NO_PAD),
            base64::encode_config(&signing_secret_data, base64::URL_SAFE_NO_PAD)
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl CryptDEReal {
    pub fn new(chain: Chain) -> Self {
        let (e_public, e_secret) = encryption::gen_keypair();
        let (s_public, s_secret) = signing::gen_keypair();
        let public_key = Self::local_public_key_from(&e_public, &s_public);
        let digest = cryptde::create_digest(&public_key, &chain.rec().contract);
        let pre_shared_data = chain.rec().contract.0;

        Self {
            public_key,
            encryption_secret_key: e_secret,
            signing_secret_key: s_secret,
            digest,
            pre_shared_data,
        }
    }

    pub fn disabled() -> Self {
        Self {
            public_key: PublicKey::new(&[0u8; cxsp::PUBLICKEYBYTES + signing::PUBLICKEYBYTES]),
            encryption_secret_key: encryption::SecretKey([0u8; cxsp::SECRETKEYBYTES]),
            signing_secret_key: signing::SecretKey([0u8; signing::SECRETKEYBYTES]),
            digest: [0u8; 32],
            pre_shared_data: [0u8; 20],
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
    use ethsign_crypto::Keccak256;
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;

    impl Default for CryptDEReal {
        fn default() -> Self {
            Self::new(TEST_DEFAULT_CHAIN)
        }
    }

    #[test]
    fn disabled_works() {
        let subject = CryptDEReal::disabled();

        assert_eq!(subject.public_key().as_slice(), &[0u8; cxsp::PUBLICKEYBYTES + signing::PUBLICKEYBYTES]);
        assert_eq!(subject.encryption_secret_key.as_ref(), &[0u8; cxsp::SECRETKEYBYTES]);
        assert_eq!(subject.signing_secret_key.as_ref(), &[0u8; signing::SECRETKEYBYTES]);
        assert_eq!(subject.digest, [0u8; 32]);
        assert_eq!(subject.pre_shared_data, [0u8; 20]);
    }

    #[test]
    fn to_string_works() {
        let subject = CryptDEReal::default();
        let encryption_secret_data = subject.encryption_secret_key.as_ref().to_vec();
        let signing_secret_data = subject.signing_secret_key.as_ref().to_vec();

        let actual_string: String = subject.to_string();

        let expected_string = format!(
            "{},{}",
            base64::encode_config(&encryption_secret_data, base64::URL_SAFE_NO_PAD),
            base64::encode_config(&signing_secret_data, base64::URL_SAFE_NO_PAD)
        );
        assert_eq!(actual_string, expected_string);
    }

    #[test]
    fn make_from_str_can_fail_on_delimiters() {
        let subject = CryptDEReal::default();
        let string = ",,,,,"; // invalid

        let result = subject.make_from_str(string, Chain::Dev);

        assert_eq!(
            result.err().unwrap(),
            "Serialized CryptDE must have 2 comma-separated parts, not 6".to_string()
        );
    }

    const ENCRYPTION_SECRET_KEY_DATA: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];
    const SIGNING_SECRET_KEY_DATA: [u8; 64] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
        48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
    ];

    #[test]
    fn make_from_str_can_fail_on_key_length_for_encryption() {
        let subject = CryptDEReal::default();
        let encryption_string = "AgMEBQ"; // invalid
        let signing_string =
            base64::encode_config(&SIGNING_SECRET_KEY_DATA, base64::URL_SAFE_NO_PAD);
        let string = format!("{},{}", encryption_string, signing_string);

        let result = subject.make_from_str(string.as_str(), Chain::Dev);

        assert_eq!(
            result.err().unwrap(),
            "Serialized CryptDE must have 32-byte encryption key, not 4".to_string()
        );
    }

    #[test]
    fn make_from_str_can_fail_on_key_length_for_signing() {
        let subject = CryptDEReal::default();
        let encryption_string =
            base64::encode_config(&ENCRYPTION_SECRET_KEY_DATA, base64::URL_SAFE_NO_PAD);
        let signing_string = "AgMEBQ"; // invalid
        let string = format!("{},{}", encryption_string, signing_string);

        let result = subject.make_from_str(string.as_str(), Chain::Dev);

        assert_eq!(
            result.err().unwrap(),
            "Serialized CryptDE must have 64-byte signing key, not 4".to_string()
        );
    }

    #[test]
    fn make_from_str_can_fail_on_base64_syntax_for_encryption() {
        let subject = CryptDEReal::default();
        let signing_string =
            base64::encode_config(&SIGNING_SECRET_KEY_DATA, base64::URL_SAFE_NO_PAD);
        let string = format!("{},{}", "/ / / /", signing_string); // invalid

        let result = subject.make_from_str(string.as_str(), Chain::Dev);

        assert_eq!(
            result.err().unwrap(),
            "Serialized CryptDE must have valid Base64, not '/ / / /'".to_string()
        );
    }

    #[test]
    fn make_from_str_can_fail_on_base64_syntax_for_signing() {
        let subject = CryptDEReal::default();
        let encryption_string =
            base64::encode_config(&ENCRYPTION_SECRET_KEY_DATA, base64::URL_SAFE_NO_PAD);
        let string = format!("{},{}", encryption_string, "/ / / /"); // invalid

        let result = subject.make_from_str(string.as_str(), Chain::Dev);

        assert_eq!(
            result.err().unwrap(),
            "Serialized CryptDE must have valid Base64, not '/ / / /'".to_string()
        );
    }

    #[test]
    fn make_from_str_can_succeed() {
        let subject = CryptDEReal::default();
        let encryption_string =
            base64::encode_config(&ENCRYPTION_SECRET_KEY_DATA, base64::URL_SAFE_NO_PAD);
        let signing_string =
            base64::encode_config(&SIGNING_SECRET_KEY_DATA, base64::URL_SAFE_NO_PAD);
        let string = format!("{},{}", encryption_string, signing_string);

        let boxed_result = subject
            .make_from_str(string.as_str(), Chain::BaseSepolia)
            .unwrap();

        let result = boxed_result
            .as_ref()
            .as_any()
            .downcast_ref::<CryptDEReal>()
            .unwrap();
        let expected_encryption_secret_key = encryption::SecretKey(ENCRYPTION_SECRET_KEY_DATA);
        let expected_signing_secret_key = signing::SecretKey(SIGNING_SECRET_KEY_DATA);
        let expected_public_key = CryptDEReal::local_public_key_from(
            &expected_encryption_secret_key.public_key(),
            &expected_signing_secret_key.public_key(),
        );
        let expected_digest =
            cryptde::create_digest(&expected_public_key, &Chain::BaseSepolia.rec().contract);
        let expected_pre_shared_data = Chain::BaseSepolia.rec().contract.0;

        assert_eq!(result.encryption_secret_key, expected_encryption_secret_key);
        assert_eq!(result.signing_secret_key, expected_signing_secret_key);
        assert_eq!(result.public_key, expected_public_key);
        assert_eq!(result.digest, expected_digest);
        assert_eq!(result.pre_shared_data, expected_pre_shared_data);
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
    fn encode_sym_with_invalid_key() {
        let subject = CryptDEReal::default();

        let result = subject.encode_sym(
            &SymmetricKey::new(b"not long enough"),
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
    fn decode_sym_with_empty_data() {
        let subject = CryptDEReal::default();
        let key = subject.gen_key_sym();

        let result = subject.decode_sym(&key, &CryptData::new(b""));

        assert_eq!(CryptdecError::EmptyData, result.err().unwrap());
    }

    #[test]
    fn decode_sym_with_data_too_short_to_be_valid() {
        let data = CryptData::new(b"short");
        let subject = CryptDEReal::default();
        let key = subject.gen_key_sym();

        let result = subject.decode_sym(&key, &data);

        assert_eq!(CryptdecError::EmptyData, result.err().unwrap());
    }

    #[test]
    fn encode_sym_and_then_decode_sym_with_the_wrong_key() {
        let subject = CryptDEReal::default();
        let key1 = subject.gen_key_sym();
        let key2 = subject.gen_key_sym();
        let data = PlainData::new(&[4u8; 100]);
        let crypt_data = subject.encode_sym(&key1, &data).unwrap();

        let result = subject.decode_sym(&key2, &crypt_data);

        assert_eq!(result, Err(CryptdecError::OpeningFailed))
    }

    #[test]
    fn encode_syming_the_same_data_twice_with_the_same_key_produces_different_results() {
        let subject = CryptDEReal::default();
        let key = subject.gen_key_sym();
        let data = PlainData::new(&[10u8; 100]);

        let crypt_data1 = subject.encode_sym(&key, &data);
        let crypt_data2 = subject.encode_sym(&key, &data);

        assert_ne!(crypt_data1, crypt_data2);
    }

    #[test]
    fn encode_sym_decode_sym_round_trip_works() {
        let subject = CryptDEReal::default();
        let key = subject.gen_key_sym();

        let data = PlainData::new(b"Let me out!");
        let encoded = subject.encode_sym(&key, &data).unwrap();
        let decoded = subject.decode_sym(&key, &encoded).unwrap();

        assert_eq!(decoded, data);
    }

    #[test]
    fn gen_key_sym_produces_different_keys_on_successive_calls() {
        let subject = CryptDEReal::default();

        let one_key = subject.gen_key_sym();
        let another_key = subject.gen_key_sym();
        let third_key = subject.gen_key_sym();

        assert_ne!(one_key, another_key);
        assert_ne!(another_key, third_key);
        assert_ne!(third_key, one_key);
    }

    #[test]
    fn stringifies_public_key_properly() {
        let subject = CryptDEReal::default();
        let public_encryption_key = &subject.public_key.as_slice()[..cxsp::PUBLICKEYBYTES];

        let result = subject.public_key_to_descriptor_fragment(subject.public_key());

        assert_eq!(
            result,
            base64::encode_config(public_encryption_key, base64::URL_SAFE_NO_PAD)
        );
    }

    #[test]
    fn destringifies_public_key_properly() {
        let subject = CryptDEReal::default();
        let public_encryption_key = &subject.public_key.as_slice()[..cxsp::PUBLICKEYBYTES];
        let half_key_string = base64::encode_config(public_encryption_key, base64::URL_SAFE_NO_PAD);

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
            base64::encode_config(short_public_encryption_key, base64::URL_SAFE_NO_PAD);

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
            base64::encode_config(&long_public_encryption_key, base64::URL_SAFE_NO_PAD);

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
            &TEST_DEFAULT_CHAIN.rec().contract.as_ref(),
        ]
        .concat();
        let expected_digest = merged.keccak256();

        let actual_digest = subject.digest();

        assert_eq!(expected_digest, actual_digest);
    }
}
