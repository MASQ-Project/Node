// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::cryptde::CryptData;
use crate::sub_lib::cryptde::CryptdecError;
use crate::sub_lib::cryptde::PlainData;
use crate::sub_lib::cryptde::PrivateKey;
use crate::sub_lib::cryptde::PublicKey;
use rand::prelude::*;

pub struct CryptDENull {
    private_key: PrivateKey,
    public_key: PublicKey,
}

impl CryptDE for CryptDENull {
    fn generate_key_pair(&mut self) {
        let mut private_key = [0; 32];
        let mut rng = thread_rng();
        for idx in 0..32 {
            private_key[idx] = rng.gen();
        }
        self.private_key = PrivateKey::from(&private_key[..]);
        self.public_key = CryptDENull::public_from_private(&self.private_key())
    }

    fn encode(&self, public_key: &PublicKey, data: &PlainData) -> Result<CryptData, CryptdecError> {
        Self::encode_with_key_data(public_key.as_slice(), data)
    }

    fn decode(&self, data: &CryptData) -> Result<PlainData, CryptdecError> {
        Self::decode_with_key_data(self.private_key.as_slice(), data)
    }

    fn random(&self, dest: &mut [u8]) {
        for i in 0..dest.len() {
            dest[i] = '4' as u8
        }
    }

    fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    // This is dup instead of clone because it returns a Box<CryptDE> instead of a CryptDENull.
    fn dup(&self) -> Box<dyn CryptDE> {
        Box::new(CryptDENull {
            private_key: self.private_key.clone(),
            public_key: self.public_key.clone(),
        })
    }

    fn sign(&self, _data: &PlainData) -> Result<CryptData, CryptdecError> {
        // To implement:
        // Hash the data (hashing should be a function of CryptDE)
        // Encrypt the hash _with our private key_ (means you can't use self.encode(); try Self::encode_with_key_data() instead)
        // Return the encrypted hash in a CryptData
        Ok(CryptData::new(b"signed"))
    }

    fn verify_signature(
        &self,
        _data: &PlainData,
        signature: &CryptData,
        _public_key: &PublicKey,
    ) -> bool {
        // To implement:
        // Decrypt the signature _with the supplied public key_ (means you can't use self.decode(); try Self::decode_with_key_data() instead)
        // Hash the data (hashing should be a function of CryptDE)
        // Compare the decrypted signature with the hash; if identical true, else false
        signature.as_slice() == CryptData::new(b"signed").as_slice()
    }
}

impl CryptDENull {
    pub fn new() -> CryptDENull {
        let key = PrivateKey::new(b"uninitialized");
        CryptDENull {
            private_key: key.clone(),
            public_key: CryptDENull::public_from_private(&key),
        }
    }

    pub fn from(public_key: &PublicKey) -> CryptDENull {
        let mut result = CryptDENull::new();
        result.set_key_pair(public_key);
        result
    }

    pub fn set_key_pair(&mut self, public_key: &PublicKey) {
        self.public_key = public_key.clone();
        self.private_key = CryptDENull::private_from_public(public_key);
    }

    pub fn private_from_public(in_key: &PublicKey) -> PrivateKey {
        PrivateKey::new(&Self::other_key_data(in_key.as_slice()))
    }

    pub fn public_from_private(in_key: &PrivateKey) -> PublicKey {
        PublicKey::new(&Self::other_key_data(in_key.as_slice()))
    }

    pub fn other_key_data(in_key_data: &[u8]) -> Vec<u8> {
        in_key_data.iter().map(|b| (*b).wrapping_add(128)).collect()
    }

    fn encode_with_key_data(key_data: &[u8], data: &PlainData) -> Result<CryptData, CryptdecError> {
        if key_data.is_empty() {
            Err(CryptdecError::EmptyKey)
        } else if data.is_empty() {
            Err(CryptdecError::EmptyData)
        } else {
            let other_key = Self::other_key_data(key_data);
            Ok(CryptData::new(
                &[&other_key.as_slice(), data.as_slice()].concat()[..],
            ))
        }
    }

    fn decode_with_key_data(key_data: &[u8], data: &CryptData) -> Result<PlainData, CryptdecError> {
        if key_data.is_empty() {
            Err(CryptdecError::EmptyKey)
        } else if data.is_empty() {
            Err(CryptdecError::EmptyData)
        } else if key_data.len() > data.len() {
            Err(CryptdecError::InvalidKey(CryptDENull::invalid_key_message(
                key_data, data,
            )))
        } else {
            let (k, d) = data.as_slice().split_at(key_data.len());
            if k != key_data {
                Err(CryptdecError::InvalidKey(CryptDENull::invalid_key_message(
                    key_data, data,
                )))
            } else {
                Ok(PlainData::new(d))
            }
        }
    }

    fn invalid_key_message(key_data: &[u8], data: &CryptData) -> String {
        let prefix_len = std::cmp::min(key_data.len(), data.len());
        let vec = Vec::from(&data.as_slice()[0..prefix_len]);
        format!(
            "Could not decrypt with {:?} data beginning with {:?}",
            key_data, vec
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_with_empty_key() {
        let subject = CryptDENull::new();

        let result = subject.encode(&PublicKey::new(b""), &PlainData::new(b"data"));

        assert_eq!(result.err().unwrap(), CryptdecError::EmptyKey);
    }

    #[test]
    fn encode_with_empty_data() {
        let subject = CryptDENull::new();

        let result = subject.encode(&PublicKey::new(b"key"), &PlainData::new(b""));

        assert_eq!(result.err().unwrap(), CryptdecError::EmptyData);
    }

    #[test]
    fn encode_with_key_and_data() {
        let subject = CryptDENull::new();

        let result = subject.encode(&PublicKey::new(b"key"), &PlainData::new(b"data"));

        let mut data: Vec<u8> = CryptDENull::private_from_public(&PublicKey::new(b"key")).into();
        data.extend(b"data".iter());
        assert_eq!(result.ok().unwrap(), CryptData::new(&data[..]));
    }

    #[test]
    fn decode_with_empty_key() {
        let mut subject = CryptDENull::new();
        subject.private_key = PrivateKey::new(b"");

        let result = subject.decode(&CryptData::new(b"keydata"));

        assert_eq!(result.err().unwrap(), CryptdecError::EmptyKey);
    }

    #[test]
    fn decode_with_empty_data() {
        let mut subject = CryptDENull::new();
        subject.private_key = PrivateKey::new(b"key");

        let result = subject.decode(&CryptData::new(b""));

        assert_eq!(result.err().unwrap(), CryptdecError::EmptyData);
    }

    #[test]
    fn decode_with_key_and_data() {
        let mut subject = CryptDENull::new();
        subject.private_key = PrivateKey::new(b"key");

        let result = subject.decode(&CryptData::new(b"keydata"));

        assert_eq!(result.ok().unwrap(), PlainData::new(b"data"));
    }

    #[test]
    fn decode_with_invalid_key_and_data() {
        let mut subject = CryptDENull::new();
        subject.private_key = PrivateKey::new(b"badKey");

        let result = subject.decode(&CryptData::new(b"keydataxyz"));

        assert_eq!(result.err().unwrap(), CryptdecError::InvalidKey (String::from ("Could not decrypt with [98, 97, 100, 75, 101, 121] data beginning with [107, 101, 121, 100, 97, 116]")));
    }

    #[test]
    fn decode_with_key_exceeding_data_length() {
        let mut subject = CryptDENull::new();
        subject.private_key = PrivateKey::new(b"invalidkey");

        let result = subject.decode(&CryptData::new(b"keydata"));

        assert_eq!(result.err().unwrap(), CryptdecError::InvalidKey (String::from ("Could not decrypt with [105, 110, 118, 97, 108, 105, 100, 107, 101, 121] data beginning with [107, 101, 121, 100, 97, 116, 97]")));
    }

    #[test]
    fn random_is_pretty_predictable() {
        let subject = CryptDENull::new();
        let mut dest: [u8; 11] = [0; 11];

        subject.random(&mut dest[..]);

        assert_eq!(dest, &b"44444444444"[..]);
    }

    #[test]
    fn private_key_before_generation() {
        let expected = PrivateKey::new(b"uninitialized");
        let subject = CryptDENull::new();

        let result = subject.private_key();

        assert_eq!(result.clone(), expected);
    }

    #[test]
    fn public_key_before_generation() {
        let subject = CryptDENull::new();
        let expected = CryptDENull::public_from_private(&PrivateKey::new(b"uninitialized"));

        let result = subject.public_key();

        assert_eq!(result.clone(), expected);
    }

    #[test]
    fn generation_produces_different_keys_each_time() {
        let mut subject = CryptDENull::new();

        subject.generate_key_pair();
        let first_public = subject.public_key().clone();
        let first_private = subject.private_key().clone();

        subject.generate_key_pair();
        let second_public = subject.public_key().clone();
        let second_private = subject.private_key().clone();

        assert_ne!(second_public, first_public);
        assert_ne!(second_private, first_private);
    }

    #[test]
    fn generated_keys_work_with_each_other() {
        let mut subject = CryptDENull::new();

        subject.generate_key_pair();

        let expected_data = PlainData::new(&b"These are the times that try men's souls"[..]);
        let encrypted_data = subject
            .encode(&subject.public_key(), &expected_data)
            .unwrap();
        let decrypted_data = subject.decode(&encrypted_data).unwrap();
        assert_eq!(decrypted_data, expected_data);
    }

    #[test]
    fn private_and_public_keys_are_different_and_derivable_from_each_other() {
        let original_private_key = PrivateKey::new(b"The quick brown fox jumps over the lazy dog");

        let public_key = CryptDENull::public_from_private(&original_private_key);
        let resulting_private_key = CryptDENull::private_from_public(&public_key);

        assert_ne!(original_private_key.as_slice(), public_key.as_slice());
        assert_eq!(resulting_private_key, original_private_key);
    }

    #[test]
    fn from_and_setting_key_pair_works() {
        let public_key = PublicKey::new(b"The quick brown fox jumps over the lazy dog");

        let subject = CryptDENull::from(&public_key);

        let expected_data = PlainData::new(&b"These are the times that try men's souls"[..]);
        let encrypted_data = subject.encode(&public_key, &expected_data).unwrap();
        let decrypted_data = subject.decode(&encrypted_data).unwrap();
        assert_eq!(decrypted_data, expected_data);
        let encrypted_data = subject
            .encode(&subject.public_key(), &expected_data)
            .unwrap();
        let decrypted_data = subject.decode(&encrypted_data).unwrap();
        assert_eq!(decrypted_data, expected_data);
    }

    #[test]
    fn dup_works() {
        let mut subject = CryptDENull::new();
        subject.generate_key_pair();

        let result = subject.dup();

        assert_eq!(result.public_key(), subject.public_key());
        assert_eq!(result.private_key(), subject.private_key());
    }

    #[test]
    fn verifying_a_good_signature_works() {
        let data = PlainData::new(b"Fourscore and seven years ago");
        let subject = CryptDENull::new();

        let signature = subject.sign(&data).unwrap();
        let result = subject.verify_signature(&data, &signature, &subject.public_key());

        assert_eq!(result, true);
    }
}
