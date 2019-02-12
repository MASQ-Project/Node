// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::cryptde::CryptDE;
use crate::cryptde::CryptData;
use crate::cryptde::CryptdecError;
use crate::cryptde::PlainData;
use crate::cryptde::PrivateKey;
use crate::cryptde::PublicKey;
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
        if public_key.is_empty() {
            Err(CryptdecError::EmptyKey)
        } else if data.is_empty() {
            Err(CryptdecError::EmptyData)
        } else {
            let other_key = CryptDENull::private_from_public(public_key);
            Ok(CryptData::new(
                &[&other_key.as_slice(), data.as_slice()].concat()[..],
            ))
        }
    }

    fn decode(&self, data: &CryptData) -> Result<PlainData, CryptdecError> {
        if self.private_key.is_empty() {
            Err(CryptdecError::EmptyKey)
        } else if data.is_empty() {
            Err(CryptdecError::EmptyData)
        } else if self.private_key.len() > data.len() {
            Err(CryptdecError::InvalidKey(CryptDENull::invalid_key_message(
                &self.private_key,
                data,
            )))
        } else {
            let (k, d) = data.as_slice().split_at(self.private_key.len());
            if k != self.private_key.as_slice() {
                Err(CryptdecError::InvalidKey(CryptDENull::invalid_key_message(
                    &self.private_key,
                    data,
                )))
            } else {
                Ok(PlainData::new(d))
            }
        }
    }

    fn random(&self, dest: &mut [u8]) {
        for i in 0..dest.len() {
            dest[i] = '4' as u8
        }
    }

    fn private_key(&self) -> PrivateKey {
        self.private_key.clone()
    }

    fn public_key(&self) -> PublicKey {
        self.public_key.clone()
    }

    // This is dup instead of clone because it returns a Box<CryptDE> instead of a CryptDENull.
    fn dup(&self) -> Box<dyn CryptDE> {
        Box::new(CryptDENull {
            private_key: self.private_key.clone(),
            public_key: self.public_key.clone(),
        })
    }

    fn sign(&self, _data: &PlainData) -> Result<CryptData, CryptdecError> {
        Ok(CryptData::new(b"signed"))
    }

    fn verify_signature(
        &self,
        _data: &PlainData,
        _signature: &CryptData,
        _public_key: &PublicKey,
    ) -> bool {
        true
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
        let out_key_data: Vec<u8> = in_key
            .as_slice()
            .iter()
            .map(|b| (*b).wrapping_add(128))
            .collect();
        PrivateKey::new(&out_key_data[..])
    }

    pub fn public_from_private(in_key: &PrivateKey) -> PublicKey {
        let out_key_data: Vec<u8> = in_key
            .as_slice()
            .iter()
            .map(|b| (*b).wrapping_add(128))
            .collect();
        PublicKey::new(&out_key_data[..])
    }

    fn invalid_key_message(key: &PrivateKey, data: &CryptData) -> String {
        let prefix_len = std::cmp::min(key.len(), data.len());
        let vec = Vec::from(&data.as_slice()[0..prefix_len]);
        format!(
            "Could not decrypt with {:?} data beginning with {:?}",
            key.as_slice(),
            vec
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

        assert_eq!(result, expected);
    }

    #[test]
    fn public_key_before_generation() {
        let subject = CryptDENull::new();
        let expected = CryptDENull::public_from_private(&PrivateKey::new(b"uninitialized"));

        let result = subject.public_key();

        assert_eq!(result, expected);
    }

    #[test]
    fn generation_produces_different_keys_each_time() {
        let mut subject = CryptDENull::new();

        subject.generate_key_pair();
        let first_public = subject.public_key();
        let first_private = subject.private_key();

        subject.generate_key_pair();
        let second_public = subject.public_key();
        let second_private = subject.private_key();

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
