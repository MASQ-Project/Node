// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use rand::prelude::*;
use cryptde::CryptDE;
use cryptde::CryptdecError;
use cryptde::Key;
use cryptde::PlainData;
use cryptde::CryptData;

#[derive (Clone)]
pub struct CryptDENull {
    private_key: Key,
    public_key: Key
}

impl CryptDE for CryptDENull {
    fn generate_key_pair(&mut self) {
        self.private_key = Key::new (&[0; 32]);
        let mut rng = thread_rng();
        for idx in 0..32 {
            self.private_key.data[idx] = rng.gen ();
        }
        self.public_key = CryptDENull::other_key (&self.private_key ())
    }

    fn encode(&self, key: &Key, data: &PlainData) -> Result<CryptData, CryptdecError> {
        if key.data.is_empty() {
            Err(CryptdecError::EmptyKey)
        } else if data.data.is_empty() {
            Err(CryptdecError::EmptyData)
        } else {
            let other_key = CryptDENull::other_key(key);
            Ok(CryptData::new (&[&other_key.data[..], &data.data[..]].concat()[..]))
        }
    }

    fn decode(&self, key: &Key, data: &CryptData) -> Result<PlainData, CryptdecError> {
        if key.data.is_empty() {
            Err(CryptdecError::EmptyKey)
        } else if data.data.is_empty() {
            Err(CryptdecError::EmptyData)
        } else if key.data.len() > data.data.len() {
            Err(CryptdecError::InvalidKey (CryptDENull::invalid_key_message(key, data)))
        } else {
            let (k, d) = data.data.split_at(key.data.len());
            if k != &key.data[..] {
                Err(CryptdecError::InvalidKey (CryptDENull::invalid_key_message(key, data)))
            } else {
                Ok(PlainData::new (d))
            }
        }
    }

    fn random (&self, dest: &mut [u8]) {
        for i in 0..dest.len () {
            dest[i] = '4' as u8
        }
    }

    fn private_key (&self) -> Key {
        self.private_key.clone ()
    }

    fn public_key (&self) -> Key {
        self.public_key.clone ()
    }
}

impl CryptDENull {
    pub fn new () -> CryptDENull {
        let key = Key::new (b"uninitialized");
        CryptDENull {
            private_key: key.clone (),
            public_key: CryptDENull::other_key (&key)
        }
    }

    pub fn other_key(in_key: &Key) -> Key {
        let out_key_data: Vec<u8> = in_key.data.iter ().map (|b| {(*b).wrapping_add (128)}).collect ();
        Key::new (&out_key_data[..])
    }

    fn invalid_key_message (key: &Key, data: &CryptData) -> String {
        let data_to_print: Vec<u8> = data.clone ().data.into_iter ().take (key.data.len ()).collect ();
        format!("Could not decrypt with {:?} data beginning with {:?}", key.data, data_to_print)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_with_empty_key() {
        let subject = CryptDENull::new ();

        let result = subject.encode(&Key::new (b""), &PlainData::new (b"data"));

        assert_eq!(result.err().unwrap(), CryptdecError::EmptyKey);
    }

    #[test]
    fn encode_with_empty_data() {
        let subject = CryptDENull::new ();

        let result = subject.encode(&Key::new (b"key"), &PlainData::new (b""));

        assert_eq!(result.err().unwrap(), CryptdecError::EmptyData);
    }

    #[test]
    fn encode_with_key_and_data() {
        let subject = CryptDENull::new ();

        let result = subject.encode(&Key::new (b"key"), &PlainData::new (b"data"));

        let mut data = CryptDENull::other_key(&Key::new (b"key")).data;
        data.extend (b"data".iter ());
        assert_eq!(result.ok().unwrap(), CryptData::new (&data[..]));
    }

    #[test]
    fn decode_with_empty_key() {
        let subject = CryptDENull::new ();

        let result = subject.decode(&Key::new(b""), &CryptData::new (b"keydata"));

        assert_eq!(result.err().unwrap(), CryptdecError::EmptyKey);
    }

    #[test]
    fn decode_with_empty_data() {
        let subject = CryptDENull::new ();

        let result = subject.decode(&Key::new (b"key"), &CryptData::new (b""));

        assert_eq!(result.err().unwrap(), CryptdecError::EmptyData);
    }

    #[test]
    fn decode_with_key_and_data() {
        let subject = CryptDENull::new ();

        let result = subject.decode(&Key::new (b"key"), &CryptData::new (b"keydata"));

        assert_eq!(result.ok().unwrap(), PlainData::new (b"data"));
    }

    #[test]
    fn decode_with_invalid_key_and_data() {
        let subject = CryptDENull::new ();

        let result = subject.decode(&Key::new (b"badKey"), &CryptData::new (b"keydata"));

        assert_eq!(result.err().unwrap(), CryptdecError::InvalidKey (String::from ("Could not decrypt with [98, 97, 100, 75, 101, 121] data beginning with [107, 101, 121, 100, 97, 116]")));
    }

    #[test]
    fn decode_with_key_exceeding_data_length() {
        let subject = CryptDENull::new ();

        let result = subject.decode(&Key::new (b"invalidkey"), &CryptData::new (b"keydata"));

        assert_eq!(result.err().unwrap(), CryptdecError::InvalidKey (String::from ("Could not decrypt with [105, 110, 118, 97, 108, 105, 100, 107, 101, 121] data beginning with [107, 101, 121, 100, 97, 116, 97]")));
    }

    #[test]
    fn random_is_pretty_predictable () {
        let subject = CryptDENull::new ();
        let mut dest: [u8; 11] = [0; 11];

        subject.random (&mut dest[..]);

        assert_eq! (dest, &b"44444444444"[..]);
    }

    #[test]
    fn private_key_before_generation () {
        let expected = Key::new (b"uninitialized");
        let subject = CryptDENull::new ();

        let result = subject.private_key ();

        assert_eq! (result, expected);
    }

    #[test]
    fn public_key_before_generation () {
        let subject = CryptDENull::new ();
        let expected = CryptDENull::other_key (&Key::new (b"uninitialized"));

        let result = subject.public_key ();

        assert_eq! (result, expected);
    }

    #[test]
    fn generation_produces_different_keys_each_time () {
        let mut subject = CryptDENull::new ();

        subject.generate_key_pair ();
        let first_public = subject.public_key ();
        let first_private = subject.private_key ();

        subject.generate_key_pair ();
        let second_public = subject.public_key ();
        let second_private = subject.private_key ();

        assert_ne! (second_public, first_public);
        assert_ne! (second_private, first_private);
    }

    #[test]
    fn generated_keys_work_with_each_other () {
        let mut subject = CryptDENull::new ();

        subject.generate_key_pair ();

        let expected_data = PlainData::new (&b"These are the times that try men's souls"[..]);
        let encrypted_data = subject.encode (&subject.public_key (), &expected_data).unwrap ();
        let decrypted_data = subject.decode (&subject.private_key (), &encrypted_data).unwrap ();
        assert_eq! (decrypted_data, expected_data);
    }

    #[test]
    fn other_key_works () {
        let one_key = Key::new (b"The quick brown fox jumps over the lazy dog");

        let another_key = CryptDENull::other_key(&one_key);

        assert_ne! (one_key, another_key);
        assert_eq! (CryptDENull::other_key(&another_key), one_key);
    }
}
