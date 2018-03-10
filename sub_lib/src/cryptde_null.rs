// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
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
            Err(CryptdecError::InvalidKey)
        } else {
            let (k, d) = data.data.split_at(key.data.len());
            if k != &key.data[..] {
                Err(CryptdecError::InvalidKey)
            } else {
                Ok(PlainData::new (d))
            }
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
        let key = Key::new (b"local_private_key");
        CryptDENull {
            private_key: key.clone (),
            public_key: CryptDENull::other_key (&key)
        }
    }

    pub fn other_key(in_key: &Key) -> Key {
        let out_key_data: Vec<u8> = in_key.data.iter ().map (|b| {(*b).wrapping_add (128)}).collect ();
        Key::new (&out_key_data[..])
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

        assert_eq!(result.err().unwrap(), CryptdecError::InvalidKey);
    }

    #[test]
    fn decode_with_key_exceeding_data_length() {
        let subject = CryptDENull::new ();

        let result = subject.decode(&Key::new (b"invalidkey"), &CryptData::new (b"keydata"));

        assert_eq!(result.err().unwrap(), CryptdecError::InvalidKey);
    }

    #[test]
    fn private_key () {
        let expected = Key::new (b"local_private_key");
        let subject = CryptDENull::new ();

        let result = subject.private_key ();

        assert_eq! (result, expected);
    }

    #[test]
    fn public_key () {
        let subject = CryptDENull::new ();
        let expected = CryptDENull::other_key (&Key::new (b"local_private_key"));

        let result = subject.public_key ();

        assert_eq! (result, expected);
    }

    #[test]
    fn other_key_works () {
        let one_key = Key::new (b"The quick brown fox jumps over the lazy dog");

        let another_key = CryptDENull::other_key(&one_key);

        assert_ne! (one_key, another_key);
        assert_eq! (CryptDENull::other_key(&another_key), one_key);
    }
}
