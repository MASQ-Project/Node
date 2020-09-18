// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::blockchain::blockchain_interface::contract_address;
use crate::sub_lib::cryptde;
use crate::sub_lib::cryptde::CryptData;
use crate::sub_lib::cryptde::CryptdecError;
use crate::sub_lib::cryptde::PlainData;
use crate::sub_lib::cryptde::PrivateKey;
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::cryptde::{CryptDE, SymmetricKey};
use rand::prelude::*;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct CryptDENull {
    private_key: PrivateKey,
    public_key: PublicKey,
    digest: [u8; 32],
    next_symmetric_key_seed: Arc<Mutex<u64>>,
}

impl CryptDE for CryptDENull {
    fn encode(&self, public_key: &PublicKey, data: &PlainData) -> Result<CryptData, CryptdecError> {
        Self::encode_with_key_data(&Self::other_key_data(public_key.as_slice()), data)
    }

    fn decode(&self, data: &CryptData) -> Result<PlainData, CryptdecError> {
        Self::decode_with_key_data(self.private_key.as_slice(), data)
    }

    fn encode_sym(&self, key: &SymmetricKey, data: &PlainData) -> Result<CryptData, CryptdecError> {
        Self::encode_with_key_data(key.as_slice(), data)
    }

    fn decode_sym(&self, key: &SymmetricKey, data: &CryptData) -> Result<PlainData, CryptdecError> {
        Self::decode_with_key_data(key.as_slice(), data)
    }

    fn gen_key_sym(&self) -> SymmetricKey {
        let mut seed = {
            let mut seed = self.next_symmetric_key_seed.lock().unwrap();
            let value: u64 = *seed.deref();
            *seed.deref_mut() = value.wrapping_add(1);
            value
        };
        let mut key_data = [0u8; 8];
        for byte in &mut key_data {
            *byte = (seed & 0xFF) as u8;
            seed >>= 8;
        }
        SymmetricKey::new(&key_data)
    }

    #[allow(clippy::needless_range_loop)]
    fn random(&self, dest: &mut [u8]) {
        for i in 0..dest.len() {
            dest[i] = b'4'
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
            digest: self.digest,
            next_symmetric_key_seed: self.next_symmetric_key_seed.clone(),
        })
    }

    fn sign(&self, data: &PlainData) -> Result<CryptData, CryptdecError> {
        let hash = self.hash(data);
        Self::encode_with_key_data(
            &Self::other_key_data(self.private_key().as_slice()),
            &PlainData::new(hash.as_slice()),
        )
    }

    fn verify_signature(
        &self,
        data: &PlainData,
        signature: &CryptData,
        public_key: &PublicKey,
    ) -> bool {
        let claimed_hash = match Self::decode_with_key_data(public_key.as_slice(), signature) {
            Err(_) => return false,
            Ok(hash) => CryptData::new(hash.as_slice()),
        };
        let actual_hash = self.hash(data);
        actual_hash == claimed_hash
    }

    fn hash(&self, data: &PlainData) -> CryptData {
        let mut hash = sha1::Sha1::new();
        hash.update(data.as_slice());
        CryptData::new(&hash.digest().bytes())
    }

    fn public_key_to_descriptor_fragment(&self, public_key: &PublicKey) -> String {
        base64::encode_config(public_key.as_slice(), base64::STANDARD_NO_PAD)
    }

    fn descriptor_fragment_to_first_contact_public_key(
        &self,
        descriptor_fragment: &str,
    ) -> Result<PublicKey, String> {
        if descriptor_fragment.is_empty() {
            return Err("Public key cannot be empty".to_string());
        }
        let half_key = match base64::decode_config(descriptor_fragment, base64::STANDARD_NO_PAD) {
            Ok(half_key) => half_key,
            Err(_) => {
                return Err(format!(
                    "Invalid Base64 value for public key: {}",
                    descriptor_fragment
                ))
            }
        };
        Ok(PublicKey::from(half_key))
    }

    fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

impl CryptDENull {
    pub fn new(chain_id: u8) -> Self {
        let mut private_key = [0; 32];
        let mut rng = thread_rng();
        for byte in &mut private_key {
            *byte = rng.gen();
        }
        let private_key = PrivateKey::from(&private_key[..]);
        let public_key = Self::public_from_private(&private_key);
        let digest = cryptde::create_digest(&public_key, &contract_address(chain_id));
        Self {
            private_key,
            public_key,
            digest,
            next_symmetric_key_seed: Arc::new(Mutex::new(0x0123_4567_89AB_CDEF)),
        }
    }

    pub fn from(public_key: &PublicKey, chain_id: u8) -> CryptDENull {
        let mut result = CryptDENull::new(chain_id);
        result.set_key_pair(public_key, chain_id);
        result
    }

    pub fn set_key_pair(&mut self, public_key: &PublicKey, chain_id: u8) {
        self.public_key = public_key.clone();
        self.private_key = CryptDENull::private_from_public(public_key);
        self.digest = cryptde::create_digest(public_key, &contract_address(chain_id));
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
            Ok(CryptData::new(&[key_data, data.as_slice()].concat()[..]))
        }
    }

    fn decode_with_key_data(key_data: &[u8], data: &CryptData) -> Result<PlainData, CryptdecError> {
        if key_data.is_empty() {
            Err(CryptdecError::EmptyKey)
        } else if data.is_empty() {
            Err(CryptdecError::EmptyData)
        } else if key_data.len() > data.len() {
            Err(CryptdecError::InvalidKey(CryptDENull::wrong_key_message(
                key_data, data,
            )))
        } else {
            let (k, d) = data.as_slice().split_at(key_data.len());
            if k != key_data {
                eprintln!("{}", Self::wrong_key_message(key_data, data));
                Err(CryptdecError::OpeningFailed)
            } else {
                Ok(PlainData::new(d))
            }
        }
    }

    fn wrong_key_message(key_data: &[u8], data: &CryptData) -> String {
        let prefix_len = std::cmp::min(key_data.len(), data.len());
        let vec = Vec::from(&data.as_slice()[0..prefix_len]);
        format!(
            "Could not decrypt with {:?} data beginning with {:?}",
            key_data, vec
        )
    }

    #[allow(dead_code)]
    fn set_next_symmetric_key_seed(&mut self, seed: u64) {
        let mut guarded_seed = self.next_symmetric_key_seed.lock().unwrap();
        *guarded_seed.deref_mut() = seed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::main_cryptde;
    use ethsign_crypto::Keccak256;
    use masq_lib::test_utils::utils::DEFAULT_CHAIN_ID;

    #[test]
    fn encode_with_empty_key() {
        let subject = main_cryptde();

        let result = subject.encode(&PublicKey::new(b""), &PlainData::new(b"data"));

        assert_eq!(CryptdecError::EmptyKey, result.err().unwrap());
    }

    #[test]
    fn encode_with_empty_data() {
        let subject = main_cryptde();

        let result = subject.encode(&PublicKey::new(b"key"), &PlainData::new(b""));

        assert_eq!(CryptdecError::EmptyData, result.err().unwrap());
    }

    #[test]
    fn encode_with_key_and_data() {
        let subject = main_cryptde();

        let result = subject.encode(&PublicKey::new(b"key"), &PlainData::new(b"data"));

        let mut data: Vec<u8> = CryptDENull::private_from_public(&PublicKey::new(b"key")).into();
        data.extend(b"data".iter());
        assert_eq!(CryptData::new(&data[..]), result.ok().unwrap());
    }

    #[test]
    fn decode_with_empty_key() {
        let mut subject = main_cryptde().clone();
        subject.private_key = PrivateKey::new(b"");

        let result = subject.decode(&CryptData::new(b"keydata"));

        assert_eq!(CryptdecError::EmptyKey, result.err().unwrap());
    }

    #[test]
    fn decode_with_empty_data() {
        let mut subject = main_cryptde().clone();
        subject.private_key = PrivateKey::new(b"key");

        let result = subject.decode(&CryptData::new(b""));

        assert_eq!(CryptdecError::EmptyData, result.err().unwrap());
    }

    #[test]
    fn decode_with_key_and_data() {
        let mut subject = main_cryptde().clone();
        subject.private_key = PrivateKey::new(b"key");

        let result = subject.decode(&CryptData::new(b"keydata"));

        assert_eq!(PlainData::new(b"data"), result.ok().unwrap());
    }

    #[test]
    fn decode_with_incorrect_private_key() {
        let mut subject = main_cryptde().clone();
        subject.private_key = PrivateKey::new(b"badKey");

        let result = subject.decode(&CryptData::new(b"keydataxyz"));

        assert_eq!(CryptdecError::OpeningFailed, result.err().unwrap());
    }

    #[test]
    fn decode_with_key_exceeding_data_length() {
        let mut subject = main_cryptde().clone();
        subject.private_key = PrivateKey::new(b"invalidkey");

        let result = subject.decode(&CryptData::new(b"keydata"));

        assert_eq!(CryptdecError::InvalidKey (String::from ("Could not decrypt with [105, 110, 118, 97, 108, 105, 100, 107, 101, 121] data beginning with [107, 101, 121, 100, 97, 116, 97]")), result.err().unwrap());
    }

    #[test]
    fn gen_key_sym_produces_different_keys_on_successive_calls() {
        let subject = main_cryptde();

        let one_key = subject.gen_key_sym();
        let another_key = subject.gen_key_sym();
        let third_key = subject.gen_key_sym();

        assert_ne!(one_key, another_key);
        assert_ne!(another_key, third_key);
        assert_ne!(third_key, one_key);
    }

    #[test]
    fn gen_key_sym_can_be_controlled_and_wraps_properly() {
        let mut subject = main_cryptde().clone();

        subject.set_next_symmetric_key_seed(0xFFFFFFFFFFFFFFFF);
        let key1 = subject.gen_key_sym();
        let key2 = subject.gen_key_sym();

        assert_eq!(
            key1.as_slice(),
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
        assert_eq!(
            key2.as_slice(),
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn encode_sym_with_empty_key() {
        let subject = main_cryptde();
        let key = SymmetricKey::new(b"");

        let result = subject.encode_sym(&key, &PlainData::new(b"data"));

        assert_eq!(CryptdecError::EmptyKey, result.err().unwrap());
    }

    #[test]
    fn encode_sym_with_empty_data() {
        let subject = main_cryptde();
        let key = subject.gen_key_sym();

        let result = subject.encode_sym(&key, &PlainData::new(b""));

        assert_eq!(CryptdecError::EmptyData, result.err().unwrap());
    }

    #[test]
    fn encode_sym_with_key_and_data() {
        let subject = main_cryptde();
        let key = SymmetricKey::new(b"key");

        let result = subject.encode_sym(&key, &PlainData::new(b"data"));

        let mut data: Vec<u8> = key.into();
        data.extend(b"data".iter());
        assert_eq!(CryptData::new(&data[..]), result.ok().unwrap());
    }

    #[test]
    fn decode_sym_with_empty_key() {
        let subject = main_cryptde().clone();
        let key = SymmetricKey::new(b"");

        let result = subject.decode_sym(&key, &CryptData::new(b"keydata"));

        assert_eq!(CryptdecError::EmptyKey, result.err().unwrap());
    }

    #[test]
    fn decode_sym_with_empty_data() {
        let subject = main_cryptde().clone();
        let key = subject.gen_key_sym();

        let result = subject.decode_sym(&key, &CryptData::new(b""));

        assert_eq!(CryptdecError::EmptyData, result.err().unwrap());
    }

    #[test]
    fn decode_sym_with_key_and_data() {
        let subject = main_cryptde().clone();
        let key = SymmetricKey::new(b"key");

        let result = subject.decode_sym(&key, &CryptData::new(b"keydata"));

        assert_eq!(PlainData::new(b"data"), result.ok().unwrap());
    }

    #[test]
    fn decode_sym_with_wrong_key() {
        let subject = main_cryptde().clone();
        let key = SymmetricKey::new(b"badKey");

        let result = subject.decode_sym(&key, &CryptData::new(b"keydataxyz"));

        assert_eq!(CryptdecError::OpeningFailed, result.err().unwrap());
    }

    #[test]
    fn decode_sym_with_key_exceeding_data_length() {
        let subject = main_cryptde().clone();
        let key = SymmetricKey::new(b"invalidkey");

        let result = subject.decode_sym(&key, &CryptData::new(b"keydata"));

        assert_eq!(CryptdecError::InvalidKey (String::from ("Could not decrypt with [105, 110, 118, 97, 108, 105, 100, 107, 101, 121] data beginning with [107, 101, 121, 100, 97, 116, 97]")), result.err().unwrap());
    }

    #[test]
    fn random_is_pretty_predictable() {
        let subject = main_cryptde();
        let mut dest: [u8; 11] = [0; 11];

        subject.random(&mut dest[..]);

        assert_eq!(&b"44444444444"[..], dest);
    }

    #[test]
    fn construction_produces_different_keys_each_time() {
        let subject1 = CryptDENull::new(DEFAULT_CHAIN_ID);
        let subject2 = CryptDENull::new(DEFAULT_CHAIN_ID);

        let first_public = subject1.public_key().clone();
        let first_private = subject1.private_key().clone();

        let second_public = subject2.public_key().clone();
        let second_private = subject2.private_key().clone();

        assert_ne!(second_public, first_public);
        assert_ne!(second_private, first_private);
    }

    #[test]
    fn generated_keys_work_with_each_other() {
        let subject = main_cryptde();

        let expected_data = PlainData::new(&b"These are the times that try men's souls"[..]);
        let encrypted_data = subject
            .encode(&subject.public_key(), &expected_data)
            .unwrap();
        let decrypted_data = subject.decode(&encrypted_data).unwrap();
        assert_eq!(expected_data, decrypted_data);
    }

    #[test]
    fn symmetric_encryption_works_with_same_key() {
        let subject = main_cryptde();

        let key = subject.gen_key_sym();
        let expected_data = PlainData::new(&b"These are the times that try men's souls"[..]);
        let encrypted_data = subject.encode_sym(&key, &expected_data).unwrap();
        let decrypted_data = subject.decode_sym(&key, &encrypted_data).unwrap();
        assert_eq!(expected_data, decrypted_data);
    }

    #[test]
    fn symmetric_encryption_fails_with_different_keys() {
        let subject = main_cryptde();

        let key1 = subject.gen_key_sym();
        let key2 = subject.gen_key_sym();
        let expected_data = PlainData::new(&b"These are the times that try men's souls"[..]);
        let encrypted_data = subject.encode_sym(&key1, &expected_data).unwrap();

        let result = subject.decode_sym(&key2, &encrypted_data);

        assert_eq!(result, Err(CryptdecError::OpeningFailed));
    }

    #[test]
    fn private_and_public_keys_are_different_and_derivable_from_each_other() {
        let original_private_key = PrivateKey::new(b"The quick brown fox jumps over the lazy dog");

        let public_key = CryptDENull::public_from_private(&original_private_key);
        let resulting_private_key = CryptDENull::private_from_public(&public_key);

        assert_ne!(original_private_key.as_slice(), public_key.as_slice());
        assert_eq!(original_private_key, resulting_private_key);
    }

    #[test]
    fn from_and_setting_key_pair_works() {
        let public_key = PublicKey::new(b"The quick brown fox jumps over the lazy dog");

        let subject = CryptDENull::from(&public_key, DEFAULT_CHAIN_ID);

        let expected_data = PlainData::new(&b"These are the times that try men's souls"[..]);
        let encrypted_data = subject.encode(&public_key, &expected_data).unwrap();
        let decrypted_data = subject.decode(&encrypted_data).unwrap();
        assert_eq!(expected_data, decrypted_data);
        let encrypted_data = subject
            .encode(&subject.public_key(), &expected_data)
            .unwrap();
        let decrypted_data = subject.decode(&encrypted_data).unwrap();
        assert_eq!(expected_data, decrypted_data);
    }

    #[test]
    fn dup_works() {
        let subject = main_cryptde();

        let result = subject.dup();

        assert_eq!(result.public_key(), subject.public_key());
        assert_eq!(result.private_key(), subject.private_key());
    }

    #[test]
    fn stringifies_public_key_properly() {
        let subject = main_cryptde();
        let public_key = PublicKey::new(&[1, 2, 3, 4]);

        let result = subject.public_key_to_descriptor_fragment(&public_key);

        assert_eq!(result, "AQIDBA".to_string());
    }

    #[test]
    fn destringifies_public_key_properly() {
        let subject = main_cryptde();
        let half_key = "AQIDBA";

        let result = subject.descriptor_fragment_to_first_contact_public_key(half_key);

        assert_eq!(result, Ok(PublicKey::new(&[1, 2, 3, 4])));
    }

    #[test]
    fn fails_to_destringify_public_key_properly() {
        let subject = main_cryptde();
        let half_key = "((]--$";

        let result = subject.descriptor_fragment_to_first_contact_public_key(half_key);

        assert_eq!(
            result,
            Err(String::from("Invalid Base64 value for public key: ((]--$"))
        );
    }

    const HASHABLE_DATA: &str = "Availing himself of the mild, summer-cool weather that now reigned \
        in these latitudes, and in preparation for the peculiarly active pursuits shortly to be \
        anticipated, Perth, the begrimed, blistered old blacksmith, had not removed his portable \
        forge to the hold again, after concluding his contributory work for Ahab's leg, but still \
        retained it on deck, fast lashed to ringbolts by the foremast; being now almost incessantly \
        invoked by the headsmen, and harpooneers, and bowsmen to do some little job for them; \
        altering, or repairing, or new shaping their various weapons and boat furniture. Often \
        he would be surrounded by an eager circle, all waiting to be served; holding boat-spades, \
        pike-heads, harpoons, and lances, and jealously watching his every sooty movement, as he \
        toiled. Nevertheless, this old man's was a patient hammer wielded by a patient arm. No \
        murmur, no impatience, no petulance did come from him. Silent, slow, and solemn; bowing \
        over still further his chronically broken back, he toiled away, as if toil were life \
        itself, and the heavy beating of his hammer the heavy beating of his heart. And so it \
        was.—Most miserable! A peculiar walk in this old man, a certain slight but painful \
        appearing yawing in his gait, had at an early period of the voyage excited the curiosity \
        of the mariners. And to the importunity of their persisted questionings he had finally \
        given in; and so it came to pass that every one now knew the shameful story of his wretched \
        fate. Belated, and not innocently, one bitter winter's midnight, on the road running \
        between two country towns, the blacksmith half-stupidly felt the deadly numbness stealing \
        over him, and sought refuge in a leaning, dilapidated barn. The issue was, the loss of the \
        extremities of both feet. Out of this revelation, part by part, at last came out the four \
        acts of the gladness, and the one long, and as yet uncatastrophied fifth act of the grief \
        of his life's drama. He was an old man, who, at the age of nearly sixty, had postponedly \
        encountered that thing in sorrow's technicals called ruin. He had been an artisan of famed \
        excellence, and with plenty to do; owned a house and garden; embraced a youthful, \
        daughter-like, loving wife, and three blithe, ruddy children; every Sunday went to a \
        cheerful-looking church, planted in a grove. But one night, under cover of darkness, and \
        further concealed in a most cunning disguisement, a desperate burglar slid into his happy \
        home, and robbed them all of everything. And darker yet to tell, the blacksmith himself \
        did ignorantly conduct this burglar into his family's heart. It was the Bottle Conjuror! \
        Upon the opening of that fatal cork, forth flew the fiend, and shrivelled up his home. \
        Now, for prudent, most wise, and economic reasons, the blacksmith's shop was in the \
        basement of his dwelling, but with a separate entrance to it; so that always had the \
        young and loving healthy wife listened with no unhappy nervousness, but with vigorous \
        pleasure, to the stout ringing of her young-armed old husband's hammer; whose \
        reverberations, muffled by passing through the floors and walls, came up to her, not \
        unsweetly, in her nursery; and so, to stout Labor's iron lullaby, the blacksmith's \
        infants were rocked to slumber. Oh, woe on woe! Oh, Death, why canst thou not sometimes \
        be timely? Hadst thou taken this old blacksmith to thyself ere his full ruin came upon \
        him, then had the young widow had a delicious grief, and her orphans a truly venerable, \
        legendary sire to dream of in their after years; and all of them a care-killing competency.";

    #[test]
    fn verifying_a_good_signature_works() {
        let data = PlainData::new(HASHABLE_DATA.as_bytes());
        let subject = main_cryptde();

        let signature = subject.sign(&data).unwrap();
        let result = subject.verify_signature(&data, &signature, &subject.public_key());

        assert_eq!(true, result);
    }

    #[test]
    fn verifying_a_bad_signature_fails() {
        let data = PlainData::new(HASHABLE_DATA.as_bytes());
        let subject = main_cryptde();
        let mut modified = Vec::from(HASHABLE_DATA.as_bytes());
        modified[0] = modified[0] + 1;
        let different_data = PlainData::from(modified);
        let signature = subject.sign(&data).unwrap();

        let result = subject.verify_signature(&different_data, &signature, &subject.public_key());

        assert_eq!(false, result);
    }

    #[test]
    fn hashing_produces_the_same_value_for_the_same_data() {
        let some_data = PlainData::new(HASHABLE_DATA.as_bytes());
        let more_data = some_data.clone();
        let subject = main_cryptde();

        let some_result = subject.hash(&some_data);
        let more_result = subject.hash(&more_data);

        assert_eq!(some_result, more_result);
    }

    #[test]
    fn hashing_produces_different_values_for_different_data() {
        let some_data = PlainData::new(HASHABLE_DATA.as_bytes());
        let mut modified = Vec::from(HASHABLE_DATA.as_bytes());
        modified[0] = modified[0] + 1;
        let different_data = PlainData::from(modified);
        let subject = main_cryptde();

        let some_result = subject.hash(&some_data);
        let different_result = subject.hash(&different_data);

        assert_ne!(some_result, different_result);
    }

    #[test]
    fn hashing_produces_the_same_length_for_long_and_short_data() {
        let long_data = PlainData::new(HASHABLE_DATA.as_bytes());
        let short_data = PlainData::new(&[1, 2, 3, 4]);
        let subject = main_cryptde();

        let long_result = subject.hash(&long_data);
        let short_result = subject.hash(&short_data);

        assert_eq!(long_result.len(), short_result.len());
    }

    #[test]
    fn hashing_produces_a_digest_with_the_smart_contract_address() {
        let subject = &main_cryptde();
        let merged = [
            subject.public_key().as_ref(),
            contract_address(DEFAULT_CHAIN_ID).as_ref(),
        ]
        .concat();
        let expected_digest = merged.keccak256();

        let actual_digest = subject.digest();

        assert_eq!(expected_digest, actual_digest);
    }

    #[test]
    fn creating_cryptde_produces_the_same_digest() {
        let subject_one = &CryptDENull::new(DEFAULT_CHAIN_ID);
        let subject_two = &CryptDENull::from(subject_one.public_key(), DEFAULT_CHAIN_ID);
        let subject_three = &mut CryptDENull::new(DEFAULT_CHAIN_ID);
        subject_three.set_key_pair(subject_two.public_key(), DEFAULT_CHAIN_ID);

        assert_eq!(subject_one.digest(), subject_two.digest());
        assert_eq!(subject_one.digest(), subject_three.digest());
    }
}
