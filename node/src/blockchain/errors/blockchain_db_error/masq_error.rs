// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::errors::blockchain_db_error::BlockchainDbError;
use serde_derive::{Deserialize, Serialize};
use std::hash::Hasher;
use variant_count::VariantCount;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, VariantCount)]
pub enum MASQError {
    PendingTooLongNotReplaced,
}

impl BlockchainDbError for MASQError {
    fn serialize_fn(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self) //TODO tested??
    }

    fn deserialize_fn(str: &str) -> Result<Box<dyn BlockchainDbError>, serde_json::Error>
    where
        Self: Sized,
    {
        let res: Result<MASQError, serde_json::Error> = serde_json::from_str(str);
        res.map(|kind| Box::new(kind) as Box<dyn BlockchainDbError>)
    }

    fn partial_eq(&self, other: &Box<dyn BlockchainDbError>) -> bool {
        other
            .as_any()
            .downcast_ref::<MASQError>()
            .map_or(false, |other| self == other)
    }

    fn costume_hash_fn(&self, hasher: &mut dyn Hasher) {
        match self {
            MASQError::PendingTooLongNotReplaced => hasher.write_u8(0),
        }
    }

    fn dup(&self) -> Box<dyn BlockchainDbError> {
        Box::new(self.clone())
    }

    as_any_ref_in_trait_impl!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::errors::blockchain_db_error::app_rpc_web3_error_kind::AppRpcWeb3ErrorKind;
    use crate::blockchain::errors::test_utils::test_clone_for_blockchain_db_error;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::Hash;

    #[test]
    fn clone_works_for_blockchain_db_error_wrapping_masq_error() {
        let subject: Box<dyn BlockchainDbError> = Box::new(MASQError::PendingTooLongNotReplaced);

        test_clone_for_blockchain_db_error::<MASQError>(subject);
    }

    #[test]
    fn hashing_for_masq_error_works() {
        let mut hasher = DefaultHasher::default();
        let mut hashes = vec![
            Box::new(MASQError::PendingTooLongNotReplaced) as Box<dyn BlockchainDbError>,
            // Add more types here as there are more types of MASQ app_rpc_web3_error_kind.
        ]
        .into_iter()
        .map(|blockchain_error| {
            blockchain_error.hash(&mut hasher);

            hasher.finish()
        })
        .collect::<Vec<u64>>();

        hashes.clone().iter().for_each(|picked_hash| {
            hashes.remove(0);
            hashes.iter().for_each(|other_hash| {
                assert_ne!(picked_hash, other_hash);
            });
        })
    }

    #[test]
    fn partial_eq_for_masq_error_works() {
        let subject: Box<dyn BlockchainDbError> = Box::new(MASQError::PendingTooLongNotReplaced);
        let other: Box<dyn BlockchainDbError> = Box::new(MASQError::PendingTooLongNotReplaced);

        assert_eq!(&subject, &other);
        // Expand this test as there are more variants of MASQError.
        assert_eq!(MASQError::VARIANT_COUNT, 1);
    }

    #[test]
    fn serialization_and_deserialization_for_blockchain_db_error_works() {
        vec![(
            Box::new(MASQError::PendingTooLongNotReplaced) as Box<dyn BlockchainDbError>,
            "\"PendingTooLongNotReplaced\"",
        )]
        .into_iter()
        .for_each(|(blockchain_error, expected_result)| {
            let json_result = serde_json::to_string(&blockchain_error).unwrap();
            assert_eq!(json_result, expected_result);
            let trait_object_result =
                serde_json::from_str::<Box<dyn BlockchainDbError>>(&json_result).unwrap();
            assert_eq!(&trait_object_result, &blockchain_error);
        })
    }
}
