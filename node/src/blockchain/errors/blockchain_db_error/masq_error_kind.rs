// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::errors::blockchain_db_error::{BlockchainDbError, CustomHash, CustomSeDe};
use crate::blockchain::errors::blockchain_loggable_error::masq_error::MASQError;
use crate::blockchain::errors::common_methods::CommonMethods;
use serde_derive::{Deserialize, Serialize};
use serde_json::Value;
use std::hash::Hasher;
use variant_count::VariantCount;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, VariantCount)]
pub enum MASQErrorKind {
    PendingTooLongNotReplaced,
}

impl BlockchainDbError for MASQErrorKind {
    fn as_common_methods(&self) -> &dyn CommonMethods<Box<dyn BlockchainDbError>> {
        self
    }
}

impl CustomSeDe for MASQErrorKind {
    fn costume_serialize(&self) -> Result<Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    fn costume_deserialize(str: &str) -> Result<Box<dyn BlockchainDbError>, serde_json::Error>
    where
        Self: Sized,
    {
        let res: Result<MASQErrorKind, serde_json::Error> = serde_json::from_str(str);
        res.map(|kind| Box::new(kind) as Box<dyn BlockchainDbError>)
    }
}

impl CommonMethods<Box<dyn BlockchainDbError>> for MASQErrorKind {
    fn partial_eq(&self, other: &Box<dyn BlockchainDbError>) -> bool {
        other
            .as_common_methods()
            .as_any()
            .downcast_ref::<MASQErrorKind>()
            .map_or(false, |other| self == other)
    }

    fn dup(&self) -> Box<dyn BlockchainDbError> {
        Box::new(self.clone())
    }

    as_any_ref_in_trait_impl!();
}

impl CustomHash for MASQErrorKind {
    fn costume_hash(&self, hasher: &mut dyn Hasher) {
        match self {
            MASQErrorKind::PendingTooLongNotReplaced => hasher.write_u8(0),
        }
    }
}

impl From<&MASQError> for MASQErrorKind {
    fn from(masq_error: &MASQError) -> Self {
        match masq_error {
            MASQError::PendingTooLongNotReplaced => MASQErrorKind::PendingTooLongNotReplaced,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::errors::blockchain_loggable_error::masq_error::MASQError;
    use crate::blockchain::errors::blockchain_loggable_error::BlockchainLoggableError;
    use crate::blockchain::errors::test_utils::test_clone_impl_for_blockchain_db_error;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::Hash;

    #[test]
    fn conversion_between_masq_error_and_masq_error_kind_works() {
        assert_eq!(
            MASQErrorKind::from(&MASQError::PendingTooLongNotReplaced),
            MASQErrorKind::PendingTooLongNotReplaced
        );
    }

    #[test]
    fn clone_works_for_blockchain_db_error_wrapping_masq_error_kind() {
        let subject: Box<dyn BlockchainDbError> =
            Box::new(MASQErrorKind::PendingTooLongNotReplaced);

        test_clone_impl_for_blockchain_db_error::<MASQErrorKind>(subject);
    }

    #[test]
    fn hashing_for_masq_error_kind_works() {
        let mut hasher = DefaultHasher::default();
        let mut hashes = vec![
            Box::new(MASQErrorKind::PendingTooLongNotReplaced) as Box<dyn BlockchainDbError>,
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
        });
        // Expand this test as there are more variants of MASQErrorKind.
        assert_eq!(MASQErrorKind::VARIANT_COUNT, 1);
    }

    #[test]
    fn partial_eq_for_masq_error_kind_works() {
        let subject: Box<dyn BlockchainDbError> =
            Box::new(MASQErrorKind::PendingTooLongNotReplaced);
        let other: Box<dyn BlockchainDbError> = Box::new(MASQErrorKind::PendingTooLongNotReplaced);

        assert_eq!(&subject, &other);
        // Expand this test as there are more variants of MASQErrorKind.
        assert_eq!(MASQErrorKind::VARIANT_COUNT, 1);
    }

    #[test]
    fn serialization_and_deserialization_for_blockchain_db_error_works() {
        vec![(
            Box::new(MASQErrorKind::PendingTooLongNotReplaced) as Box<dyn BlockchainDbError>,
            "\"PendingTooLongNotReplaced\"",
        )]
        .into_iter()
        .for_each(|(blockchain_error, expected_result)| {
            let json_result = serde_json::to_string(&blockchain_error).unwrap();
            assert_eq!(json_result, expected_result);
            let trait_object_result =
                serde_json::from_str::<Box<dyn BlockchainDbError>>(&json_result).unwrap();
            assert_eq!(&trait_object_result, &blockchain_error);
        });
        // Expand this test as there are more variants of MASQErrorKind.
        assert_eq!(MASQErrorKind::VARIANT_COUNT, 1);
    }

    #[test]
    fn blockchain_loggable_error_can_be_converted_to_blockchain_db_error_for_masq_errors() {
        let error: Box<dyn BlockchainLoggableError> =
            Box::new(MASQError::PendingTooLongNotReplaced);

        let result = <Box<dyn BlockchainDbError>>::from(error);

        assert_eq!(
            &result,
            &(Box::new(MASQErrorKind::PendingTooLongNotReplaced) as Box<dyn BlockchainDbError>)
        );
        // Expand this test as there are more variants of MASQErrorKind.
        assert_eq!(MASQErrorKind::VARIANT_COUNT, 1);
    }
}
