// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use serde_derive::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Clone, Eq)]
pub enum InternalError {
    PendingTooLongNotReplaced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InternalErrorKind {
    PendingTooLongNotReplaced,
}

impl From<&InternalError> for InternalErrorKind {
    fn from(error: &InternalError) -> Self {
        match error {
            InternalError::PendingTooLongNotReplaced => {
                InternalErrorKind::PendingTooLongNotReplaced
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversion_between_internal_error_and_internal_error_kind_works() {
        assert_eq!(
            InternalErrorKind::from(&InternalError::PendingTooLongNotReplaced),
            InternalErrorKind::PendingTooLongNotReplaced
        );
    }

    #[test]
    fn app_rpc_error_kind_serialization_deserialization() {
        let errors = vec![InternalErrorKind::PendingTooLongNotReplaced];

        errors.into_iter().for_each(|error| {
            let serialized = serde_json::to_string(&error).unwrap();
            let deserialized: InternalErrorKind = serde_json::from_str(&serialized).unwrap();
            assert_eq!(
                error, deserialized,
                "Failed serde attempt for {:?} that should look like {:?}",
                deserialized, error
            );
        });
    }
}
