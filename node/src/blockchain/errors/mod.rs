// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::errors::internal_errors::{InternalError, InternalErrorKind};
use crate::blockchain::errors::rpc_errors::{AppRpcError, AppRpcErrorKind};
use serde_derive::{Deserialize, Serialize};

pub mod internal_errors;
pub mod rpc_errors;
pub mod validation_status;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockchainError {
    AppRpc(AppRpcError),
    Internal(InternalError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BlockchainErrorKind {
    AppRpc(AppRpcErrorKind),
    Internal(InternalErrorKind),
}

#[cfg(test)]
mod tests {
    use crate::blockchain::errors::internal_errors::InternalErrorKind;
    use crate::blockchain::errors::rpc_errors::{AppRpcErrorKind, LocalErrorKind};
    use crate::blockchain::errors::BlockchainErrorKind;

    #[test]
    fn blockchain_error_serialization_deserialization() {
        vec![
            (
                BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Decoder)),
                r#"{"AppRpc":{"Local":"Decoder"}}"#,
            ),
            (
                BlockchainErrorKind::Internal(InternalErrorKind::PendingTooLongNotReplaced),
                r#"{"Internal":"PendingTooLongNotReplaced"}"#,
            ),
        ]
        .into_iter()
        .for_each(|(err, expected_json)| {
            let json = serde_json::to_string(&err).unwrap();
            assert_eq!(json, expected_json);
            let deserialized_err = serde_json::from_str::<BlockchainErrorKind>(&json).unwrap();
            assert_eq!(deserialized_err, err);
        })
    }
}
