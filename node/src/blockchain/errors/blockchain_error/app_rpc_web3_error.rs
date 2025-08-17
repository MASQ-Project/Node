// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::errors::blockchain_db_error::BlockchainDbError;
use crate::blockchain::errors::blockchain_error::BlockchainError;
use crate::blockchain::errors::custom_common_methods::CustomCommonMethods;
use std::fmt::{Display, Formatter};
use web3::error::Error as Web3Error;

// Prefixed with App to clearly distinguish app-specific app_rpc_web3_error_kind from library app_rpc_web3_error_kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppRpcWeb3Error {
    Local(LocalError),
    Remote(RemoteError),
}

impl BlockchainError for AppRpcWeb3Error {
    fn as_common_methods(&self) -> &dyn CustomCommonMethods<Box<dyn BlockchainError>> {
        self
    }

    fn downgrade(&self) -> Box<dyn BlockchainDbError> {
        todo!()
    }
}

impl CustomCommonMethods<Box<dyn BlockchainError>> for AppRpcWeb3Error {
    fn partial_eq(&self, other: &Box<dyn BlockchainError>) -> bool {
        todo!()
    }

    fn dup(&self) -> Box<dyn BlockchainError> {
        Box::new(self.clone())
    }

    as_any_ref_in_trait_impl!();
}

impl Display for AppRpcWeb3Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalError {
    Decoder(String),
    Internal,
    Io(String),
    Signing(String),
    Transport(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteError {
    InvalidResponse(String),
    Unreachable,
    Web3RpcError { code: i64, message: String },
}

// EVM based app_rpc_web3_error_kind
impl From<Web3Error> for AppRpcWeb3Error {
    fn from(error: Web3Error) -> Self {
        match error {
            // Local Errors
            Web3Error::Decoder(error) => AppRpcWeb3Error::Local(LocalError::Decoder(error)),
            Web3Error::Internal => AppRpcWeb3Error::Local(LocalError::Internal),
            Web3Error::Io(error) => AppRpcWeb3Error::Local(LocalError::Io(error.to_string())),
            Web3Error::Signing(error) => {
                // This variant cannot be tested due to import limitations.
                AppRpcWeb3Error::Local(LocalError::Signing(error.to_string()))
            }
            Web3Error::Transport(error) => AppRpcWeb3Error::Local(LocalError::Transport(error)),

            // Api Errors
            Web3Error::InvalidResponse(response) => {
                AppRpcWeb3Error::Remote(RemoteError::InvalidResponse(response))
            }
            Web3Error::Rpc(web3_rpc_error) => AppRpcWeb3Error::Remote(RemoteError::Web3RpcError {
                code: web3_rpc_error.code.code(),
                message: web3_rpc_error.message,
            }),
            Web3Error::Unreachable => AppRpcWeb3Error::Remote(RemoteError::Unreachable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::errors::test_utils::test_clone_impl_for_blockchain_error;
    use std::vec;

    #[test]
    fn web3_error_to_failure_reason_conversion_works() {
        // Local Errors
        assert_eq!(
            AppRpcWeb3Error::from(Web3Error::Decoder("Decoder error".to_string())),
            AppRpcWeb3Error::Local(LocalError::Decoder("Decoder error".to_string()))
        );
        assert_eq!(
            AppRpcWeb3Error::from(Web3Error::Internal),
            AppRpcWeb3Error::Local(LocalError::Internal)
        );
        assert_eq!(
            AppRpcWeb3Error::from(Web3Error::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "IO error"
            ))),
            AppRpcWeb3Error::Local(LocalError::Io("IO error".to_string()))
        );
        assert_eq!(
            AppRpcWeb3Error::from(Web3Error::Transport("Transport error".to_string())),
            AppRpcWeb3Error::Local(LocalError::Transport("Transport error".to_string()))
        );

        // Api Errors
        assert_eq!(
            AppRpcWeb3Error::from(Web3Error::InvalidResponse("Invalid response".to_string())),
            AppRpcWeb3Error::Remote(RemoteError::InvalidResponse("Invalid response".to_string()))
        );
        assert_eq!(
            AppRpcWeb3Error::from(Web3Error::Rpc(jsonrpc_core::types::error::Error {
                code: jsonrpc_core::types::error::ErrorCode::ServerError(42),
                message: "RPC error".to_string(),
                data: None,
            })),
            AppRpcWeb3Error::Remote(RemoteError::Web3RpcError {
                code: 42,
                message: "RPC error".to_string(),
            })
        );
        assert_eq!(
            AppRpcWeb3Error::from(Web3Error::Unreachable),
            AppRpcWeb3Error::Remote(RemoteError::Unreachable)
        );
    }

    #[test]
    fn clone_works_for_blockchain_error_wrapping_app_rpc_web3_error() {
        let subject: Box<dyn BlockchainError> =
            Box::new(AppRpcWeb3Error::Local(LocalError::Internal));

        test_clone_impl_for_blockchain_error::<AppRpcWeb3Error>(subject);
    }

    #[test]
    fn display_for_blockchain_error_object_works() {
        vec![
            AppRpcWeb3Error::Local(LocalError::Decoder("Serious decoder error".to_string())),
            AppRpcWeb3Error::Remote(RemoteError::InvalidResponse(
                "The most invalid response of all invalid responses".to_string(),
            )),
            AppRpcWeb3Error::Local(LocalError::Internal),
            AppRpcWeb3Error::Remote(RemoteError::Unreachable),
        ]
        .into_iter()
        .for_each(|error| {
            let wrapped_as_trait_object: Box<dyn BlockchainError> = Box::new(error.clone());
            assert_eq!(wrapped_as_trait_object.to_string(), format!("{:?}", error));
        })
    }
}
