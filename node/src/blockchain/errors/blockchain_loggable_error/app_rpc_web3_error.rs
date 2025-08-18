// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::errors::blockchain_db_error::app_rpc_web3_error_kind::AppRpcWeb3ErrorKind;
use crate::blockchain::errors::blockchain_db_error::BlockchainDbError;
use crate::blockchain::errors::blockchain_loggable_error::BlockchainLoggableError;
use crate::blockchain::errors::common_methods::CommonMethods;
use std::fmt::{Display, Formatter};
use web3::error::Error as Web3Error;

// Prefixed with App to clearly distinguish app-specific app_rpc_web3_error_kind from library app_rpc_web3_error_kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppRpcWeb3Error {
    Local(LocalError),
    Remote(RemoteError),
}

impl BlockchainLoggableError for AppRpcWeb3Error {
    fn as_common_methods(&self) -> &dyn CommonMethods<Box<dyn BlockchainLoggableError>> {
        self
    }

    fn downgrade(&self) -> Box<dyn BlockchainDbError> {
        Box::new(AppRpcWeb3ErrorKind::from(self))
    }
}

impl CommonMethods<Box<dyn BlockchainLoggableError>> for AppRpcWeb3Error {
    fn partial_eq(&self, other: &Box<dyn BlockchainLoggableError>) -> bool {
        other
            .as_common_methods()
            .as_any()
            .downcast_ref::<AppRpcWeb3Error>()
            .map_or(false, |other| self == other)
    }

    fn dup(&self) -> Box<dyn BlockchainLoggableError> {
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
    use crate::blockchain::errors::blockchain_db_error::app_rpc_web3_error_kind::AppRpcWeb3ErrorKind;
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
        let subject: Box<dyn BlockchainLoggableError> =
            Box::new(AppRpcWeb3Error::Local(LocalError::Internal));

        test_clone_impl_for_blockchain_error::<AppRpcWeb3Error>(subject);
    }

    #[test]
    fn partial_eq_for_app_rpc_error_works() {
        let subject: Box<dyn BlockchainLoggableError> =
            Box::new(AppRpcWeb3Error::Remote(RemoteError::Web3RpcError {
                code: 222,
                message: "Some message".to_string(),
            }));
        let other_1: Box<dyn BlockchainLoggableError> =
            Box::new(AppRpcWeb3Error::Remote(RemoteError::Unreachable));
        let other_2: Box<dyn BlockchainLoggableError> =
            Box::new(AppRpcWeb3Error::Remote(RemoteError::Web3RpcError {
                code: 123,
                message: "Some message".to_string(),
            }));
        let other_3: Box<dyn BlockchainLoggableError> =
            Box::new(AppRpcWeb3Error::Remote(RemoteError::Web3RpcError {
                code: 222,
                message: "Some other message".to_string(),
            }));
        let other_4: Box<dyn BlockchainLoggableError> =
            Box::new(AppRpcWeb3Error::Local(LocalError::Internal));
        let other_5: Box<dyn BlockchainLoggableError> =
            Box::new(AppRpcWeb3Error::Remote(RemoteError::Web3RpcError {
                code: 222,
                message: "Some message".to_string(),
            }));

        assert_ne!(&subject, &other_1);
        assert_ne!(&subject, &other_2);
        assert_ne!(&subject, &other_3);
        assert_ne!(&subject, &other_4);
        assert_eq!(&subject, &other_5);
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
            let wrapped_as_trait_object: Box<dyn BlockchainLoggableError> = Box::new(error.clone());
            assert_eq!(wrapped_as_trait_object.to_string(), format!("{:?}", error));
        })
    }

    #[test]
    fn blockchain_loggable_error_can_be_converted_to_blockchain_db_error_for_app_rpc_web3_errors() {
        let error_1: Box<dyn BlockchainLoggableError> = Box::new(AppRpcWeb3Error::Local(
            LocalError::Decoder("This is a decoder error".to_string()),
        ));
        let error_2: Box<dyn BlockchainLoggableError> =
            Box::new(AppRpcWeb3Error::Remote(RemoteError::Unreachable));

        let result_1 = <Box<dyn BlockchainDbError>>::from(error_1);
        let result_2 = <Box<dyn BlockchainDbError>>::from(error_2);

        assert_eq!(
            &result_1,
            &(Box::new(AppRpcWeb3ErrorKind::Decoder) as Box<dyn BlockchainDbError>)
        );
        assert_eq!(
            &result_2,
            &(Box::new(AppRpcWeb3ErrorKind::ServerUnreachable) as Box<dyn BlockchainDbError>)
        );
    }
}
