// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use serde_derive::{Deserialize, Serialize};
use web3::error::Error as Web3Error;

// Prefixed with App to clearly distinguish app-specific errors from library errors.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum AppRpcError {
    Local(LocalError),
    Remote(RemoteError),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum LocalError {
    Decoder(String),
    Internal,
    IO(String),
    Signing(String),
    Transport(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum RemoteError {
    InvalidResponse(String),
    Unreachable,
    Web3RpcError { code: i64, message: String },
}

// EVM based errors
impl From<Web3Error> for AppRpcError {
    fn from(error: Web3Error) -> Self {
        match error {
            // Local Errors
            Web3Error::Decoder(error) => AppRpcError::Local(LocalError::Decoder(error)),
            Web3Error::Internal => AppRpcError::Local(LocalError::Internal),
            Web3Error::Io(error) => AppRpcError::Local(LocalError::IO(error.to_string())),
            Web3Error::Signing(error) => {
                // This variant cannot be tested due to import limitations.
                AppRpcError::Local(LocalError::Signing(error.to_string()))
            }
            Web3Error::Transport(error) => AppRpcError::Local(LocalError::Transport(error)),

            // Api Errors
            Web3Error::InvalidResponse(response) => {
                AppRpcError::Remote(RemoteError::InvalidResponse(response))
            }
            Web3Error::Rpc(web3_rpc_error) => AppRpcError::Remote(RemoteError::Web3RpcError {
                code: web3_rpc_error.code.code(),
                message: web3_rpc_error.message,
            }),
            Web3Error::Unreachable => AppRpcError::Remote(RemoteError::Unreachable),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum AppRpcErrorKind {
    Local(LocalErrorKind),
    Remote(RemoteErrorKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LocalErrorKind {
    Decoder,
    Internal,
    Io,
    Signing,
    Transport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RemoteErrorKind {
    InvalidResponse,
    Unreachable,
    Web3RpcError(i64), // Keep only the stable error code
}

impl From<&AppRpcError> for AppRpcErrorKind {
    fn from(err: &AppRpcError) -> Self {
        match err {
            AppRpcError::Local(local) => match local {
                LocalError::Decoder(_) => Self::Local(LocalErrorKind::Decoder),
                LocalError::Internal => Self::Local(LocalErrorKind::Internal),
                LocalError::IO(_) => Self::Local(LocalErrorKind::IO),
                LocalError::Signing(_) => Self::Local(LocalErrorKind::Signing),
                LocalError::Transport(_) => Self::Local(LocalErrorKind::Transport),
            },
            AppRpcError::Remote(remote) => match remote {
                RemoteError::InvalidResponse(_) => Self::Remote(RemoteErrorKind::InvalidResponse),
                RemoteError::Unreachable => Self::Remote(RemoteErrorKind::Unreachable),
                RemoteError::Web3RpcError { code, .. } => {
                    Self::Remote(RemoteErrorKind::Web3RpcError(*code))
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::blockchain::errors::rpc_errors::{
        AppRpcError, AppRpcErrorKind, LocalError, LocalErrorKind, RemoteError, RemoteErrorKind,
    };
    use web3::error::Error as Web3Error;

    #[test]
    fn web3_error_to_failure_reason_conversion_works() {
        // Local Errors
        assert_eq!(
            AppRpcError::from(Web3Error::Decoder("Decoder error".to_string())),
            AppRpcError::Local(LocalError::Decoder("Decoder error".to_string()))
        );
        assert_eq!(
            AppRpcError::from(Web3Error::Internal),
            AppRpcError::Local(LocalError::Internal)
        );
        assert_eq!(
            AppRpcError::from(Web3Error::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "IO error"
            ))),
            AppRpcError::Local(LocalError::IO("IO error".to_string()))
        );
        assert_eq!(
            AppRpcError::from(Web3Error::Transport("Transport error".to_string())),
            AppRpcError::Local(LocalError::Transport("Transport error".to_string()))
        );

        // Api Errors
        assert_eq!(
            AppRpcError::from(Web3Error::InvalidResponse("Invalid response".to_string())),
            AppRpcError::Remote(RemoteError::InvalidResponse("Invalid response".to_string()))
        );
        assert_eq!(
            AppRpcError::from(Web3Error::Rpc(jsonrpc_core::types::error::Error {
                code: jsonrpc_core::types::error::ErrorCode::ServerError(42),
                message: "RPC error".to_string(),
                data: None,
            })),
            AppRpcError::Remote(RemoteError::Web3RpcError {
                code: 42,
                message: "RPC error".to_string(),
            })
        );
        assert_eq!(
            AppRpcError::from(Web3Error::Unreachable),
            AppRpcError::Remote(RemoteError::Unreachable)
        );
    }

    #[test]
    fn conversion_between_app_rpc_error_and_app_rpc_error_kind_works() {
        assert_eq!(
            AppRpcErrorKind::from(&AppRpcError::Local(LocalError::Decoder(
                "Decoder error".to_string()
            ))),
            AppRpcErrorKind::Local(LocalErrorKind::Decoder)
        );
        assert_eq!(
            AppRpcErrorKind::from(&AppRpcError::Local(LocalError::Internal)),
            AppRpcErrorKind::Local(LocalErrorKind::Internal)
        );
        assert_eq!(
            AppRpcErrorKind::from(&AppRpcError::Local(LocalError::IO("IO error".to_string()))),
            AppRpcErrorKind::Local(LocalErrorKind::IO)
        );
        assert_eq!(
            AppRpcErrorKind::from(&AppRpcError::Local(LocalError::Signing(
                "Signing error".to_string()
            ))),
            AppRpcErrorKind::Local(LocalErrorKind::Signing)
        );
        assert_eq!(
            AppRpcErrorKind::from(&AppRpcError::Local(LocalError::Transport(
                "Transport error".to_string()
            ))),
            AppRpcErrorKind::Local(LocalErrorKind::Transport)
        );
        assert_eq!(
            AppRpcErrorKind::from(&AppRpcError::Remote(RemoteError::InvalidResponse(
                "Invalid response".to_string()
            ))),
            AppRpcErrorKind::Remote(RemoteErrorKind::InvalidResponse)
        );
        assert_eq!(
            AppRpcErrorKind::from(&AppRpcError::Remote(RemoteError::Unreachable)),
            AppRpcErrorKind::Remote(RemoteErrorKind::Unreachable)
        );
        assert_eq!(
            AppRpcErrorKind::from(&AppRpcError::Remote(RemoteError::Web3RpcError {
                code: 55,
                message: "Booga".to_string()
            })),
            AppRpcErrorKind::Remote(RemoteErrorKind::Web3RpcError(55))
        );
    }

    #[test]
    fn app_rpc_error_kind_serialization_deserialization() {
        let errors = vec![
            AppRpcErrorKind::Local(LocalErrorKind::Decoder),
            AppRpcErrorKind::Local(LocalErrorKind::Internal),
            AppRpcErrorKind::Local(LocalErrorKind::IO),
            AppRpcErrorKind::Local(LocalErrorKind::Signing),
            AppRpcErrorKind::Local(LocalErrorKind::Transport),
            AppRpcErrorKind::Remote(RemoteErrorKind::InvalidResponse),
            AppRpcErrorKind::Remote(RemoteErrorKind::Unreachable),
            AppRpcErrorKind::Remote(RemoteErrorKind::Web3RpcError(42)),
        ];

        errors.into_iter().for_each(|error| {
            let serialized = serde_json::to_string(&error).unwrap();
            let deserialized: AppRpcErrorKind = serde_json::from_str(&serialized).unwrap();
            assert_eq!(
                error, deserialized,
                "Failed serde attempt for {:?} that should look like {:?}",
                deserialized, error
            );
        });
    }
}
