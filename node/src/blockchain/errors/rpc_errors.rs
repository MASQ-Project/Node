// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use serde_derive::{Deserialize, Serialize};
use web3::error::Error as Web3Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcError {
    Local(LocalError),
    Remote(RemoteError),
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

// EVM based errors
impl From<Web3Error> for RpcError {
    fn from(error: Web3Error) -> Self {
        match error {
            // Local Errors
            Web3Error::Decoder(error) => RpcError::Local(LocalError::Decoder(error)),
            Web3Error::Internal => RpcError::Local(LocalError::Internal),
            Web3Error::Io(error) => RpcError::Local(LocalError::Io(error.to_string())),
            Web3Error::Signing(error) => {
                // This variant cannot be tested due to import limitations.
                RpcError::Local(LocalError::Signing(error.to_string()))
            }
            Web3Error::Transport(error) => RpcError::Local(LocalError::Transport(error)),

            // Api Errors
            Web3Error::InvalidResponse(response) => {
                RpcError::Remote(RemoteError::InvalidResponse(response))
            }
            Web3Error::Rpc(web3_rpc_error) => RpcError::Remote(RemoteError::Web3RpcError {
                code: web3_rpc_error.code.code(),
                message: web3_rpc_error.message,
            }),
            Web3Error::Unreachable => RpcError::Remote(RemoteError::Unreachable),
        }
    }
}

#[derive(Debug, Hash, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RpcErrorKind {
    // Local
    Decoder,
    Internal,
    IO,
    Signing,
    Transport,

    // Remote
    InvalidResponse,
    ServerUnreachable,
    Web3RpcError(i64), // Keep only the stable error code
}

impl From<&RpcError> for RpcErrorKind {
    fn from(err: &RpcError) -> Self {
        match err {
            RpcError::Local(local) => match local {
                LocalError::Decoder(_) => Self::Decoder,
                LocalError::Internal => Self::Internal,
                LocalError::Io(_) => Self::IO,
                LocalError::Signing(_) => Self::Signing,
                LocalError::Transport(_) => Self::Transport,
            },
            RpcError::Remote(remote) => match remote {
                RemoteError::InvalidResponse(_) => Self::InvalidResponse,
                RemoteError::Unreachable => Self::ServerUnreachable,
                RemoteError::Web3RpcError { code, .. } => Self::Web3RpcError(*code),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::blockchain::errors::rpc_errors::{LocalError, RemoteError, RpcError, RpcErrorKind};
    use web3::error::Error as Web3Error;

    #[test]
    fn web3_error_to_failure_reason_conversion_works() {
        // Local Errors
        assert_eq!(
            RpcError::from(Web3Error::Decoder("Decoder error".to_string())),
            RpcError::Local(LocalError::Decoder("Decoder error".to_string()))
        );
        assert_eq!(
            RpcError::from(Web3Error::Internal),
            RpcError::Local(LocalError::Internal)
        );
        assert_eq!(
            RpcError::from(Web3Error::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "IO error"
            ))),
            RpcError::Local(LocalError::Io("IO error".to_string()))
        );
        assert_eq!(
            RpcError::from(Web3Error::Transport("Transport error".to_string())),
            RpcError::Local(LocalError::Transport("Transport error".to_string()))
        );

        // Api Errors
        assert_eq!(
            RpcError::from(Web3Error::InvalidResponse("Invalid response".to_string())),
            RpcError::Remote(RemoteError::InvalidResponse("Invalid response".to_string()))
        );
        assert_eq!(
            RpcError::from(Web3Error::Rpc(jsonrpc_core::types::error::Error {
                code: jsonrpc_core::types::error::ErrorCode::ServerError(42),
                message: "RPC error".to_string(),
                data: None,
            })),
            RpcError::Remote(RemoteError::Web3RpcError {
                code: 42,
                message: "RPC error".to_string(),
            })
        );
        assert_eq!(
            RpcError::from(Web3Error::Unreachable),
            RpcError::Remote(RemoteError::Unreachable)
        );
    }

    #[test]
    fn conversion_between_app_rpc_error_and_app_rpc_error_kind_works() {
        assert_eq!(
            RpcErrorKind::from(&RpcError::Local(LocalError::Decoder(
                "Decoder error".to_string()
            ))),
            RpcErrorKind::Decoder
        );
        assert_eq!(
            RpcErrorKind::from(&RpcError::Local(LocalError::Internal)),
            RpcErrorKind::Internal
        );
        assert_eq!(
            RpcErrorKind::from(&RpcError::Local(LocalError::Io("IO error".to_string()))),
            RpcErrorKind::IO
        );
        assert_eq!(
            RpcErrorKind::from(&RpcError::Local(LocalError::Signing(
                "Signing error".to_string()
            ))),
            RpcErrorKind::Signing
        );
        assert_eq!(
            RpcErrorKind::from(&RpcError::Local(LocalError::Transport(
                "Transport error".to_string()
            ))),
            RpcErrorKind::Transport
        );
        assert_eq!(
            RpcErrorKind::from(&RpcError::Remote(RemoteError::InvalidResponse(
                "Invalid response".to_string()
            ))),
            RpcErrorKind::InvalidResponse
        );
        assert_eq!(
            RpcErrorKind::from(&RpcError::Remote(RemoteError::Unreachable)),
            RpcErrorKind::ServerUnreachable
        );
        assert_eq!(
            RpcErrorKind::from(&RpcError::Remote(RemoteError::Web3RpcError {
                code: 55,
                message: "Booga".to_string()
            })),
            RpcErrorKind::Web3RpcError(55)
        );
    }

    #[test]
    fn app_rpc_error_kind_serialization_deserialization() {
        let errors = vec![
            // Local Errors
            RpcErrorKind::Decoder,
            RpcErrorKind::Internal,
            RpcErrorKind::IO,
            RpcErrorKind::Signing,
            RpcErrorKind::Transport,
            // Remote Errors
            RpcErrorKind::InvalidResponse,
            RpcErrorKind::ServerUnreachable,
            RpcErrorKind::Web3RpcError(42),
        ];

        errors.into_iter().for_each(|error| {
            let serialized = serde_json::to_string(&error).unwrap();
            let deserialized: RpcErrorKind = serde_json::from_str(&serialized).unwrap();
            assert_eq!(
                error, deserialized,
                "Failed serde attempt for {:?} that should look \
            like {:?}",
                deserialized, error
            );
        });
    }
}
