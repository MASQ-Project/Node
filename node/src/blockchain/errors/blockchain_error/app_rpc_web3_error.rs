// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use serde_derive::{Deserialize, Serialize};
use web3::error::Error as Web3Error;

// Prefixed with App to clearly distinguish app-specific app_rpc_web3_error_kind from library app_rpc_web3_error_kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppRpcWeb3Error {
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
}
