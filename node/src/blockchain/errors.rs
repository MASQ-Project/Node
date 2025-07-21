use serde_derive::{Deserialize, Serialize};
use web3::error::Error as Web3Error;

// Prefixed with App to clearly distinguish app-specific errors from library errors.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AppRpcError {
    Local(LocalError),
    Remote(RemoteError),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LocalError {
    Decoder(String),
    Internal,
    Io(String),
    Signing(String),
    Transport(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
            Web3Error::Io(error) => AppRpcError::Local(LocalError::Io(error.to_string())),
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

mod tests {
    use crate::blockchain::errors::{AppRpcError, LocalError, RemoteError};
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
            AppRpcError::Local(LocalError::Io("IO error".to_string()))
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
    fn app_rpc_error_serialization_deserialization() {
        let errors = vec![
            // Local Errors
            AppRpcError::Local(LocalError::Decoder("Decoder error".to_string())),
            AppRpcError::Local(LocalError::Internal),
            AppRpcError::Local(LocalError::Io("IO error".to_string())),
            AppRpcError::Local(LocalError::Signing("Signing error".to_string())),
            AppRpcError::Local(LocalError::Transport("Transport error".to_string())),
            // Remote Errors
            AppRpcError::Remote(RemoteError::InvalidResponse("Invalid response".to_string())),
            AppRpcError::Remote(RemoteError::Unreachable),
            AppRpcError::Remote(RemoteError::Web3RpcError {
                code: 42,
                message: "RPC error".to_string(),
            }),
        ];

        errors.into_iter().for_each(|error| {
            let serialized = serde_json::to_string(&error).unwrap();
            let deserialized: AppRpcError = serde_json::from_str(&serialized).unwrap();
            assert_eq!(error, deserialized, "Error: {:?}", error);
        });
    }
}
