use crate::accountant::scanners::pending_payable_scanner::utils::{
    FailedValidationError, ValidationFailureClock,
};
use serde::ser::SerializeStruct;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;
use web3::error::Error as Web3Error;
use websocket::url::quirks::hash;

// Prefixed with App to clearly distinguish app-specific errors from library errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppRpcError {
    Local(LocalError),
    Remote(RemoteError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocalError {
    Decoder(String),
    Internal,
    Io(String),
    Signing(String),
    Transport(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemoteError {
    InvalidResponse(String),
    Unreachable,
    Web3RpcError { code: i64, message: String },
}

#[derive(Debug, Hash, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppRpcErrorKind {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorStats {
    #[serde(rename = "firstSeen")]
    pub first_seen: SystemTime,
    pub attempts: u16,
}

impl ErrorStats {
    pub fn now(clock: &dyn ValidationFailureClock) -> Self {
        Self {
            first_seen: clock.now(),
            attempts: 1,
        }
    }

    pub fn increment(&mut self) {
        self.attempts += 1;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreviousAttempts {
    #[serde(flatten)]
    inner: HashMap<AppRpcErrorKind, ErrorStats>,
}

impl PreviousAttempts {
    pub fn new(error: AppRpcErrorKind, clock: &dyn ValidationFailureClock) -> Self {
        Self {
            inner: hashmap!(error => ErrorStats::now(clock)),
        }
    }

    pub fn add_attempt(
        mut self,
        error: AppRpcErrorKind,
        clock: &dyn ValidationFailureClock,
    ) -> Self {
        self.inner
            .entry(error)
            .and_modify(|stats| stats.increment())
            .or_insert_with(|| ErrorStats::now(clock));
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationStatus {
    Waiting,
    Reattempting(PreviousAttempts),
}

enum ErrorKinds {
    AppRcpError(AppRpcErrorKind),
    Uninterpretable(UninterpretabilityReason),
}

enum UninterpretabilityReason {
    FailedTxLeftPending,
}

impl From<FailedValidationError> for AppRpcErrorKind {
    fn from(err: FailedValidationError) -> Self {
        match err {
            FailedValidationError::Known(AppRpcError::Local(local)) => match local {
                LocalError::Decoder(_) => Self::Decoder,
                LocalError::Internal => Self::Internal,
                LocalError::Io(_) => Self::IO,
                LocalError::Signing(_) => Self::Signing,
                LocalError::Transport(_) => Self::Transport,
            },
            FailedValidationError::Known(AppRpcError::Remote(remote)) => match remote {
                RemoteError::InvalidResponse(_) => Self::InvalidResponse,
                RemoteError::Unreachable => Self::ServerUnreachable,
                RemoteError::Web3RpcError { code, .. } => Self::Web3RpcError(code),
            },
            FailedValidationError::TxResubmissionFailed => Self::Unknown,
        }
    }
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

#[cfg(test)]
mod tests {
    use crate::accountant::scanners::pending_payable_scanner::utils::{
        FailedValidationError, ValidationFailureClockReal,
    };
    use crate::blockchain::errors::{
        AppRpcError, AppRpcErrorKind, LocalError, PreviousAttempts, RemoteError,
    };
    use std::time::SystemTime;
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

    #[test]
    fn previous_attempts_and_validation_failure_clock_work_together_fine() {
        let validation_failure_clock = ValidationFailureClockReal::default();
        // new()
        let timestamp_a = SystemTime::now();
        let subject = PreviousAttempts::new(AppRpcErrorKind::Decoder, &validation_failure_clock);
        // add_attempt()
        let timestamp_b = SystemTime::now();
        let subject = subject.add_attempt(AppRpcErrorKind::Internal, &validation_failure_clock);
        let timestamp_c = SystemTime::now();
        let subject = subject.add_attempt(AppRpcErrorKind::IO, &validation_failure_clock);
        let timestamp_d = SystemTime::now();
        let subject = subject.add_attempt(AppRpcErrorKind::Decoder, &validation_failure_clock);
        let subject = subject.add_attempt(AppRpcErrorKind::IO, &validation_failure_clock);

        let decoder_error_stats = subject.inner.get(&AppRpcErrorKind::Decoder).unwrap();
        assert!(
            timestamp_a <= decoder_error_stats.first_seen
                && decoder_error_stats.first_seen <= timestamp_b,
            "Was expected from {:?} to {:?} but was {:?}",
            timestamp_a,
            timestamp_b,
            decoder_error_stats.first_seen
        );
        assert_eq!(decoder_error_stats.attempts, 2);
        let internal_error_stats = subject.inner.get(&AppRpcErrorKind::Internal).unwrap();
        assert!(
            timestamp_b <= internal_error_stats.first_seen
                && internal_error_stats.first_seen <= timestamp_c,
            "Was expected from {:?} to {:?} but was {:?}",
            timestamp_b,
            timestamp_c,
            internal_error_stats.first_seen
        );
        assert_eq!(internal_error_stats.attempts, 1);
        let io_error_stats = subject.inner.get(&AppRpcErrorKind::IO).unwrap();
        assert!(
            timestamp_c <= io_error_stats.first_seen && io_error_stats.first_seen <= timestamp_d,
            "Was expected from {:?} to {:?} but was {:?}",
            timestamp_c,
            timestamp_d,
            io_error_stats.first_seen
        );
        assert_eq!(io_error_stats.attempts, 2);
        let other_error_stats = subject.inner.get(&AppRpcErrorKind::Signing);
        assert_eq!(other_error_stats, None);
    }

    #[test]
    fn conversion_between_app_rpc_error_and_app_rpc_error_kind_works() {
        assert_eq!(
            AppRpcErrorKind::from(FailedValidationError::Known(AppRpcError::Local(
                LocalError::Decoder("Decoder error".to_string())
            ))),
            AppRpcErrorKind::Decoder
        );
        assert_eq!(
            AppRpcErrorKind::from(FailedValidationError::Known(AppRpcError::Local(
                LocalError::Internal
            ))),
            AppRpcErrorKind::Internal
        );
        assert_eq!(
            AppRpcErrorKind::from(FailedValidationError::Known(AppRpcError::Local(
                LocalError::Io("IO error".to_string())
            ))),
            AppRpcErrorKind::IO
        );
        assert_eq!(
            AppRpcErrorKind::from(FailedValidationError::Known(AppRpcError::Local(
                LocalError::Signing("Signing error".to_string())
            ))),
            AppRpcErrorKind::Signing
        );
        assert_eq!(
            AppRpcErrorKind::from(FailedValidationError::Known(AppRpcError::Local(
                LocalError::Transport("Transport error".to_string())
            ))),
            AppRpcErrorKind::Transport
        );
        assert_eq!(
            AppRpcErrorKind::from(FailedValidationError::Known(AppRpcError::Remote(
                RemoteError::InvalidResponse("Invalid response".to_string())
            ))),
            AppRpcErrorKind::InvalidResponse
        );
        assert_eq!(
            AppRpcErrorKind::from(FailedValidationError::Known(AppRpcError::Remote(
                RemoteError::Unreachable
            ))),
            AppRpcErrorKind::ServerUnreachable
        );
        assert_eq!(
            AppRpcErrorKind::from(FailedValidationError::Known(AppRpcError::Remote(
                RemoteError::Web3RpcError {
                    code: 55,
                    message: "Booga".to_string()
                }
            ))),
            AppRpcErrorKind::Web3RpcError(55)
        );
        assert_eq!(
            AppRpcErrorKind::from(FailedValidationError::TxResubmissionFailed),
            AppRpcErrorKind::Unknown
        );
    }
}
