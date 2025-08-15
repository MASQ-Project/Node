use std::borrow::Borrow;
// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use serde::{Deserialize as DeserializeTrait, Serialize as SerializeTrait};
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::hash::{Hash, Hasher};
use std::time::SystemTime;
use web3::error::Error as Web3Error;

impl SerializeTrait for Box<dyn BlockchainDbError> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        todo!()
    }
}

impl<'de> DeserializeTrait<'de> for Box<dyn BlockchainDbError> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        todo!()
    }
}

impl Clone for Box<dyn BlockchainDbError> {
    fn clone(&self) -> Self {
        self.dup()
    }
}

impl PartialEq for Box<dyn BlockchainDbError> {
    fn eq(&self, other: &Self) -> bool {
        todo!()
    }
}

impl Hash for Box<dyn BlockchainDbError> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.costume_hash_fn(state)
    }
}

impl Eq for Box<dyn BlockchainDbError> {}

pub trait BlockchainDbError: Debug {
    fn serialize(&self) -> String;
    fn deserialize(str: &str) -> Box<dyn BlockchainDbError>
    where
        Self: Sized;
    fn partial_eq(&self, other: &dyn BlockchainDbError) -> bool;
    fn costume_hash_fn(&self, hasher: &mut dyn Hasher);
    fn dup(&self) -> Box<dyn BlockchainDbError>;
    as_any_ref_in_trait!();
}

impl BlockchainDbError for AppRpcErrorKind {
    fn serialize(&self) -> String {
        todo!()
    }

    fn deserialize(str: &str) -> Box<dyn BlockchainDbError>
    where
        Self: Sized,
    {
        todo!()
    }

    fn partial_eq(&self, other: &dyn BlockchainDbError) -> bool {
        todo!()
    }

    fn costume_hash_fn(&self, hasher: &mut dyn Hasher) {
        match self {
            AppRpcErrorKind::Decoder => hasher.write_u8(0),
            AppRpcErrorKind::Internal => hasher.write_u8(1),
            AppRpcErrorKind::IO => hasher.write_u8(2),
            AppRpcErrorKind::Signing => hasher.write_u8(3),
            AppRpcErrorKind::Transport => hasher.write_u8(4),
            AppRpcErrorKind::InvalidResponse => hasher.write_u8(5),
            AppRpcErrorKind::ServerUnreachable => hasher.write_u8(6),
            AppRpcErrorKind::Web3RpcError(code) => {
                hasher.write_u8(7);
                hasher.write_i64(*code);
            }
        }
    }

    fn dup(&self) -> Box<dyn BlockchainDbError> {
        Box::new(self.clone())
    }

    as_any_ref_in_trait_impl!();
}

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
pub enum MASQError {
    PendingTooLongNotReplaced,
}

impl BlockchainDbError for MASQError {
    fn serialize(&self) -> String {
        todo!()
    }

    fn deserialize(str: &str) -> Box<dyn BlockchainDbError>
    where
        Self: Sized,
    {
        todo!()
    }

    fn partial_eq(&self, other: &dyn BlockchainDbError) -> bool {
        todo!()
    }

    fn costume_hash_fn(&self, hasher: &mut dyn Hasher) {
        match self {
            MASQError::PendingTooLongNotReplaced => hasher.write_u8(0),
        }
    }

    fn dup(&self) -> Box<dyn BlockchainDbError> {
        Box::new(self.clone())
    }

    as_any_ref_in_trait_impl!();
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
    inner: HashMap<Box<dyn BlockchainDbError>, ErrorStats>,
}

impl PreviousAttempts {
    pub fn new(error: Box<dyn BlockchainDbError>, clock: &dyn ValidationFailureClock) -> Self {
        Self {
            inner: hashmap!(error => ErrorStats::now(clock)),
        }
    }

    pub fn add_attempt(
        mut self,
        error: Box<dyn BlockchainDbError>,
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

impl From<AppRpcError> for AppRpcErrorKind {
    fn from(err: AppRpcError) -> Self {
        match err {
            AppRpcError::Local(local) => match local {
                LocalError::Decoder(_) => Self::Decoder,
                LocalError::Internal => Self::Internal,
                LocalError::Io(_) => Self::IO,
                LocalError::Signing(_) => Self::Signing,
                LocalError::Transport(_) => Self::Transport,
            },
            AppRpcError::Remote(remote) => match remote {
                RemoteError::InvalidResponse(_) => Self::InvalidResponse,
                RemoteError::Unreachable => Self::ServerUnreachable,
                RemoteError::Web3RpcError { code, .. } => Self::Web3RpcError(code),
            },
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

// TODO this is here just to appease the compiler; Jan has this in a diff location
pub trait ValidationFailureClock {
    fn now(&self) -> SystemTime;
}

#[derive(Default)]
pub struct ValidationFailureClockReal {}

impl ValidationFailureClock for ValidationFailureClockReal {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}
// TODO here it ende

mod tests {
    use crate::blockchain::errors::{
        AppRpcError, AppRpcErrorKind, BlockchainDbError, LocalError, MASQError, PreviousAttempts,
        RemoteError, ValidationFailureClockReal,
    };
    use std::collections::hash_map::DefaultHasher;
    use std::fmt::Debug;
    use std::hash::{Hash, Hasher};
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
        let subject = PreviousAttempts::new(
            Box::new(AppRpcErrorKind::Decoder),
            &validation_failure_clock,
        );
        // add_attempt()
        let timestamp_b = SystemTime::now();
        let subject = subject.add_attempt(
            Box::new(AppRpcErrorKind::Internal),
            &validation_failure_clock,
        );
        let timestamp_c = SystemTime::now();
        let subject = subject.add_attempt(Box::new(AppRpcErrorKind::IO), &validation_failure_clock);
        let timestamp_d = SystemTime::now();
        let subject = subject.add_attempt(
            Box::new(AppRpcErrorKind::Decoder),
            &validation_failure_clock,
        );
        let subject = subject.add_attempt(Box::new(AppRpcErrorKind::IO), &validation_failure_clock);

        let decoder_error_stats = subject
            .inner
            .get(&(Box::new(AppRpcErrorKind::Decoder) as Box<dyn BlockchainDbError>))
            .unwrap();
        assert!(
            timestamp_a <= decoder_error_stats.first_seen
                && decoder_error_stats.first_seen <= timestamp_b,
            "Was expected from {:?} to {:?} but was {:?}",
            timestamp_a,
            timestamp_b,
            decoder_error_stats.first_seen
        );
        assert_eq!(decoder_error_stats.attempts, 2);
        let internal_error_stats = subject
            .inner
            .get(&(Box::new(AppRpcErrorKind::Internal) as Box<dyn BlockchainDbError>))
            .unwrap();
        assert!(
            timestamp_b <= internal_error_stats.first_seen
                && internal_error_stats.first_seen <= timestamp_c,
            "Was expected from {:?} to {:?} but was {:?}",
            timestamp_b,
            timestamp_c,
            internal_error_stats.first_seen
        );
        assert_eq!(internal_error_stats.attempts, 1);
        let io_error_stats = subject
            .inner
            .get(&(Box::new(AppRpcErrorKind::IO) as Box<dyn BlockchainDbError>))
            .unwrap();
        assert!(
            timestamp_c <= io_error_stats.first_seen && io_error_stats.first_seen <= timestamp_d,
            "Was expected from {:?} to {:?} but was {:?}",
            timestamp_c,
            timestamp_d,
            io_error_stats.first_seen
        );
        assert_eq!(io_error_stats.attempts, 2);
        let other_error_stats = subject
            .inner
            .get(&(Box::new(AppRpcErrorKind::Signing) as Box<dyn BlockchainDbError>));
        assert_eq!(other_error_stats, None);
    }

    #[test]
    fn conversion_between_app_rpc_error_and_app_rpc_error_kind_works() {
        assert_eq!(
            AppRpcErrorKind::from(AppRpcError::Local(LocalError::Decoder(
                "Decoder error".to_string()
            ))),
            AppRpcErrorKind::Decoder
        );
        assert_eq!(
            AppRpcErrorKind::from(AppRpcError::Local(LocalError::Internal)),
            AppRpcErrorKind::Internal
        );
        assert_eq!(
            AppRpcErrorKind::from(AppRpcError::Local(LocalError::Io("IO error".to_string()))),
            AppRpcErrorKind::IO
        );
        assert_eq!(
            AppRpcErrorKind::from(AppRpcError::Local(LocalError::Signing(
                "Signing error".to_string()
            ))),
            AppRpcErrorKind::Signing
        );
        assert_eq!(
            AppRpcErrorKind::from(AppRpcError::Local(LocalError::Transport(
                "Transport error".to_string()
            ))),
            AppRpcErrorKind::Transport
        );
        assert_eq!(
            AppRpcErrorKind::from(AppRpcError::Remote(RemoteError::InvalidResponse(
                "Invalid response".to_string()
            ))),
            AppRpcErrorKind::InvalidResponse
        );
        assert_eq!(
            AppRpcErrorKind::from(AppRpcError::Remote(RemoteError::Unreachable)),
            AppRpcErrorKind::ServerUnreachable
        );
        assert_eq!(
            AppRpcErrorKind::from(AppRpcError::Remote(RemoteError::Web3RpcError {
                code: 55,
                message: "Booga".to_string()
            })),
            AppRpcErrorKind::Web3RpcError(55)
        );
    }

    #[test]
    fn clone_works_for_blockchain_db_error_wrapping_app_rpc_error_kind() {
        let subject: Box<dyn BlockchainDbError> = Box::new(AppRpcErrorKind::Web3RpcError(123));

        let result = subject.clone();

        test_clone_for_blockchain_db_error::<AppRpcErrorKind>(subject);
    }

    #[test]
    fn clone_works_for_blockchain_db_error_wrapping_masq_error() {
        let subject: Box<dyn BlockchainDbError> = Box::new(MASQError::PendingTooLongNotReplaced);

        test_clone_for_blockchain_db_error::<MASQError>(subject);
    }

    fn test_clone_for_blockchain_db_error<ErrorType>(subject: Box<dyn BlockchainDbError>)
    where
        ErrorType: PartialEq + Debug + 'static,
    {
        let result = subject.clone();

        let specified_subject = subject.as_any().downcast_ref::<ErrorType>().unwrap();
        let specified_result = result.as_any().downcast_ref::<ErrorType>().unwrap();
        assert_eq!(specified_result, specified_subject)
    }
    #[test]
    fn hashing_for_app_arp_error_kind_works() {
        let mut hasher = DefaultHasher::default();
        let mut hashes = vec![
            Box::new(AppRpcErrorKind::Decoder) as Box<dyn BlockchainDbError>,
            Box::new(AppRpcErrorKind::Internal),
            Box::new(AppRpcErrorKind::IO),
            Box::new(AppRpcErrorKind::Signing),
            Box::new(AppRpcErrorKind::Transport),
            Box::new(AppRpcErrorKind::InvalidResponse),
            Box::new(AppRpcErrorKind::ServerUnreachable),
            Box::new(AppRpcErrorKind::Web3RpcError(123)),
            Box::new(AppRpcErrorKind::Web3RpcError(124)),
            Box::new(AppRpcErrorKind::Web3RpcError(555555)),
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
        })
    }

    #[test]
    fn hashing_for_masq_error_works() {
        let mut hasher = DefaultHasher::default();
        let mut hashes = vec![
            Box::new(MASQError::PendingTooLongNotReplaced) as Box<dyn BlockchainDbError>,
            // Add more types here as there are more types of MASQ errors.
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
        })
    }

    #[test]
    fn serialization_and_deserialization_for_blockchain_db_error_works() {
        vec![
            (
                Box::new(AppRpcErrorKind::Web3RpcError(123)) as Box<dyn BlockchainDbError>,
                "bluh",
            ),
            (Box::new(AppRpcErrorKind::Internal), "bluh2"),
            (Box::new(MASQError::PendingTooLongNotReplaced), "bluh3"),
        ]
        .into_iter()
        .for_each(|(blockchain_error, expected_result)| {
            let json_result = serde_json::to_string(&blockchain_error).unwrap();
            assert_eq!(json_result, expected_result);
            let trait_object_result =
                serde_json::from_str::<Box<dyn BlockchainDbError>>(&json_result).unwrap();
            assert_eq!(&trait_object_result, &blockchain_error);
        })
    }
}
