// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::errors::blockchain_db_error::BlockchainDbError;
use crate::blockchain::errors::blockchain_error::app_rpc_web3_error::{
    AppRpcWeb3Error, LocalError, RemoteError,
};
use libc::pathconf;
use serde::Serialize as SerializeTrait;
use serde_derive::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};
use std::hash::{Hash, Hasher};

impl BlockchainDbError for AppRpcWeb3ErrorKind {
    fn serialize_fn(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self) //TODO tested??
    }

    fn deserialize_fn(str: &str) -> Result<Box<dyn BlockchainDbError>, serde_json::Error>
    where
        Self: Sized,
    {
        eprintln!("{:?}", str);
        let res: Result<AppRpcWeb3ErrorKind, serde_json::Error> = serde_json::from_str(str);
        res.map(|kind| Box::new(kind) as Box<dyn BlockchainDbError>)
    }

    fn partial_eq(&self, other: &Box<dyn BlockchainDbError>) -> bool {
        other
            .as_any()
            .downcast_ref::<AppRpcWeb3ErrorKind>()
            .map_or(false, |other| self == other)
    }

    fn costume_hash_fn(&self, hasher: &mut dyn Hasher) {
        match self {
            AppRpcWeb3ErrorKind::Decoder => hasher.write_u8(0),
            AppRpcWeb3ErrorKind::Internal => hasher.write_u8(1),
            AppRpcWeb3ErrorKind::IO => hasher.write_u8(2),
            AppRpcWeb3ErrorKind::Signing => hasher.write_u8(3),
            AppRpcWeb3ErrorKind::Transport => hasher.write_u8(4),
            AppRpcWeb3ErrorKind::InvalidResponse => hasher.write_u8(5),
            AppRpcWeb3ErrorKind::ServerUnreachable => hasher.write_u8(6),
            AppRpcWeb3ErrorKind::Web3RpcError(code) => {
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

#[derive(Debug, Hash, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppRpcWeb3ErrorKind {
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

impl From<AppRpcWeb3Error> for AppRpcWeb3ErrorKind {
    fn from(err: AppRpcWeb3Error) -> Self {
        match err {
            AppRpcWeb3Error::Local(local) => match local {
                LocalError::Decoder(_) => Self::Decoder,
                LocalError::Internal => Self::Internal,
                LocalError::Io(_) => Self::IO,
                LocalError::Signing(_) => Self::Signing,
                LocalError::Transport(_) => Self::Transport,
            },
            AppRpcWeb3Error::Remote(remote) => match remote {
                RemoteError::InvalidResponse(_) => Self::InvalidResponse,
                RemoteError::Unreachable => Self::ServerUnreachable,
                RemoteError::Web3RpcError { code, .. } => Self::Web3RpcError(code),
            },
        }
    }
}

mod tests {
    use crate::blockchain::errors::blockchain_db_error::app_rpc_web3_error_kind::AppRpcWeb3ErrorKind;
    use crate::blockchain::errors::blockchain_db_error::masq_error::MASQError;
    use crate::blockchain::errors::blockchain_db_error::BlockchainDbError;
    use crate::blockchain::errors::blockchain_error::app_rpc_web3_error::{
        AppRpcWeb3Error, LocalError, RemoteError,
    };
    use crate::blockchain::errors::test_utils::test_clone_for_blockchain_db_error;
    use std::collections::hash_map::DefaultHasher;
    use std::fmt::Debug;
    use std::hash::{Hash, Hasher};

    #[test]
    fn conversion_between_app_rpc_error_and_app_rpc_error_kind_works() {
        assert_eq!(
            AppRpcWeb3ErrorKind::from(AppRpcWeb3Error::Local(LocalError::Decoder(
                "Decoder error".to_string()
            ))),
            AppRpcWeb3ErrorKind::Decoder
        );
        assert_eq!(
            AppRpcWeb3ErrorKind::from(AppRpcWeb3Error::Local(LocalError::Internal)),
            AppRpcWeb3ErrorKind::Internal
        );
        assert_eq!(
            AppRpcWeb3ErrorKind::from(AppRpcWeb3Error::Local(LocalError::Io(
                "IO error".to_string()
            ))),
            AppRpcWeb3ErrorKind::IO
        );
        assert_eq!(
            AppRpcWeb3ErrorKind::from(AppRpcWeb3Error::Local(LocalError::Signing(
                "Signing error".to_string()
            ))),
            AppRpcWeb3ErrorKind::Signing
        );
        assert_eq!(
            AppRpcWeb3ErrorKind::from(AppRpcWeb3Error::Local(LocalError::Transport(
                "Transport error".to_string()
            ))),
            AppRpcWeb3ErrorKind::Transport
        );
        assert_eq!(
            AppRpcWeb3ErrorKind::from(AppRpcWeb3Error::Remote(RemoteError::InvalidResponse(
                "Invalid response".to_string()
            ))),
            AppRpcWeb3ErrorKind::InvalidResponse
        );
        assert_eq!(
            AppRpcWeb3ErrorKind::from(AppRpcWeb3Error::Remote(RemoteError::Unreachable)),
            AppRpcWeb3ErrorKind::ServerUnreachable
        );
        assert_eq!(
            AppRpcWeb3ErrorKind::from(AppRpcWeb3Error::Remote(RemoteError::Web3RpcError {
                code: 55,
                message: "Booga".to_string()
            })),
            AppRpcWeb3ErrorKind::Web3RpcError(55)
        );
    }

    #[test]
    fn clone_works_for_blockchain_db_error_wrapping_app_rpc_error_kind() {
        let subject: Box<dyn BlockchainDbError> = Box::new(AppRpcWeb3ErrorKind::Web3RpcError(123));

        test_clone_for_blockchain_db_error::<AppRpcWeb3ErrorKind>(subject);
    }

    #[test]
    fn hashing_for_app_arp_error_kind_works() {
        let mut hasher = DefaultHasher::default();
        let mut hashes = vec![
            Box::new(AppRpcWeb3ErrorKind::Decoder) as Box<dyn BlockchainDbError>,
            Box::new(AppRpcWeb3ErrorKind::Internal),
            Box::new(AppRpcWeb3ErrorKind::IO),
            Box::new(AppRpcWeb3ErrorKind::Signing),
            Box::new(AppRpcWeb3ErrorKind::Transport),
            Box::new(AppRpcWeb3ErrorKind::InvalidResponse),
            Box::new(AppRpcWeb3ErrorKind::ServerUnreachable),
            Box::new(AppRpcWeb3ErrorKind::Web3RpcError(123)),
            Box::new(AppRpcWeb3ErrorKind::Web3RpcError(124)),
            Box::new(AppRpcWeb3ErrorKind::Web3RpcError(555555)),
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
    fn partial_eq_for_app_rpc_error_kind_works() {
        let subject: Box<dyn BlockchainDbError> = Box::new(AppRpcWeb3ErrorKind::Web3RpcError(123));
        let other_1: Box<dyn BlockchainDbError> = Box::new(AppRpcWeb3ErrorKind::Web3RpcError(124));
        let other_2: Box<dyn BlockchainDbError> = Box::new(AppRpcWeb3ErrorKind::Web3RpcError(123));
        let other_3: Box<dyn BlockchainDbError> = Box::new(AppRpcWeb3ErrorKind::Internal);

        assert_ne!(&subject, &other_1);
        assert_eq!(&subject, &other_2);
        assert_ne!(&subject, &other_3);
    }

    #[test]
    fn app_rpc_error_kind_serialization_deserialization() {
        let errors = vec![
            // Local Errors
            AppRpcWeb3ErrorKind::Decoder,
            AppRpcWeb3ErrorKind::Internal,
            AppRpcWeb3ErrorKind::IO,
            AppRpcWeb3ErrorKind::Signing,
            AppRpcWeb3ErrorKind::Transport,
            // Remote Errors
            AppRpcWeb3ErrorKind::InvalidResponse,
            AppRpcWeb3ErrorKind::ServerUnreachable,
            AppRpcWeb3ErrorKind::Web3RpcError(42),
        ];

        errors.into_iter().for_each(|error| {
            let serialized = serde_json::to_string(&error).unwrap();
            let deserialized: AppRpcWeb3ErrorKind = serde_json::from_str(&serialized).unwrap();
            assert_eq!(
                error, deserialized,
                "Failed serde attempt for {:?} that should look \
            like {:?}",
                deserialized, error
            );
        });
    }

    #[test]
    fn serialization_and_deserialization_for_blockchain_db_error_works() {
        vec![
            (
                Box::new(AppRpcWeb3ErrorKind::Internal) as Box<dyn BlockchainDbError>,
                "\"Internal\"",
            ),
            (
                Box::new(AppRpcWeb3ErrorKind::Web3RpcError(123)),
                "{\"Web3RpcError\":123}",
            ),
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
