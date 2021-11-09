// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use ethsign::{PublicKey, SecretKey};
use itertools::Itertools;
use secp256k1;
use std::convert::TryFrom;
use std::fmt::Debug;

#[derive(Debug)]
pub struct DualSecret {
    pub ethsign_secret: SecretKey,
    pub secp256k1_secret: secp256k1::key::SecretKey,
}

impl DualSecret {
    pub fn public(&self) -> PublicKey {
        self.ethsign_secret.public()
    }
}

impl TryFrom<&[u8]> for DualSecret {
    type Error = String;

    fn try_from(raw_secret: &[u8]) -> Result<Self, Self::Error> {
        match (
            SecretKey::from_raw(raw_secret),
            secp256k1::key::SecretKey::from_slice(raw_secret),
        ) {
            (Ok(ethsign_secret), Ok(secp256k1_secret)) => Ok(Self {
                ethsign_secret,
                secp256k1_secret,
            }),
            tuple => Err(resolve_hetero_err(tuple)),
        }
    }
}

impl From<(SecretKey, secp256k1::key::SecretKey)> for DualSecret {
    fn from(secrets: (SecretKey, secp256k1::SecretKey)) -> Self {
        let (ethsign_secret, secp256k1_secret) = secrets;
        Self {
            ethsign_secret,
            secp256k1_secret,
        }
    }
}

fn resolve_hetero_err<T: Debug>(
    to_check: (
        Result<ethsign::SecretKey, T>,
        Result<secp256k1::SecretKey, secp256k1::Error>,
    ),
) -> String
where
{
    const SECRET_KEY: &str = "SecretKey";
    fn convert_into_string<C: ?Sized>(is_err: bool, closure: Box<C>) -> String
    where
        C: FnOnce() -> String,
    {
        if is_err {
            closure()
        } else {
            String::new()
        }
    }
    let (a, b) = to_check;
    let vec = vec![
        (
            a.is_err(),
            Box::new(|| {
                let e = a.expect_err("wasn't err?");
                format!("ethsign {}: {:?}", SECRET_KEY, e)
            }) as Box<dyn FnOnce() -> String>,
        ),
        (
            b.is_err(),
            Box::new(|| {
                let e = b.expect_err("wasn't err?");
                format!("secp256k1 {}: {}", SECRET_KEY, e)
            }) as Box<dyn FnOnce() -> String>,
        ),
    ];
    let summary = vec
        .into_iter()
        .map(|(is_err, closure)| convert_into_string(is_err, closure))
        .filter(|item| !item.is_empty())
        .join("; ");
    summary
}

#[cfg(test)]
mod tests {
    use crate::blockchain::dual_secret::{resolve_hetero_err, DualSecret};
    use std::convert::TryFrom;

    #[derive(Debug)]
    struct Debugable;

    #[test]
    fn resolve_hetero_errors_catches_left_only() {
        let debugable = Debugable;
        let results_for_left = (
            Err(debugable),
            Ok(secp256k1::SecretKey::from_slice(b"000000000000000000000000000000aa").unwrap()),
        );

        let output = resolve_hetero_err(results_for_left);

        assert_eq!(output, "ethsign SecretKey: Debugable".to_string())
    }

    #[test]
    fn resolve_hetero_errors_catches_right_only() {
        let results_for_right: (Result<_, Debugable>, Result<_, _>) = (
            Ok(ethsign::SecretKey::from_raw(b"000000000000000000000000000000ab").unwrap()),
            Err(secp256k1::Error::InvalidSecretKey),
        );

        let output = resolve_hetero_err(results_for_right);

        assert_eq!(
            output,
            "secp256k1 SecretKey: secp: malformed or out-of-range secret key".to_string()
        );
    }

    #[test]
    fn try_from_catches_both_errors_from_creation_of_the_secrets() {
        let result = DualSecret::try_from(&b"xyz"[..]);

        let err = match result {
            Err(e) => e,
            _ => panic!("we expected err, but got ok"),
        };
        assert_eq!(
            err,
            "ethsign SecretKey: InvalidInputLength; secp256k1 SecretKey: secp: malformed or out-of-range secret key"
                .to_string()
        )
    }
}
