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
            tuple => Err(resolve_hetero_errors(
                tuple,
                ("ethsign SecretKey: ", "secp256k1 SecretKey: "),
            )),
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

fn resolve_hetero_errors<T, E, R, S>(
    to_check: (Result<T, E>, Result<R, S>),
    intros: (&str, &str),
) -> String
where
    T: Debug,
    E: Debug,
    R: Debug,
    S: Debug,
{
    fn if_err_convert_into_string(
        is_err: bool,
        r: Result<impl Debug, impl Debug>,
        intro: &str,
    ) -> String {
        if is_err {
            let r = r.expect_err("wasn't err?");
            format!("{}{:?}", intro, r)
        } else {
            String::new()
        }
    }
    let (a, b) = to_check;
    let (intro_a, intro_b) = intros;
    let a_is_err = a.is_err();
    let b_is_err = b.is_err();
    let a = if_err_convert_into_string(a_is_err, a, intro_a);
    let b = if_err_convert_into_string(b_is_err, b, intro_b);
    [a, b].iter().filter(|item| !item.is_empty()).join(", ")
}

#[cfg(test)]
mod tests {
    use crate::blockchain::dual_secret::{resolve_hetero_errors, DualSecret};
    use masq_lib::utils::localhost;
    use std::convert::TryFrom;
    use std::net::IpAddr;

    #[test]
    fn resolve_hetero_errors_catches_left_only() {
        let results_for_left: (Result<u8, ()>, Result<&str, IpAddr>) = (Err(()), Ok("phew"));

        let output = resolve_hetero_errors(results_for_left, ("left ", "right "));

        assert_eq!(output, "left ()".to_string())
    }

    #[test]
    fn resolve_hetero_errors_catches_right_only() {
        let results_for_right: (Result<u8, ()>, Result<&str, IpAddr>) =
            (Ok(2_u8), Err(localhost()));

        let output = resolve_hetero_errors(results_for_right, ("left ", "right "));

        assert_eq!(output, "right 127.0.0.1".to_string());
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
            "ethsign SecretKey: InvalidInputLength, secp256k1 SecretKey: InvalidSecretKey"
                .to_string()
        )
    }
}
