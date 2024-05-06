// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::neighborhood::node_record::NodeRecordInner_0v1;
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::migrations::utils::value_to_type;
use crate::sub_lib::neighborhood::RatePack;
use crate::sub_lib::versioned_data::{MigrationError, Migrations, StepError, VersionedData};
use crate::sub_lib::wallet::Wallet;
use lazy_static::lazy_static;
use serde_cbor::Value;
use std::collections::BTreeSet;
use std::convert::TryFrom;

lazy_static! {
    pub static ref MIGRATIONS: Migrations = {
        let current_version = masq_lib::constants::NODE_RECORD_INNER_CURRENT_VERSION;
        let mut migrations = Migrations::new(current_version);

        migrate_value!(dv!(0, 1), NodeRecordInner_0v1, NodeRecordInnerMF_0v1, {|value: serde_cbor::Value| {
            NodeRecordInner_0v1::try_from (&value)
        }});
        migrations.add_step (masq_lib::data_version::FUTURE_VERSION, dv!(0, 1), Box::new (NodeRecordInnerMF_0v1{}));

        // add more steps here

        migrations
    };
}

impl From<NodeRecordInner_0v1> for VersionedData<NodeRecordInner_0v1> {
    fn from(inner: NodeRecordInner_0v1) -> Self {
        VersionedData::new(&MIGRATIONS, &inner)
    }
}

impl TryFrom<VersionedData<NodeRecordInner_0v1>> for NodeRecordInner_0v1 {
    type Error = MigrationError;

    fn try_from(vd: VersionedData<NodeRecordInner_0v1>) -> Result<Self, Self::Error> {
        vd.extract(&MIGRATIONS)
    }
}

impl TryFrom<&Value> for NodeRecordInner_0v1 {
    type Error = StepError;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        #[allow(clippy::single_match)]
        match value {
            Value::Map(map) => {
                let mut public_key_opt: Option<PublicKey> = None;
                let mut earning_wallet_opt: Option<Wallet> = None;
                let mut rate_pack_opt: Option<RatePack> = None;
                let mut neighbors_opt: Option<BTreeSet<PublicKey>> = None;
                let mut accepts_connections_opt: Option<bool> = None;
                let mut routes_data_opt: Option<bool> = None;
                let mut version_opt: Option<u32> = None;
                let mut country_code_opt: Option<String> = None;
                map.keys().for_each(|k| {
                    let v = map.get(k).expect("Disappeared");
                    match (k, v) {
                        (Value::Text(field_name), Value::Map(_)) => match field_name.as_str() {
                            "earning_wallet" => earning_wallet_opt = value_to_type::<Wallet>(v),
                            "rate_pack" => rate_pack_opt = value_to_type::<RatePack>(v),
                            _ => (),
                        },
                        (Value::Text(field_name), Value::Array(field_value)) => {
                            match field_name.as_str() {
                                "neighbors" => {
                                    neighbors_opt = Self::public_keys_to_btree_set(field_value)
                                }
                                _ => (),
                            }
                        }
                        (Value::Text(field_name), Value::Bytes(field_value)) => {
                            match field_name.as_str() {
                                "public_key" => public_key_opt = Some(PublicKey::new(field_value)),
                                _ => (),
                            }
                        }
                        (Value::Text(field_name), Value::Bool(field_value)) => {
                            match field_name.as_str() {
                                "accepts_connections" => {
                                    accepts_connections_opt = Some(*field_value)
                                }
                                "routes_data" => routes_data_opt = Some(*field_value),
                                _ => (),
                            }
                        }
                        (Value::Text(field_name), Value::Integer(field_value)) => {
                            match field_name.as_str() {
                                "version" => match field_value {
                                    n if *n < 0 => (),
                                    n if *n >= 0xFFFF_FFFFi128 => (),
                                    n => version_opt = Some(*n as u32),
                                },
                                _ => (),
                            }
                        }
                        (Value::Text(field_name), Value::Text(field_value)) => {
                            match field_name.as_str() {
                                "country_code" => country_code_opt = Some(field_value.clone()),
                                _ => (),
                            }
                        }
                        _ => (),
                    }
                });
                let mut missing_fields: Vec<&str> = vec![];
                fn check_field<'a, T>(
                    missing_fields: &mut Vec<&'a str>,
                    name: &'a str,
                    field: &Option<T>,
                ) {
                    if field.is_none() {
                        missing_fields.push(name)
                    }
                }
                check_field(&mut missing_fields, "public_key", &public_key_opt);
                check_field(&mut missing_fields, "earning_wallet", &earning_wallet_opt);
                check_field(&mut missing_fields, "rate_pack", &rate_pack_opt);
                check_field(&mut missing_fields, "neighbors", &neighbors_opt);
                check_field(
                    &mut missing_fields,
                    "accepts_connections",
                    &accepts_connections_opt,
                );
                check_field(&mut missing_fields, "routes_data", &routes_data_opt);
                check_field(&mut missing_fields, "version", &version_opt);
                check_field(&mut missing_fields, "country_code", &country_code_opt);
                if !missing_fields.is_empty() {
                    unimplemented!("{:?}", missing_fields.clone())
                }
                Ok(NodeRecordInner_0v1 {
                    public_key: public_key_opt.expect("public_key disappeared"),
                    earning_wallet: earning_wallet_opt.expect("public_key disappeared"),
                    rate_pack: rate_pack_opt.expect("public_key disappeared"),
                    neighbors: neighbors_opt.expect("public_key disappeared"),
                    accepts_connections: accepts_connections_opt.expect("public_key disappeared"),
                    routes_data: routes_data_opt.expect("public_key disappeared"),
                    version: version_opt.expect("public_key disappeared"),
                    country_code: country_code_opt.expect("country_code disappeared"),
                })
            }
            _ => Err(StepError::SemanticError(format!(
                "Expected Value::Map; found {:?}",
                value
            ))),
        }
    }
}

impl NodeRecordInner_0v1 {
    fn public_keys_to_btree_set(field_value: &[Value]) -> Option<BTreeSet<PublicKey>> {
        let mut output: BTreeSet<PublicKey> = BTreeSet::new();
        for value in field_value {
            match value_to_type::<PublicKey>(value) {
                None => return None,
                Some(public_key) => output.insert(public_key),
            };
        }
        Some(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::neighborhood::DEFAULT_RATE_PACK;
    use masq_lib::data_version::DataVersion;
    use serde_derive::{Deserialize, Serialize};
    use std::iter::FromIterator;

    #[test]
    fn can_migrate_from_the_future() {
        #[derive(Serialize, Deserialize)]
        struct ExampleFutureNRI {
            pub public_key: PublicKey,
            pub earning_wallet: Wallet,
            pub rate_pack: RatePack,
            pub neighbors: BTreeSet<PublicKey>,
            pub accepts_connections: bool,
            pub routes_data: bool,
            pub version: u32,
            pub country_code: String,
            pub another_field: String,
            pub yet_another_field: u64,
        }
        let expected_nri = NodeRecordInner_0v1 {
            public_key: PublicKey::new(&[1, 2, 3, 4]),
            earning_wallet: Wallet::new("0x0123456789012345678901234567890123456789"),
            rate_pack: DEFAULT_RATE_PACK,
            neighbors: BTreeSet::from_iter(
                vec![PublicKey::new(&[2, 3, 4, 5]), PublicKey::new(&[3, 4, 5, 6])].into_iter(),
            ),
            accepts_connections: false,
            routes_data: true,
            version: 42,
            country_code: "AU".to_string()
        };
        let future_nri = ExampleFutureNRI {
            public_key: expected_nri.public_key.clone(),
            earning_wallet: expected_nri.earning_wallet.clone(),
            rate_pack: expected_nri.rate_pack.clone(),
            neighbors: expected_nri.neighbors.clone(),
            accepts_connections: expected_nri.accepts_connections,
            routes_data: expected_nri.routes_data,
            version: expected_nri.version,
            country_code: expected_nri.country_code.clone(),
            another_field: "These are the times that try men's souls".to_string(),
            yet_another_field: 1234567890,
        };
        let future_migrations = Migrations::new(DataVersion::new(4095, 4095));
        let serialized =
            serde_cbor::ser::to_vec(&VersionedData::new(&future_migrations, &future_nri)).unwrap();
        let future_vd =
            serde_cbor::de::from_slice::<VersionedData<NodeRecordInner_0v1>>(&serialized).unwrap();

        let actual_nri = NodeRecordInner_0v1::try_from(future_vd).unwrap();

        assert_eq!(actual_nri, expected_nri);
    }

    #[test]
    fn cannot_migrate_from_value_other_than_map() {
        let value = Value::Bool(true);

        let result = NodeRecordInner_0v1::try_from(&value);

        assert_eq!(
            result,
            Err(StepError::SemanticError(
                "Expected Value::Map; found Bool(true)".to_string()
            ))
        )
    }
}
