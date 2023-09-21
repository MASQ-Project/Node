// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::sub_lib::migrations::utils::value_to_type;
use crate::sub_lib::proxy_client::ClientResponsePayload_0v1;
use crate::sub_lib::sequence_buffer::SequencedPacket;
use crate::sub_lib::stream_key::StreamKey;
use crate::sub_lib::versioned_data::Migrations;
use crate::sub_lib::versioned_data::{MigrationError, StepError, VersionedData};
use lazy_static::lazy_static;
use serde_cbor::Value;
use std::convert::TryFrom;

lazy_static! {
    pub static ref MIGRATIONS: Migrations = {
        let current_version = masq_lib::constants::CLIENT_RESPONSE_PAYLOAD_CURRENT_VERSION;
        let mut migrations = Migrations::new(current_version);

        migrate_value!(dv!(0, 1), ClientResponsePayload_0v1, ClientResponsePayloadMF_0v1, {|value: serde_cbor::Value| {
            ClientResponsePayload_0v1::try_from (&value)
        }});
        migrations.add_step (masq_lib::data_version::FUTURE_VERSION, dv!(0, 1), Box::new (ClientResponsePayloadMF_0v1{}));

        // add more steps here

        migrations
    };
}

impl From<ClientResponsePayload_0v1> for VersionedData<ClientResponsePayload_0v1> {
    fn from(data: ClientResponsePayload_0v1) -> Self {
        VersionedData::new(&MIGRATIONS, &data)
    }
}

impl TryFrom<VersionedData<ClientResponsePayload_0v1>> for ClientResponsePayload_0v1 {
    type Error = MigrationError;

    fn try_from(vd: VersionedData<ClientResponsePayload_0v1>) -> Result<Self, Self::Error> {
        vd.extract(&MIGRATIONS)
    }
}

impl TryFrom<&Value> for ClientResponsePayload_0v1 {
    type Error = StepError;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        match value {
            Value::Map(map) => {
                let mut stream_key_opt: Option<StreamKey> = None;
                let mut sequenced_packet_opt: Option<SequencedPacket> = None;
                map.keys().for_each(|k| {
                    let v = map.get(k).expect("Disappeared");
                    if let Value::Text(field_name) = k {
                        match field_name.as_str() {
                            "stream_key" => stream_key_opt = value_to_type::<StreamKey>(v),
                            "sequenced_packet" => {
                                sequenced_packet_opt = value_to_type::<SequencedPacket>(v)
                            }
                            _ => (),
                        }
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
                check_field(&mut missing_fields, "stream_key", &stream_key_opt);
                check_field(
                    &mut missing_fields,
                    "sequenced_packet",
                    &sequenced_packet_opt,
                );
                if !missing_fields.is_empty() {
                    unimplemented!("{:?}", missing_fields.clone())
                }
                Ok(ClientResponsePayload_0v1 {
                    stream_key: stream_key_opt.expect("stream_key disappeared"),
                    sequenced_packet: sequenced_packet_opt.expect("sequenced_packet disappeared"),
                })
            }
            _ => Err(StepError::SemanticError(format!(
                "Expected Value::Map; found {:?}",
                value
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use masq_lib::data_version::DataVersion;
    use serde_derive::{Deserialize, Serialize};

    #[test]
    fn can_migrate_from_the_future() {
        #[derive(Serialize, Deserialize)]
        struct ExampleFutureCRP {
            pub stream_key: StreamKey,
            pub sequenced_packet: SequencedPacket,
            pub another_field: String,
            pub yet_another_field: u64,
        }
        let expected_crp = ClientResponsePayload_0v1 {
            stream_key: StreamKey::make_meaningful_stream_key("All Things Must Pass"),
            sequenced_packet: SequencedPacket::new(vec![4, 3, 2, 1], 4321, false),
        };
        let future_crp = ExampleFutureCRP {
            stream_key: expected_crp.stream_key.clone(),
            sequenced_packet: expected_crp.sequenced_packet.clone(),
            another_field: "These are the times that try men's souls".to_string(),
            yet_another_field: 1234567890,
        };
        let future_migrations = Migrations::new(DataVersion::new(4095, 4095));
        let serialized =
            serde_cbor::ser::to_vec(&VersionedData::new(&future_migrations, &future_crp)).unwrap();
        let future_vd =
            serde_cbor::de::from_slice::<VersionedData<ClientResponsePayload_0v1>>(&serialized)
                .unwrap();

        let actual_crp = ClientResponsePayload_0v1::try_from(future_vd).unwrap();

        assert_eq!(actual_crp, expected_crp);
    }

    #[test]
    fn cannot_migrate_from_value_other_than_map() {
        let value = Value::Bool(true);

        let result = ClientResponsePayload_0v1::try_from(&value);

        assert_eq!(
            result,
            Err(StepError::SemanticError(
                "Expected Value::Map; found Bool(true)".to_string()
            ))
        )
    }
}
