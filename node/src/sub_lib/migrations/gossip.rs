// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::neighborhood::gossip::{GossipNodeRecord, Gossip_0v1};
use crate::sub_lib::versioned_data::{
    MigrationError, Migrations, StepError, VersionedData, FUTURE_VERSION,
};
use lazy_static::lazy_static;
use serde_cbor::Value;
use std::convert::TryFrom;

lazy_static! {
    static ref MIGRATIONS: Migrations = {
        let current_version = dv!(0, 1);
        let mut migrations = Migrations::new(current_version);

        migrate_value!(dv!(0, 1), Gossip_0v1, GossipMF_0v1, {|value: serde_cbor::Value| {
            Gossip_0v1::try_from (&value)
        }});
        migrations.add_step (FUTURE_VERSION, dv!(0, 1), Box::new (GossipMF_0v1{}));

        // add more steps here

        migrations
    };
}

impl Into<VersionedData<Gossip_0v1>> for Gossip_0v1 {
    fn into(self) -> VersionedData<Gossip_0v1> {
        VersionedData::new(&MIGRATIONS, &self)
    }
}

impl TryFrom<VersionedData<Gossip_0v1>> for Gossip_0v1 {
    type Error = MigrationError;

    fn try_from(vd: VersionedData<Gossip_0v1>) -> Result<Self, Self::Error> {
        vd.extract(&MIGRATIONS)
    }
}

impl TryFrom<&Value> for Gossip_0v1 {
    type Error = StepError;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        match value {
            Value::Map(map) => {
                let init: (Option<StepError>, Vec<GossipNodeRecord>) = (None, vec![]);
                let (error_opt, node_records) =
                    map.keys().fold(init, |(error_opt, node_records), key| {
                        match (key, map.get(key)) {
                            (Value::Text(field_name), Some(Value::Array(field_value))) => {
                                if field_name == "node_records" {
                                    let mut mut_node_records = vec![];
                                    let mut mut_error_opt = error_opt;
                                    for value in field_value {
                                        match (
                                            mut_error_opt.clone(),
                                            GossipNodeRecord::try_from(value),
                                        ) {
                                            (Some(_), _) => (),
                                            (_, Err(e)) => mut_error_opt = Some(e),
                                            (None, Ok(gnr)) => mut_node_records.push(gnr),
                                        }
                                    }
                                    (mut_error_opt, mut_node_records)
                                } else {
                                    (error_opt, node_records)
                                }
                            }
                            _ => (error_opt, node_records),
                        }
                    });
                match error_opt {
                    Some(e) => Err(e),
                    None => Ok(Gossip_0v1 { node_records }),
                }
            }
            _ => unimplemented!(), //Err (StepError::SemanticError("Inscrutable future version".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::neighborhood::gossip::GossipBuilder;
    use crate::sub_lib::versioned_data::DataVersion;
    use crate::test_utils::neighborhood_test_utils::{db_from_node, make_node_record};
    use serde_derive::{Deserialize, Serialize};

    #[test]
    fn can_migrate_from_the_future() {
        #[derive(Serialize, Deserialize)]
        struct ExampleFutureGossip {
            pub node_records: Vec<GossipNodeRecord>,
            pub another_field: String,
            pub yet_another_field: u64,
        }
        let one_node = make_node_record(1234, true);
        let another_node = make_node_record(2345, true);
        let mut db = db_from_node(&one_node);
        db.add_node(another_node.clone()).unwrap();
        db.add_arbitrary_full_neighbor(one_node.public_key(), another_node.public_key());
        let expected_gossip = GossipBuilder::new(&db)
            .node(one_node.public_key(), true)
            .node(another_node.public_key(), true)
            .build();
        let future_gossip = ExampleFutureGossip {
            node_records: expected_gossip.node_records.clone(),
            another_field: "These are the times that try men's souls".to_string(),
            yet_another_field: 1234567890,
        };
        let future_migrations = Migrations::new(DataVersion::new(4095, 4095));
        let serialized =
            serde_cbor::ser::to_vec(&VersionedData::new(&future_migrations, &future_gossip))
                .unwrap();
        let future_vd =
            serde_cbor::de::from_slice::<VersionedData<Gossip_0v1>>(&serialized).unwrap();

        let actual_gossip = Gossip_0v1::try_from(future_vd).unwrap();

        assert_eq!(actual_gossip, expected_gossip);
    }
}
