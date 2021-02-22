// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::sub_lib::neighborhood::GossipFailure_0v1;
use crate::sub_lib::versioned_data::Migrations;
use crate::sub_lib::versioned_data::FUTURE_VERSION;
use crate::sub_lib::versioned_data::{MigrationError, StepError, VersionedData};
use lazy_static::lazy_static;
use serde_cbor::Value;
use std::convert::TryFrom;

lazy_static! {
    pub static ref MIGRATIONS: Migrations = {
        let current_version = dv!(0, 1);
        let mut migrations = Migrations::new(current_version);

        migrate_value!(dv!(0, 1), GossipFailure_0v1, GossipFailureMF_0v1, {|value: serde_cbor::Value| {
            GossipFailure_0v1::try_from (&value)
        }});
        migrations.add_step (FUTURE_VERSION, dv!(0, 1), Box::new (GossipFailureMF_0v1{}));

        // add more steps here

        migrations
    };
}

impl Into<VersionedData<GossipFailure_0v1>> for GossipFailure_0v1 {
    fn into(self) -> VersionedData<GossipFailure_0v1> {
        VersionedData::new(&MIGRATIONS, &self)
    }
}

impl TryFrom<VersionedData<GossipFailure_0v1>> for GossipFailure_0v1 {
    type Error = MigrationError;

    fn try_from(vd: VersionedData<GossipFailure_0v1>) -> Result<Self, Self::Error> {
        vd.extract(&MIGRATIONS)
    }
}

impl TryFrom<&Value> for GossipFailure_0v1 {
    type Error = StepError;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        match value {
            Value::Text(name) => match name.as_str() {
                "NoNeighbors" => Ok(GossipFailure_0v1::NoNeighbors),
                "NoSuitableNeighbors" => Ok(GossipFailure_0v1::NoSuitableNeighbors),
                "ManualRejection" => Ok(GossipFailure_0v1::ManualRejection),
                "Unknown" => Ok(GossipFailure_0v1::Unknown),
                _ => Ok(GossipFailure_0v1::Unknown),
            },
            _ => Err(StepError::SemanticError(format!(
                "Expected Value::Text; found {:?}",
                value
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::versioned_data::DataVersion;
    use serde_derive::{Deserialize, Serialize};

    #[test]
    fn can_migrate_from_the_future() {
        #[derive(Serialize, Deserialize)]
        enum ExampleFutureGF {
            NoNeighbors,
            NoSuitableNeighbors,
            ManualRejection,
            Unknown,
            AnotherField,
            YetAnotherField,
        }
        let check_migration = |future: ExampleFutureGF, present: GossipFailure_0v1| {
            let future_migrations = Migrations::new(DataVersion::new(4095, 4095));
            let serialized =
                serde_cbor::ser::to_vec(&VersionedData::new(&future_migrations, &future)).unwrap();
            let future_vd =
                serde_cbor::de::from_slice::<VersionedData<GossipFailure_0v1>>(&serialized)
                    .unwrap();

            let actual = GossipFailure_0v1::try_from(future_vd).unwrap();

            assert_eq!(actual, present);
        };

        check_migration(ExampleFutureGF::NoNeighbors, GossipFailure_0v1::NoNeighbors);
        check_migration(
            ExampleFutureGF::NoSuitableNeighbors,
            GossipFailure_0v1::NoSuitableNeighbors,
        );
        check_migration(
            ExampleFutureGF::ManualRejection,
            GossipFailure_0v1::ManualRejection,
        );
        check_migration(ExampleFutureGF::Unknown, GossipFailure_0v1::Unknown);
        check_migration(ExampleFutureGF::AnotherField, GossipFailure_0v1::Unknown);
        check_migration(ExampleFutureGF::YetAnotherField, GossipFailure_0v1::Unknown);
    }

    #[test]
    fn cannot_migrate_from_value_other_than_text() {
        let value = Value::Bool(true);

        let result = GossipFailure_0v1::try_from(&value);

        assert_eq!(
            result,
            Err(StepError::SemanticError(
                "Expected Value::Text; found Bool(true)".to_string()
            ))
        )
    }
}
