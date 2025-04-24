// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use itertools::Itertools;
use masq_lib::data_version::{DataVersion, FUTURE_VERSION};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::RwLock;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionedData<T: Serialize + DeserializeOwned> {
    version: DataVersion,
    bytes: Vec<u8>,
    phantom: PhantomData<fn() -> T>,
}

impl<T> VersionedData<T>
where
    T: Serialize + DeserializeOwned,
{
    pub fn test_new(version: DataVersion, bytes: Vec<u8>) -> VersionedData<T> {
        VersionedData {
            version,
            bytes,
            phantom: PhantomData,
        }
    }

    pub fn new(migrations: &Migrations, data: &T) -> VersionedData<T> {
        VersionedData {
            version: migrations.current_version(),
            bytes: serde_cbor::ser::to_vec(&data).expect("Serialization error"),
            phantom: PhantomData,
        }
    }

    pub fn version(&self) -> DataVersion {
        self.version
    }

    pub fn bytes(&self) -> &Vec<u8> {
        unimplemented!()
    }

    pub fn extract(self, migrations: &Migrations) -> Result<T, MigrationError> {
        let from_version = if self.version > migrations.current_version {
            FUTURE_VERSION
        } else {
            self.version
        };
        let migrated_bytes = if from_version == migrations.current_version {
            self.bytes
        } else {
            match migrations.migration(from_version) {
                None => {
                    return Err(MigrationError::MigrationNotFound(
                        from_version,
                        migrations.current_version,
                    ))
                }
                Some(step) => match step.migrate(self.bytes) {
                    Err(e) => return Err(MigrationError::MigrationFailed(e)),
                    Ok(bytes) => bytes,
                },
            }
        };
        match serde_cbor::de::from_slice::<T>(&migrated_bytes) {
            Err(e) => Err(MigrationError::MigrationFailed(
                StepError::DeserializationError(
                    migrations.current_version,
                    migrations.current_version,
                    format!("{:?}", e),
                ),
            )),
            Ok(item) => Ok(item),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepError {
    DeserializationError(DataVersion, DataVersion, String),
    SemanticError(String),
}

pub trait MigrationStep: Send + Sync {
    fn migrate(&self, data: Vec<u8>) -> Result<Vec<u8>, StepError>;
    fn dup(&self) -> Box<dyn MigrationStep>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MigrationError {
    MigrationNotFound(DataVersion, DataVersion),
    MigrationFailed(StepError),
}

#[allow(clippy::type_complexity)]
pub struct Migrations {
    current_version: DataVersion,
    table: RwLock<HashMap<DataVersion, HashMap<DataVersion, Box<dyn MigrationStep>>>>,
}

struct ComboStep {
    substeps: Vec<Box<dyn MigrationStep>>,
}
impl MigrationStep for ComboStep {
    fn migrate(&self, data: Vec<u8>) -> Result<Vec<u8>, StepError> {
        self.substeps
            .iter()
            .fold(Ok(data), |sofar, substep| match sofar {
                Err(e) => Err(e),
                Ok(input) => substep.migrate(input),
            })
    }
    fn dup(&self) -> Box<dyn MigrationStep> {
        Box::new(ComboStep {
            substeps: self.substeps.iter().map(|x| x.dup()).collect_vec(),
        })
    }
}
impl ComboStep {
    fn new(substeps: Vec<Box<dyn MigrationStep>>) -> ComboStep {
        ComboStep { substeps }
    }
}

impl Migrations {
    pub fn new(current_version: DataVersion) -> Migrations {
        Migrations {
            current_version,
            table: RwLock::new(HashMap::new()),
        }
    }

    pub fn current_version(&self) -> DataVersion {
        self.current_version
    }

    pub fn migration(&self, from_version: DataVersion) -> Option<Box<dyn MigrationStep>> {
        // This is a hack because we don't want to lock self.table for writing if it's already locked for reading
        let mut new_step: Option<Box<dyn MigrationStep>> = None;
        let result: Option<Box<dyn MigrationStep>> = {
            let table = self.table.read().expect("Migrations poisoned");
            match table.get(&from_version) {
                None => None,
                Some(from_map) => match from_map.get(&self.current_version) {
                    None => {
                        let elements =
                            self.find_migration_chain(from_version, self.current_version);
                        if elements.is_empty() {
                            None
                        } else {
                            new_step = Some(Box::new(ComboStep::new(elements)));
                            None
                        }
                    }
                    Some(boxed_step) => Some(boxed_step.dup()),
                },
            }
        };
        match new_step {
            None => result,
            Some(combo_step_box) => {
                let mut table = self.table.write().expect("Migrations poisoned");
                let _ = table
                    .get_mut(&from_version)
                    .expect("From version disappeared")
                    .insert(self.current_version, combo_step_box.dup());
                Some(combo_step_box)
            }
        }
    }

    pub fn add_step(&mut self, from: DataVersion, to: DataVersion, step: Box<dyn MigrationStep>) {
        self.validate_step(from, to);
        let mut table = self.table.write().expect("Migrations poisoned");
        match table.get_mut(&from) {
            None => {
                let _ = table.insert(from, HashMap::new());
                let from_map = table.get_mut(&from).expect("Disappeared");
                let _ = from_map.insert(to, step);
            }
            Some(from_map) => {
                let _ = from_map.insert(to, step);
            }
        }
    }

    fn validate_step(&self, from: DataVersion, to: DataVersion) {
        // Some of these restrictions are specifically to prevent cycles in the Migrations table,
        // along with the consequent infinite recursion. The trick is that a step must always be
        // from a lower version to a higher version, unless it's from FUTURE_VERSION, and no
        // migration step can ever migrate to FUTURE_VERSION. Hence, no cycles.
        if to == FUTURE_VERSION {
            panic!("A migration step that migrates to FUTURE_VERSION cannot be added");
        }
        if from == to {
            panic!(
                "A migration step from {} to {} is useless and can't be added",
                from, to
            );
        }
        if to > self.current_version() {
            panic! ("A migration step from {} to {} migrates past the current version {} and can't be added", from, to, self.current_version());
        }
        if from != FUTURE_VERSION {
            if from > to {
                panic! ("A migration step from {} to {} steps backward from a known version and can't be added", from, to);
            }
            if from.major != to.major {
                panic!(
                    "A migration step from {} to {} crosses a breaking change and can't be added",
                    from, to
                );
            }
            if (from.major != self.current_version.major)
                || (to.major != self.current_version.major)
            {
                panic!(
                    "A migration step from {} to {} can't be added to migrations within {}.x",
                    from, to, self.current_version.major
                )
            }
        }
    }

    fn find_migration_chain(
        &self,
        from: DataVersion,
        to: DataVersion,
    ) -> Vec<Box<dyn MigrationStep>> {
        let table = self.table.read().expect("Migrations poisoned");
        let from_map = table.get(&from).expect("From disappeared");
        from_map
            .keys()
            .flat_map(|next_key| {
                let migration = from_map
                    .get(next_key)
                    .expect("Intermediate disappeared")
                    .dup();
                if *next_key == to {
                    Some(vec![migration])
                } else {
                    match self.find_migration_chain(*next_key, to) {
                        ref tail if (tail).is_empty() => None,
                        tail => {
                            let mut list = vec![migration];
                            list.extend(tail);
                            Some(list)
                        }
                    }
                }
            })
            .fold(vec![], |sofar, elem| {
                if sofar.is_empty() || (elem.len() < sofar.len()) {
                    elem
                } else {
                    sofar
                }
            })
    }
}

/// This is a shortcut to define an empty struct with an implementation that migrates data from one
/// type to another. An instance of this struct should be added to a `Migrations` object once it is
/// defined.
///
/// You should use this macro if you're migrating versions upward, or if you otherwise have a struct
/// whose type you can pass in as `$ft`. In that case, the macro can take care of deserializing the
/// incoming bytes into an instance of `$ft` to make it easier for you to access.
///
/// `$fv` - from version - `DataVersion` for the version from which this migration migrates.
///
/// `$ft` - from type - The type from which this migration migrates.
///
/// `$tv` - to version - `DataVersion` for the version to which this migration migrates.
///
/// `$tt` - to type - The type to which this migration migrates.
///
/// `$mt` - migrator type - A name for the new type that will be defined to migrate from `$ft` to `$tt`.
///
/// `$b` - block - A block that accepts an item of type `$ft` and tries to make of it an item of
///                type `$tt`, returning a `Result<$tt, StepError>`.
#[macro_export]
macro_rules! migrate_item {
    ($fv:expr, $ft:ty, $tv:expr, $tt:ty, $mt:ident, $b:block) => {
        #[allow(non_camel_case_types)]
        struct $mt {}
        impl $crate::sub_lib::versioned_data::MigrationStep for $mt {
            fn migrate(
                &self,
                data: Vec<u8>,
            ) -> Result<Vec<u8>, $crate::sub_lib::versioned_data::StepError> {
                let in_item = match serde_cbor::de::from_slice::<$ft>(&data) {
                    Ok(item) => item,
                    Err(_) => {
                        return Err(
                            $crate::sub_lib::versioned_data::StepError::DeserializationError(
                                $fv,
                                $tv,
                                format!(
                                    "Unable to deserialize {} with data {:?}",
                                    stringify!($mt),
                                    data
                                ),
                            ),
                        )
                    }
                };
                let result: Result<$tt, $crate::sub_lib::versioned_data::StepError> = $b(in_item);
                match result {
                    Ok(out_item) => {
                        Ok(serde_cbor::ser::to_vec(&out_item).expect("Serialization failed"))
                    }
                    Err(e) => Err(e),
                }
            }
            fn dup(&self) -> Box<dyn $crate::sub_lib::versioned_data::MigrationStep> {
                Box::new($mt {})
            }
        }
    };
}

/// This is a shortcut to define an empty struct with an implementation that migrates data from one
/// type to another. An instance of this struct should be added to a `Migrations` object once it is
/// defined.
///
/// You should use this macro if you're migrating versions downward; that is, if you have no struct
/// that can hold the incoming data (because it comes from a version later than yours). In that case,
/// the macro cannot deserialize the incoming bytes into a purpose-built struct for you, but it can
/// produce a `serde_cbor::Value` object that you can explore for fields that you know about.
///
/// `$tv` - to version - `DataVersion` for the version to which this migration migrates.
///
/// `$tt` - to type - The type to which this migration migrates.
///
/// `$mt` - migrator type - A name for the new type that will be defined to migrate from `$ft` to `$tt`.
///
/// `$b` - block - A block that accepts an item of type `serde_cbor::Value` and tries to make of it
///                an item of type `$tt`, returning a `Result<$tt, StepError>`.
#[macro_export]
macro_rules! migrate_value {
    ($tv:expr, $tt:ty, $mt:ident, $b:block) => {
        #[allow(non_camel_case_types)]
        #[allow(clippy::upper_case_acronyms)]
        struct $mt {}
        impl $crate::sub_lib::versioned_data::MigrationStep for $mt {
            fn migrate(
                &self,
                data: Vec<u8>,
            ) -> Result<Vec<u8>, $crate::sub_lib::versioned_data::StepError> {
                let value: serde_cbor::Value = match serde_cbor::de::from_slice(&data) {
                    Ok(v) => v,
                    Err(_) => {
                        return Err(
                            $crate::sub_lib::versioned_data::StepError::DeserializationError(
                                masq_lib::data_version::FUTURE_VERSION,
                                $tv,
                                format!(
                                    "Unable to deserialize {} with data {:?}",
                                    stringify!($mt),
                                    data
                                ),
                            ),
                        )
                    }
                };
                let result: Result<$tt, $crate::sub_lib::versioned_data::StepError> = $b(value);
                match result {
                    Ok(out_item) => {
                        Ok(serde_cbor::ser::to_vec(&out_item).expect("Serialization failed"))
                    }
                    Err(e) => Err(e),
                }
            }
            fn dup(&self) -> Box<dyn $crate::sub_lib::versioned_data::MigrationStep> {
                Box::new($mt {})
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use masq_lib::data_version::FUTURE_VERSION;
    use serde_cbor::Value;

    #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
    struct PersonV44 {
        name: String,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
    struct PersonV45 {
        name: String,
        weight: u16,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
    struct PersonV46 {
        name: String,
        weight: u16,
        address: String,
    }

    migrate_item! {dv!(4, 4), PersonV44, dv! (4, 5), PersonV45, PersonM4v4to4v5, {|in_item: PersonV44|
        Ok(PersonV45 {
            name: in_item.name,
            weight: 170
        })
    }}

    migrate_item! {dv! (4, 5), PersonV45, dv! (4, 6), PersonV46, PersonM45v46, {|in_item: PersonV45|
        Ok(PersonV46 {
            name: in_item.name,
            weight: in_item.weight,
            address: "Unknown".to_string()
        })
    }}

    migrate_value! {dv! (4, 4), PersonV44, PersonMF4v4, {|value: Value| {
        let mut out_item = PersonV44{name: String::new()};
        match value {
            Value::Map(map) => {
                map.keys().for_each(|k| match (k, map.get(k)) {
                    (Value::Text(field_name), Some(Value::Text(field_value))) => if field_name == "name" {
                        out_item.name = field_value.clone()
                    }
                    _ => (),
                })
            },
            _ => (),
        };
        Ok(out_item)
    }}}

    migrate_item! {dv! (4, 4), PersonV44, dv! (4, 5), PersonV45, PersonM44v45Err, {|_: PersonV44|
        Err(StepError::SemanticError("My tummy hurts".to_string()))
    }}

    struct PersonM44v45BadData {}
    impl MigrationStep for PersonM44v45BadData {
        fn migrate(&self, _data: Vec<u8>) -> Result<Vec<u8>, StepError> {
            Ok(vec![1, 2, 3, 4])
        }
        fn dup(&self) -> Box<dyn MigrationStep> {
            Box::new(PersonM44v45BadData {})
        }
    }

    #[test]
    #[should_panic(expected = "A migration step from 1.1 to 1.1 is useless and can't be added")]
    fn migration_steps_cant_be_added_from_and_to_the_same_version() {
        let mut subject = Migrations::new(dv!(4, 5));

        subject.add_step(dv!(1, 1), dv!(1, 1), Box::new(PersonM4v4to4v5 {}));
    }

    #[test]
    #[should_panic(
        expected = "A migration step from 1.2 to 1.1 steps backward from a known version and can't be added"
    )]
    fn migration_steps_cant_go_backward_from_a_known_version() {
        let mut subject = Migrations::new(dv!(4, 5));

        subject.add_step(dv!(1, 2), dv!(1, 1), Box::new(PersonM4v4to4v5 {}));
    }

    #[test]
    #[should_panic(expected = "A migration step that migrates to FUTURE_VERSION cannot be added")]
    fn migration_steps_cant_go_to_future_version() {
        let mut subject = Migrations::new(dv!(4, 5));

        subject.add_step(dv!(4, 4), FUTURE_VERSION, Box::new(PersonM4v4to4v5 {}));
    }

    #[test]
    #[should_panic(
        expected = "A migration step from 4.4 to 4.6 migrates past the current version 4.5 and can't be added"
    )]
    fn migration_steps_cant_go_past_current_version() {
        let mut subject = Migrations::new(dv!(4, 5));

        subject.add_step(dv!(4, 4), dv!(4, 6), Box::new(PersonM4v4to4v5 {}));
    }

    #[test]
    #[should_panic(
        expected = "A migration step from 1.2 to 2.1 crosses a breaking change and can't be added"
    )]
    fn migration_steps_cant_cross_breaking_changes() {
        let mut subject = Migrations::new(dv!(4, 5));

        subject.add_step(dv!(1, 2), dv!(2, 1), Box::new(PersonM4v4to4v5 {}));
    }

    #[test]
    #[should_panic(
        expected = "A migration step from 1.2 to 1.3 can't be added to migrations within 4.x"
    )]
    fn migration_steps_must_match_migrations_major_version() {
        let mut subject = Migrations::new(dv!(4, 5));

        subject.add_step(dv!(1, 2), dv!(1, 3), Box::new(PersonM4v4to4v5 {}));
    }

    #[test]
    fn migration_steps_backward_from_unknown_version_works_fine() {
        let mut subject = Migrations::new(dv!(4, 5));

        subject.add_step(FUTURE_VERSION, dv!(4, 5), Box::new(PersonM4v4to4v5 {}));
    }

    #[test]
    fn migrations_can_find_specified_migration_step() {
        let mut migrations = Migrations::new(dv!(4, 5));
        migrations.add_step(dv!(4, 4), dv!(4, 5), Box::new(PersonM4v4to4v5 {}));

        let result = migrations.migration(dv!(4, 4)).unwrap();

        let in_data = PersonV44 {
            name: "Billy".to_string(),
        };
        let serialized = serde_cbor::ser::to_vec(&in_data).unwrap();
        let migrated = result.migrate(serialized).unwrap();
        let out_data = serde_cbor::de::from_slice::<PersonV45>(&migrated).unwrap();
        assert_eq!(
            out_data,
            PersonV45 {
                name: "Billy".to_string(),
                weight: 170
            }
        )
    }

    #[test]
    fn migrations_can_construct_chained_migration_step() {
        let mut migrations = Migrations::new(dv!(4, 6));
        migrations.add_step(dv!(4, 4), dv!(4, 5), Box::new(PersonM4v4to4v5 {}));
        migrations.add_step(dv!(4, 5), dv!(4, 6), Box::new(PersonM45v46 {}));

        let result = migrations.migration(dv!(4, 4)).unwrap();

        let in_data = PersonV44 {
            name: "Billy".to_string(),
        };
        let serialized = serde_cbor::ser::to_vec(&in_data).unwrap();
        let migrated = result.migrate(serialized).unwrap();
        let out_data = serde_cbor::de::from_slice::<PersonV46>(&migrated).unwrap();
        assert_eq!(
            out_data,
            PersonV46 {
                name: "Billy".to_string(),
                weight: 170,
                address: "Unknown".to_string(),
            }
        )
    }

    #[test]
    fn migrations_cannot_find_nonexistent_major_migration_step() {
        let migrations = Migrations::new(dv!(4, 5));

        let result = migrations.migration(dv!(4, 4));

        assert!(result.is_none());
    }

    #[test]
    fn migrations_cannot_find_nonexistent_minor_migration_step() {
        let mut migrations = Migrations::new(dv!(4, 5));
        migrations.add_step(dv!(4, 4), dv!(4, 5), Box::new(PersonM4v4to4v5 {}));

        let result = migrations.migration(dv!(4, 3));

        assert!(result.is_none());
    }

    #[test]
    fn versioned_data_can_be_serialized_and_deserialized_when_version_doesnt_change() {
        let migrations = Migrations::new(dv!(4, 5));
        let original = VersionedData::new(&migrations, &"Booga".to_string());

        let bytes = serde_cbor::ser::to_vec(&original).unwrap();
        let deserialized = serde_cbor::de::from_slice::<VersionedData<String>>(&bytes).unwrap();

        assert_eq!(deserialized.version(), dv!(4, 5));
        assert_eq!(deserialized.extract(&migrations), Ok("Booga".to_string()));
    }

    #[test]
    fn versioned_data_can_be_serialized_and_deserialized_a_version_later() {
        let in_migrations = Migrations::new(dv!(4, 4));
        let mut out_migrations = Migrations::new(dv!(4, 5));
        out_migrations.add_step(dv!(4, 4), dv!(4, 5), Box::new(PersonM4v4to4v5 {}));

        let in_data = PersonV44 {
            name: "Billy".to_string(),
        };
        let in_vd = VersionedData::new(&in_migrations, &in_data);

        let serialized = serde_cbor::ser::to_vec(&in_vd).unwrap();
        let out_vd = serde_cbor::de::from_slice::<VersionedData<PersonV45>>(&serialized).unwrap();

        let out_data = out_vd.extract(&out_migrations).unwrap();
        assert_eq!(
            out_data,
            PersonV45 {
                name: "Billy".to_string(),
                weight: 170
            }
        )
    }

    #[test]
    fn versioned_data_can_be_serialized_and_deserialized_two_versions_later() {
        let in_migrations = Migrations::new(dv!(4, 4));
        let mut out_migrations = Migrations::new(dv!(4, 6));
        out_migrations.add_step(dv!(4, 4), dv!(4, 5), Box::new(PersonM4v4to4v5 {}));
        out_migrations.add_step(dv!(4, 5), dv!(4, 6), Box::new(PersonM45v46 {}));

        let in_data = PersonV44 {
            name: "Billy".to_string(),
        };
        let in_vd = VersionedData::new(&in_migrations, &in_data);

        let serialized = serde_cbor::ser::to_vec(&in_vd).unwrap();
        let out_vd = serde_cbor::de::from_slice::<VersionedData<PersonV46>>(&serialized).unwrap();

        let out_data = out_vd.extract(&out_migrations).unwrap();
        assert_eq!(
            out_data,
            PersonV46 {
                name: "Billy".to_string(),
                weight: 170,
                address: "Unknown".to_string()
            }
        )
    }

    #[test]
    fn versioned_data_can_be_serialized_and_deserialized_to_previous_version() {
        let in_migrations = Migrations::new(dv!(4, 5));
        let mut out_migrations = Migrations::new(dv!(4, 4));
        out_migrations.add_step(FUTURE_VERSION, dv!(4, 4), Box::new(PersonMF4v4 {}));

        let in_data = PersonV45 {
            name: "Billy".to_string(),
            weight: 280,
        };
        let in_vd = VersionedData::new(&in_migrations, &in_data);

        let serialized = serde_cbor::ser::to_vec(&in_vd).unwrap();
        let out_vd = serde_cbor::de::from_slice::<VersionedData<PersonV44>>(&serialized).unwrap();

        let out_data = out_vd.extract(&out_migrations).unwrap();
        assert_eq!(
            out_data,
            PersonV44 {
                name: "Billy".to_string(),
            }
        )
    }

    #[test]
    fn versioned_data_can_be_serialized_and_deserialized_to_much_earlier_version() {
        let in_migrations = Migrations::new(dv!(4, 5));
        let mut out_migrations = Migrations::new(dv!(4, 4));
        out_migrations.add_step(FUTURE_VERSION, dv!(4, 4), Box::new(PersonMF4v4 {}));

        let in_data = PersonV46 {
            name: "Billy".to_string(),
            weight: 280,
            address: "123 Main St.".to_string(),
        };
        let in_vd = VersionedData::new(&in_migrations, &in_data);

        let serialized = serde_cbor::ser::to_vec(&in_vd).unwrap();
        let out_vd = serde_cbor::de::from_slice::<VersionedData<PersonV44>>(&serialized).unwrap();

        let out_data = out_vd.extract(&out_migrations).unwrap();
        assert_eq!(
            out_data,
            PersonV44 {
                name: "Billy".to_string(),
            }
        )
    }

    #[test]
    fn versioned_data_deserialization_fails_if_step_fails() {
        let in_migrations = Migrations::new(dv!(4, 4));
        let mut out_migrations = Migrations::new(dv!(4, 6));
        out_migrations.add_step(dv!(4, 4), dv!(4, 5), Box::new(PersonM44v45Err {}));
        out_migrations.add_step(dv!(4, 5), dv!(4, 6), Box::new(PersonM45v46 {}));

        let in_data = PersonV44 {
            name: "Billy".to_string(),
        };
        let in_vd = VersionedData::new(&in_migrations, &in_data);

        let serialized = serde_cbor::ser::to_vec(&in_vd).unwrap();
        let out_vd = serde_cbor::de::from_slice::<VersionedData<PersonV46>>(&serialized).unwrap();

        let result = out_vd.extract(&out_migrations);
        assert_eq!(
            result,
            Err(MigrationError::MigrationFailed(StepError::SemanticError(
                "My tummy hurts".to_string()
            )))
        );
    }

    #[test]
    fn versioned_data_deserialization_fails_if_suitable_migration_does_not_exist() {
        let in_migrations = Migrations::new(dv!(4, 4));
        let out_migrations = Migrations::new(dv!(4, 6));

        let in_data = PersonV44 {
            name: "Billy".to_string(),
        };
        let in_vd = VersionedData::new(&in_migrations, &in_data);

        let serialized = serde_cbor::ser::to_vec(&in_vd).unwrap();
        let out_vd = serde_cbor::de::from_slice::<VersionedData<PersonV46>>(&serialized).unwrap();

        let result = out_vd.extract(&out_migrations);
        assert_eq!(
            result,
            Err(MigrationError::MigrationNotFound(dv!(4, 4), dv!(4, 6)))
        );
    }

    #[test]
    fn versioned_data_deserialization_fails_if_final_deserialization_fails() {
        let in_migrations = Migrations::new(dv!(4, 4));
        let mut out_migrations = Migrations::new(dv!(4, 5));
        out_migrations.add_step(dv!(4, 4), dv!(4, 5), Box::new(PersonM44v45BadData {}));

        let in_data = PersonV44 {
            name: "Billy".to_string(),
        };
        let in_vd = VersionedData::new(&in_migrations, &in_data);

        let serialized = serde_cbor::ser::to_vec(&in_vd).unwrap();
        let out_vd = serde_cbor::de::from_slice::<VersionedData<PersonV45>>(&serialized).unwrap();

        let result = out_vd.extract(&out_migrations);
        assert_eq!(
            result,
            Err(MigrationError::MigrationFailed(
                StepError::DeserializationError(dv!(4, 5), dv!(4, 5), "ErrorImpl { code: Message(\"invalid type: integer `1`, expected struct PersonV45\"), offset: 0 }".to_string())
            ))
        );
    }

    #[test]
    fn migrate_value_fails_to_parse_cbor_value() {
        let subject = PersonMF4v4 {};

        let result = subject.migrate(vec![]);

        assert_eq!(
            result,
            Err(StepError::DeserializationError(
                FUTURE_VERSION,
                dv!(4, 4),
                "Unable to deserialize PersonMF4v4 with data []".to_string()
            ))
        );
    }

    #[test]
    fn migrate_item_fails_to_parse_cbor_value() {
        let subject = PersonM4v4to4v5 {};

        let result = subject.migrate(vec![]);

        match result {
            Err(StepError::DeserializationError(
                previous_data_version,
                next_data_version,
                error_msg,
            )) => {
                // macros migrate_item and migrate_value have both the same method migrate(), where the implementation of this
                // kind of error differs in the initial entry; either some specific version or the constant FUTURE_VERSION
                assert_ne!(previous_data_version, FUTURE_VERSION);
                assert_eq!(previous_data_version, dv!(4, 4));
                assert_eq!(next_data_version, dv!(4, 5));
                assert_eq!(
                    error_msg,
                    "Unable to deserialize PersonM4v4to4v5 with data []"
                )
            }
            x => panic!("We expected DeserializationError but got this: {:?}", x),
        }
    }
}
