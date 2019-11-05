use serde::{Serialize, Deserialize};
use std::fmt::Debug;
use std::collections::HashMap;
use serde::de::DeserializeOwned;
use std::marker::PhantomData;
use std::cmp::Ordering;
use itertools::Itertools;
use std::sync::RwLock;

pub const FUTURE_VERSION: DataVersion = DataVersion {major: 0xFFFF, minor: 0xFFFF};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DataVersion {
    pub major: u16,
    pub minor: u16,
}

impl DataVersion {
    fn new (major: u16, minor: u16) -> DataVersion {
        DataVersion{ major, minor }
    }
}

impl PartialOrd for DataVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.major.partial_cmp (&other.major) {
            None => None,
            Some(Ordering::Equal) => self.minor.partial_cmp(&other.minor),
            Some(ordering) => Some(ordering)
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionedData<T: Serialize + DeserializeOwned> {
    version: DataVersion,
    bytes: Vec<u8>,
    phantom: PhantomData<*const T>,
}

impl<T> VersionedData<T> where T: Serialize + DeserializeOwned {
    pub fn new (migrations: &Migrations, data: &T) -> VersionedData<T> {
        VersionedData {
            version: migrations.current_version(),
            bytes: serde_cbor::ser::to_vec(&data).expect ("Test-drive me"),
            phantom: PhantomData
        }
    }

    pub fn version(&self) -> DataVersion {
        self.version
    }

    pub fn extract(&self, _migrations: &Migrations) -> Result<T, MigrationError> {
        Ok(serde_cbor::de::from_slice::<T>(&self.bytes).expect("Test-drive me"))
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum StepError {

}

pub trait MigrationStep: Send + Sync {
    fn migrate(&self, data: Vec<u8>) -> Result<Vec<u8>, StepError>;
    fn dup(&self) -> Box<dyn MigrationStep>;
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MigrationError {

}

pub struct Migrations {
    current_version: DataVersion,
    table: RwLock<HashMap<DataVersion, HashMap<DataVersion, Box<dyn MigrationStep>>>>,
}

struct ComboStep {
    substeps: Vec<Box<dyn MigrationStep>>
}
impl MigrationStep for ComboStep {
    fn migrate(&self, data: Vec<u8>) -> Result<Vec<u8>, StepError> {
        self.substeps.iter ()
            .fold(Ok(data), |sofar, substep| {
                match sofar {
                    Err(e) => Err(e),
                    Ok (input) => substep.migrate(input)
                }
            })
    }
    fn dup(&self) -> Box<dyn MigrationStep> {
        Box::new (ComboStep {
            substeps: self.substeps.iter().map(|x| x.dup()).collect_vec()
        })
    }
}
impl ComboStep {
    fn new (substeps: Vec<Box<dyn MigrationStep>>) -> ComboStep {
        ComboStep {
            substeps
        }
    }
}

impl Migrations {
    pub fn new(current_version: DataVersion) -> Migrations {
        Migrations {
            current_version,
            table: RwLock::new (HashMap::new()),
        }
    }

    pub fn current_version(&self) -> DataVersion {
        self.current_version
    }

    pub fn migration(&self, from_version: DataVersion) -> Option<Box<dyn MigrationStep>> {
        let mut new_step: Option<Box<dyn MigrationStep>> = None;
        let result: Option<Box<dyn MigrationStep>> = {
            let table = self.table.read().expect("Migrations poisoned");
            match table.get(&from_version) {
                None => None,
                Some(from_map) => match from_map.get(&self.current_version) {
                    None => {
                        let elements = self
                            .find_migration_chain(from_version, self.current_version);
                        if elements.is_empty() {
                            None
                        } else {
                            new_step = Some(Box::new (ComboStep::new (elements)));
                            None
                        }
                    },
                    Some(boxed_step) => Some(boxed_step.dup())
                }
            }
        };
        match new_step {
            None => result,
            Some(combo_step) => {
                let mut table = self.table.write().expect("Migrations poisoned");
                let _ = table.get_mut(&from_version).expect("From version disappeared").insert(self.current_version, combo_step).expect("Chain insertion failed");
                self.migration(from_version)
            }
        }
    }

    pub fn add_step(&mut self, from: DataVersion, to: DataVersion, step: Box<dyn MigrationStep>) {
        let mut table = self.table.write().expect("Migrations poisoned");
        match table.get_mut(&from) {
            None => {
                let _ = table.insert (from, HashMap::new());
                let from_map = table.get_mut(&from).expect ("Disappeared");
                let _ = from_map.insert (to, step);
            },
            Some(from_map) => {
                let _ = from_map.insert (to, step);
            }
        }
    }

    fn find_migration_chain(&self, from: DataVersion, to: DataVersion) -> Vec<Box<dyn MigrationStep>> {
        let table = self.table.read().expect("Migrations poisoned");
        let from_map = table.get(&from).expect ("From disappeared");
        from_map.keys().into_iter()
            .flat_map (|next_key| {
                let migration = from_map.get(next_key).expect ("Intermediate disappeared").dup();
                if *next_key == to {
                    Some (vec![migration])
                }
                else {
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
                }
                else {
                    sofar
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct PersonV44 {
        name: String,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct PersonV45 {
        name: String,
        weight: u16,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct PersonV46 {
        name: String,
        weight: u16,
        address: String,
    }

    struct PersonM44v45 {}
    impl MigrationStep for PersonM44v45 {
        fn migrate(&self, data: Vec<u8>) -> Result<Vec<u8>, StepError> {
            let in_item = serde_cbor::de::from_slice::<PersonV44>(&data).unwrap();
            let out_item = PersonV45 {name: in_item.name, weight: 170};
            Ok(serde_cbor::ser::to_vec(&out_item).unwrap())
        }
        fn dup(&self) -> Box<dyn MigrationStep> {Box::new(PersonM44v45{})}
    }

    struct PersonM45v46 {}
    impl MigrationStep for PersonM45v46 {
        fn migrate(&self, data: Vec<u8>) -> Result<Vec<u8>, StepError> {
            let in_item = serde_cbor::de::from_slice::<PersonV45>(&data).unwrap();
            let out_item = PersonV46 {name: in_item.name, weight: in_item.weight, address: "Unknown".to_string()};
            Ok(serde_cbor::ser::to_vec(&out_item).unwrap())
        }
        fn dup(&self) -> Box<dyn MigrationStep> {Box::new(PersonM45v46{})}
    }

    #[test]
    fn dataversions_can_be_compared() {
        let low_low_version = DataVersion::new (2, 3);
        let low_high_version = DataVersion::new (2, 8);
        let high_low_version = DataVersion::new (7, 4);
        let high_high_version = DataVersion::new (7, 6);

        assert! (low_low_version < low_high_version);
        assert! (low_low_version < high_low_version);
        assert! (low_low_version < high_high_version);
        assert! (low_high_version > low_low_version);
        assert! (low_high_version < high_low_version);
        assert! (low_high_version < high_high_version);
        assert! (high_low_version > low_low_version);
        assert! (high_low_version > low_high_version);
        assert! (high_low_version < high_high_version);
        assert! (high_high_version > low_low_version);
        assert! (high_high_version > low_high_version);
        assert! (high_high_version > high_low_version);
    }

    #[test]
    fn migrations_can_find_specified_migration_step() {
        let mut migrations = Migrations::new(DataVersion::new(4, 5));
        migrations.add_step (DataVersion::new (4, 4), DataVersion::new (4, 5), Box::new (PersonM44v45{}));

        let result = migrations.migration(DataVersion::new(4, 4)).unwrap();

        let in_data = PersonV44{name: "Billy".to_string()};
        let serialized = serde_cbor::ser::to_vec(&in_data).unwrap();
        let migrated = result.migrate(serialized).unwrap();
        let out_data = serde_cbor::de::from_slice::<PersonV45>(&migrated).unwrap();
        assert_eq! (out_data, PersonV45 {
            name: "Billy".to_string(),
            weight: 170
        })
    }

    #[test]
    fn migrations_can_construct_chained_migration_step() {
        let mut migrations = Migrations::new(DataVersion::new(4, 5));
        migrations.add_step (DataVersion::new (4, 4), DataVersion::new (4, 5), Box::new (PersonM44v45{}));
        migrations.add_step (DataVersion::new (4, 5), DataVersion::new (4, 6), Box::new (PersonM45v46{}));

        let result = migrations.migration(DataVersion::new(4, 6)).unwrap();

        let in_data = PersonV44{name: "Billy".to_string()};
        let serialized = serde_cbor::ser::to_vec(&in_data).unwrap();
        let migrated = result.migrate(serialized).unwrap();
        let out_data = serde_cbor::de::from_slice::<PersonV46>(&migrated).unwrap();
        assert_eq! (out_data, PersonV46 {
            name: "Billy".to_string(),
            weight: 170,
            address: "Unknown".to_string(),
        })
    }

    #[test]
    fn migrations_cannot_find_nonexistent_major_migration_step() {
        let migrations = Migrations::new(DataVersion::new(4, 5));

        let result = migrations.migration(DataVersion::new(4, 4));

        assert!(result.is_none());
    }

    #[test]
    fn migrations_cannot_find_nonexistent_minor_migration_step() {
        let mut migrations = Migrations::new(DataVersion::new(4, 5));
        migrations.add_step (DataVersion::new (4, 4), DataVersion::new (4, 5), Box::new (PersonM44v45{}));

        let result = migrations.migration(DataVersion::new(4, 3));

        assert!(result.is_none());
    }

    #[test]
    fn versioned_data_can_be_serialized_and_deserialized_when_version_doesnt_change() {
        let migrations = Migrations::new(DataVersion::new(4, 5));
        let original = VersionedData::new (&migrations, &"Booga".to_string());

        let bytes = serde_cbor::ser::to_vec(&original).unwrap();
        let deserialized = serde_cbor::de::from_slice::<VersionedData<String>>(&bytes).unwrap();

        assert_eq! (deserialized.version(), DataVersion::new (4, 5));
        assert_eq! (deserialized.extract(&migrations), Ok("Booga".to_string()));
    }

    #[test]
    #[ignore]
    fn versioned_data_can_be_serialized_and_deserialized_a_version_later() {
        let in_migrations = Migrations::new(DataVersion::new(4, 4));
        let mut out_migrations = Migrations::new(DataVersion::new(4, 5));
        out_migrations.add_step (DataVersion::new (4, 4), DataVersion::new (4, 5), Box::new (PersonM44v45{}));

        let in_data = PersonV44{name: "Billy".to_string()};
        let in_vd = VersionedData::new(&in_migrations, &in_data);

        let serialized = serde_cbor::ser::to_vec(&in_vd).unwrap();
        let out_vd = serde_cbor::de::from_slice::<VersionedData<PersonV45>>(&serialized).unwrap();

        let out_data = out_vd.extract(&out_migrations).unwrap();
        assert_eq! (out_data, PersonV45 {
            name: "Billy".to_string(),
            weight: 170
        })
    }
}
