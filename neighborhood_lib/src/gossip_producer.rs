// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use gossip::Gossip;
use sub_lib::cryptde::Key;
use neighborhood_database::NeighborhoodDatabase;
use gossip::GossipBuilder;
use sub_lib::logger::Logger;

pub trait GossipProducer {
    fn produce (&self, database: &NeighborhoodDatabase, target: &Key) -> Gossip;
}

pub struct GossipProducerReal {
    _logger: Logger,
}

impl GossipProducer for GossipProducerReal {

    fn produce(&self, database: &NeighborhoodDatabase, target: &Key) -> Gossip {
        let target_node_ref = match database.node_by_key (target) {
            Some (node_ref) => node_ref,
            None => panic! ("Target node {:?} not in NeighborhoodDatabase", target)
        };
        let builder = database.keys ().into_iter ()
            .fold (GossipBuilder::new (), |so_far, key_ref| {
                let node_record_ref = database.node_by_key (key_ref).expect ("Key magically disappeared");
                let reveal_node_addr = node_record_ref.has_neighbor (target_node_ref.public_key ()) || target_node_ref.has_neighbor (node_record_ref.public_key ());
                so_far.node (node_record_ref, reveal_node_addr)
            });
        let builder = database.keys ().into_iter ().fold (builder, |so_far_outer, key_ref| {
            database.node_by_key (key_ref).expect ("Key magically disappeared").neighbors ().iter ()
                .filter(|neighbor| !database.node_by_key(neighbor).expect("Key magically disappeared").is_bootstrap_node())
                .fold (so_far_outer, |so_far_inner, neighbor_ref| {
                so_far_inner.neighbor_pair (key_ref, neighbor_ref)
            })
        });
        builder.build ()
    }
}

impl GossipProducerReal {
    pub fn new() -> GossipProducerReal {
        GossipProducerReal { _logger: Logger::new ("GossipProducerReal") }
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use neighborhood_test_utils::*;
    use gossip::GossipNodeRecord;

    #[test]
    #[should_panic(expected="Target node AgMEBQ not in NeighborhoodDatabase")]
    fn produce_fails_for_target_not_in_database() {
        let this_node = make_node_record(1234, true, false);
        let target_node = make_node_record(2345, true, false);
        let database = NeighborhoodDatabase::new(this_node.public_key(), this_node.node_addr_opt().as_ref().unwrap(), this_node.is_bootstrap_node());

        let subject = GossipProducerReal::new();

        subject.produce(&database, target_node.public_key());
    }

    #[test]
    fn database_produces_gossip_with_standard_gossip_handler_and_well_connected_target () {
        let this_node = make_node_record(1234, true, false);
        let first_neighbor = make_node_record(2345, true, false);
        let second_neighbor = make_node_record(3456, true, true);
        let target = make_node_record (4567, false, false);
        let mut database = NeighborhoodDatabase::new(this_node.public_key(),
                                                     this_node.node_addr_opt().as_ref().unwrap(), this_node.is_bootstrap_node());
        database.add_node(&first_neighbor).unwrap();
        database.add_node(&second_neighbor).unwrap();
        database.add_node(&target).unwrap();
        database.add_neighbor(this_node.public_key(), first_neighbor.public_key()).unwrap();
        database.add_neighbor(this_node.public_key(), second_neighbor.public_key()).unwrap();
        database.add_neighbor(first_neighbor.public_key(), second_neighbor.public_key()).unwrap();
        database.add_neighbor(first_neighbor.public_key (), target.public_key ()).unwrap ();
        database.add_neighbor (target.public_key (), second_neighbor.public_key ()).unwrap ();
        let subject = GossipProducerReal::new();

        let result = subject.produce(&database, target.public_key ());

        assert_eq!(result.node_records.contains(&GossipNodeRecord::from(&this_node, false)), true, "{:?}", result.node_records);
        assert_eq!(result.node_records.contains(&GossipNodeRecord::from(&first_neighbor, true)), true, "{:?}", result.node_records);
        assert_eq!(result.node_records.contains(&GossipNodeRecord::from(&second_neighbor, true)), true, "{:?}", result.node_records);
        assert_eq!(result.node_records.contains(&GossipNodeRecord::from(&target, false)), true, "{:?}", result.node_records);
        assert_eq!(result.node_records.len(), 4);
        let neighbor_keys: Vec<(Key, Key)> = result.neighbor_pairs.iter().map(|neighbor_relationship| {
            let from_idx = neighbor_relationship.from;
            let to_idx = neighbor_relationship.to;
            let from_key: Key = result.node_records.get(from_idx as usize).unwrap().public_key.clone();
            let to_key: Key = result.node_records.get(to_idx as usize).unwrap().public_key.clone();
            (from_key, to_key)
        }).collect();
        assert_eq!(neighbor_keys.contains(&(this_node.public_key().clone(),
                                            first_neighbor.public_key().clone())), true, "{:?}", neighbor_keys);
        assert_eq!(neighbor_keys.contains(&(first_neighbor.public_key().clone(),
                                            target.public_key().clone())), true, "{:?}", neighbor_keys);
        assert_eq!(neighbor_keys.len(), 2);
    }

    #[test]
    fn database_produces_gossip_with_standard_gossip_handler_and_badly_connected_target () {
        let this_node = make_node_record(1234, true, false);
        let first_neighbor = make_node_record(2345, true, false);
        let second_neighbor = make_node_record(3456, true, true);
        let target = make_node_record (4567, false, false);
        let mut database = NeighborhoodDatabase::new(this_node.public_key(),
                                                     this_node.node_addr_opt().as_ref().unwrap(), this_node.is_bootstrap_node());
        database.add_node(&first_neighbor).unwrap();
        database.add_node(&second_neighbor).unwrap();
        database.add_node(&target).unwrap();
        database.add_neighbor(this_node.public_key(), first_neighbor.public_key()).unwrap();
        database.add_neighbor(this_node.public_key(), second_neighbor.public_key()).unwrap();
        database.add_neighbor(first_neighbor.public_key(), second_neighbor.public_key()).unwrap();
        let subject = GossipProducerReal::new();

        let result = subject.produce(&database, target.public_key ());

        assert_eq!(result.node_records.contains(&GossipNodeRecord::from(&this_node, false)), true, "{:?}", result.node_records);
        assert_eq!(result.node_records.contains(&GossipNodeRecord::from(&first_neighbor, false)), true, "{:?}", result.node_records);
        assert_eq!(result.node_records.contains(&GossipNodeRecord::from(&second_neighbor, false)), true, "{:?}", result.node_records);
        assert_eq!(result.node_records.contains(&GossipNodeRecord::from(&target, false)), true, "{:?}", result.node_records);
        assert_eq!(result.node_records.len(), 4);
        let neighbor_keys: Vec<(Key, Key)> = result.neighbor_pairs.iter().map(|neighbor_relationship| {
            let from_idx = neighbor_relationship.from;
            let to_idx = neighbor_relationship.to;
            let from_key: Key = result.node_records.get(from_idx as usize).unwrap().public_key.clone();
            let to_key: Key = result.node_records.get(to_idx as usize).unwrap().public_key.clone();
            (from_key, to_key)
        }).collect();
        assert_eq!(neighbor_keys.contains(&(this_node.public_key().clone(),
                                            first_neighbor.public_key().clone())), true, "{:?}", neighbor_keys);
        assert_eq!(neighbor_keys.len(), 1);
    }
}