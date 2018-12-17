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
    /*
        `produce`
            the purpose of `produce` is to convert the raw neighborhood from the DB into a Gossip message for a target node
            the Gossip that `produce` returns includes the entire neighborhood, but masks the IP addresses of nodes that
            are not directly connected to `target`. it also filters out connections from any node to any bootstrap_node
        params:
            `database`: the DB that contains the whole neighborhood
            `target`: the node to produce the gossip for
                allows `produce` to determine which ip addrs to mask/reveal, based on which other nodes `target` is connected to (in either direction)
        returns:
            a Gossip message representing the current neighborhood for a target node
    */
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
    use test_utils::test_utils::cryptde;
    use sub_lib::cryptde_null::CryptDENull;
    use test_utils::test_utils::assert_contains;

    #[test]
    #[should_panic(expected="Target node AgMEBQ not in NeighborhoodDatabase")]
    fn produce_fails_for_target_not_in_database() {
        let this_node = make_node_record(1234, true, false);
        let target_node = make_node_record(2345, true, false);
        let database = NeighborhoodDatabase::new(this_node.public_key(), this_node.node_addr_opt().as_ref().unwrap(), this_node.is_bootstrap_node(), cryptde ());

        let subject = GossipProducerReal::new();

        subject.produce(&database, target_node.public_key());
    }

    #[test]
    fn database_produces_gossip_with_standard_gossip_handler_and_well_connected_target () {
        let mut this_node = make_node_record(1234, true, false);
        let mut first_neighbor = make_node_record(2345, true, false);
        let second_neighbor = make_node_record(3456, true, true);
        let mut target = make_node_record (4567, false, false);
        this_node.neighbors_mut().push (first_neighbor.public_key ().clone ());
        this_node.neighbors_mut().push (second_neighbor.public_key ().clone ());
        first_neighbor.neighbors_mut().push (second_neighbor.public_key ().clone ());
        first_neighbor.neighbors_mut().push (target.public_key ().clone ());
        target.neighbors_mut().push (second_neighbor.public_key ().clone ());

        let mut database = NeighborhoodDatabase::new(this_node.public_key(),
                                                     this_node.node_addr_opt().as_ref().unwrap(), this_node.is_bootstrap_node(), &CryptDENull::from(this_node.public_key()));

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

        assert_contains (&result.node_records, &GossipNodeRecord::from(&this_node, false));
        assert_contains (&result.node_records, &GossipNodeRecord::from(&first_neighbor, true));
        assert_contains (&result.node_records, &GossipNodeRecord::from(&second_neighbor, true));
        assert_contains (&result.node_records, &GossipNodeRecord::from(&target, false));
        assert_eq!(result.node_records.len(), 4);
        let neighbor_keys: Vec<(Key, Key)> = result.neighbor_pairs.iter().map(|neighbor_relationship| {
            let from_idx = neighbor_relationship.from;
            let to_idx = neighbor_relationship.to;
            let from_key: Key = result.node_records.get(from_idx as usize).unwrap().inner.public_key.clone();
            let to_key: Key = result.node_records.get(to_idx as usize).unwrap().inner.public_key.clone();
            (from_key, to_key)
        }).collect();
        assert_eq!(neighbor_keys.len(), 2);
        assert_contains (&neighbor_keys, &(this_node.public_key().clone(),
                                            first_neighbor.public_key().clone()));
        assert_contains (&neighbor_keys, &(first_neighbor.public_key().clone(),
                                            target.public_key().clone()));
    }

    #[test]
    fn database_produces_gossip_with_standard_gossip_handler_and_badly_connected_target () {
        let mut this_node = make_node_record(1234, true, false);
        let mut first_neighbor = make_node_record(2345, true, false);
        let second_neighbor = make_node_record(3456, true, true);
        let target = make_node_record (4567, false, false);
        this_node.neighbors_mut().push (first_neighbor.public_key ().clone ());
        this_node.neighbors_mut().push (second_neighbor.public_key ().clone ());
        first_neighbor.neighbors_mut().push (second_neighbor.public_key ().clone ());
        let mut database = NeighborhoodDatabase::new(this_node.public_key(),
                                                     this_node.node_addr_opt().as_ref().unwrap(), this_node.is_bootstrap_node(), &CryptDENull::from(this_node.public_key()));
        database.add_node(&first_neighbor).unwrap();
        database.add_node(&second_neighbor).unwrap();
        database.add_node(&target).unwrap();
        database.add_neighbor(this_node.public_key(), first_neighbor.public_key()).unwrap();
        database.add_neighbor(this_node.public_key(), second_neighbor.public_key()).unwrap();
        database.add_neighbor(first_neighbor.public_key(), second_neighbor.public_key()).unwrap();
        let subject = GossipProducerReal::new();

        let result = subject.produce(&database, target.public_key ());

        assert_contains (&result.node_records, &GossipNodeRecord::from(&this_node, false));
        assert_contains (&result.node_records, &GossipNodeRecord::from(&first_neighbor, false));
        assert_contains (&result.node_records, &GossipNodeRecord::from(&second_neighbor, false));
        assert_contains (&result.node_records, &GossipNodeRecord::from(&target, false));
        assert_eq!(result.node_records.len(), 4);
        let neighbor_keys: Vec<(Key, Key)> = result.neighbor_pairs.iter().map(|neighbor_relationship| {
            let from_idx = neighbor_relationship.from;
            let to_idx = neighbor_relationship.to;
            let from_key: Key = result.node_records.get(from_idx as usize).unwrap().inner.public_key.clone();
            let to_key: Key = result.node_records.get(to_idx as usize).unwrap().inner.public_key.clone();
            (from_key, to_key)
        }).collect();
        assert_eq!(neighbor_keys.len(), 1);
        assert_contains (&neighbor_keys, &(this_node.public_key().clone(), first_neighbor.public_key().clone()));
    }

    #[test]
    fn gossip_producer_filters_out_target_connections_to_bootstrap_nodes() { //but keeps target connections from bootstrap nodes
        let mut this_node = make_node_record(1234, true, false);
        let mut bootstrap = make_node_record(3456, true, true);
        let mut target = make_node_record (4567, false, false);
        this_node.neighbors_mut().push (bootstrap.public_key ().clone ());
        bootstrap.neighbors_mut().push (target.public_key ().clone ());
        target.neighbors_mut().push (bootstrap.public_key ().clone ());
        let mut database = NeighborhoodDatabase::new(this_node.public_key(),
                                                     this_node.node_addr_opt().as_ref().unwrap(), this_node.is_bootstrap_node(), &CryptDENull::from(this_node.public_key()));
        database.add_node(&bootstrap).unwrap();
        database.add_node(&target).unwrap();
        database.add_neighbor(this_node.public_key(), bootstrap.public_key()).unwrap();
        database.add_neighbor (target.public_key (), bootstrap.public_key ()).unwrap ();
        database.add_neighbor (bootstrap.public_key (), target.public_key ()).unwrap ();
        let subject = GossipProducerReal::new();

        let result = subject.produce(&database, target.public_key ());

        assert_contains (&result.node_records, &GossipNodeRecord::from(&this_node, false));
        assert_contains (&result.node_records, &GossipNodeRecord::from(&bootstrap, true));
        assert_contains (&result.node_records, &GossipNodeRecord::from(&target, false));
        assert_eq!(result.node_records.len(), 3);
        let neighbor_keys: Vec<(Key, Key)> = result.neighbor_pairs.iter().map(|neighbor_relationship| {
            let from_idx = neighbor_relationship.from;
            let to_idx = neighbor_relationship.to;
            let from_key: Key = result.node_records.get(from_idx as usize).unwrap().inner.public_key.clone();
            let to_key: Key = result.node_records.get(to_idx as usize).unwrap().inner.public_key.clone();
            (from_key, to_key)
        }).collect();
        assert_eq!(neighbor_keys.contains(&(bootstrap.public_key().clone(),
                                            target.public_key().clone())), true, "{:?}", neighbor_keys);
        assert_eq!(neighbor_keys.len(), 1);

    }

    #[test]
    fn gossip_producer_masks_ip_addrs_for_nodes_not_directly_connected_to_target() {
        let mut this_node = make_node_record(1234, true, false);
        let mut first_neighbor = make_node_record(2345, true, false);
        let second_neighbor = make_node_record(3456, true, false);
        let mut target = make_node_record (4567, false, false);
        this_node.neighbors_mut().push (first_neighbor.public_key().clone ());
        this_node.neighbors_mut().push (second_neighbor.public_key().clone ());
        first_neighbor.neighbors_mut().push(second_neighbor.public_key().clone ());
        first_neighbor.neighbors_mut().push(target.public_key().clone ());
        target.neighbors_mut().push (second_neighbor.public_key ().clone ());
        let mut database = NeighborhoodDatabase::new(this_node.public_key(),
                                                     this_node.node_addr_opt().as_ref().unwrap(), this_node.is_bootstrap_node(), &CryptDENull::from(this_node.public_key()));
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

        assert_contains (&result.node_records, &GossipNodeRecord::from(&this_node, false));
        assert_contains (&result.node_records, &GossipNodeRecord::from(&first_neighbor, true));
        assert_contains (&result.node_records, &GossipNodeRecord::from(&second_neighbor, true));
        assert_contains (&result.node_records, &GossipNodeRecord::from(&target, false));
        assert_eq!(result.node_records.len(), 4);
        let neighbor_connections: Vec<(GossipNodeRecord, GossipNodeRecord)> = result.neighbor_pairs.iter().map(|neighbor_relationship| {
            let from_idx = neighbor_relationship.from;
            let to_idx = neighbor_relationship.to;
            let from: GossipNodeRecord = result.node_records.get(from_idx as usize).unwrap().clone();
            let to: GossipNodeRecord = result.node_records.get(to_idx as usize).unwrap().clone();
            (from, to)
        }).collect();

        assert_contains (&neighbor_connections, &(GossipNodeRecord::from(&first_neighbor, true),
                                                     GossipNodeRecord::from(&target, false)));
        assert_contains (&neighbor_connections, &(GossipNodeRecord::from(&target, false),
                                                     GossipNodeRecord::from(&second_neighbor, true)));

        assert_contains (&neighbor_connections, &(GossipNodeRecord::from(&this_node, false), // node_addr of this_node is not revealed for target
                                                   GossipNodeRecord::from(&first_neighbor, true)));

        assert_contains (&neighbor_connections, &(GossipNodeRecord::from(&this_node, false),
                                                   GossipNodeRecord::from(&second_neighbor, true)));
        assert_contains (&neighbor_connections, &(GossipNodeRecord::from(&first_neighbor, true),
                                                   GossipNodeRecord::from(&second_neighbor, true)));
        assert_eq!(neighbor_connections.len(), 5);
    }
}