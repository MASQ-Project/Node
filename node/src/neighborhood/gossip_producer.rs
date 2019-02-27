// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use super::gossip::to_dot_graph;
use super::gossip::Gossip;
use super::gossip::GossipBuilder;
use super::neighborhood_database::NeighborhoodDatabase;
use super::neighborhood_database::NodeRecord;
use sub_lib::cryptde::PublicKey;
use sub_lib::logger::Logger;

static MINIMUM_NEIGHBORS: usize = 3;

pub trait GossipProducer {
    fn produce(&self, database: &NeighborhoodDatabase, target: &PublicKey) -> Gossip;
}

pub struct GossipProducerReal {
    logger: Logger,
}

impl GossipProducer for GossipProducerReal {
    /*
        `produce`
            the purpose of `produce` is to convert the raw neighborhood from the DB into a Gossip message for a target node
            the Gossip that `produce` returns includes the entire neighborhood, but masks the IP addresses of nodes that
            are not directly connected to `target`.
        params:
            `database`: the DB that contains the whole neighborhood
            `target`: the node to produce the gossip for
                allows `produce` to determine which ip addrs to mask/reveal, based on which other nodes `target` is connected to (in either direction)
        returns:
            a Gossip message representing the current neighborhood for a target node
    */
    fn produce(&self, database: &NeighborhoodDatabase, target: &PublicKey) -> Gossip {
        let target_node_ref = match database.node_by_key(target) {
            Some(node_ref) => node_ref,
            None => panic!("Target node {:?} not in NeighborhoodDatabase", target),
        };

        let introducees = self.choose_introductions(database, target_node_ref);
        let builder = database
            .keys()
            .into_iter()
            .fold(GossipBuilder::new(), |so_far, key_ref| {
                let node_record_ref = database
                    .node_by_key(key_ref)
                    .expect("Key magically disappeared");
                let reveal_node_addr = node_record_ref.has_neighbor(target_node_ref.public_key())
                    || target_node_ref.has_neighbor(node_record_ref.public_key())
                    || introducees.contains(&key_ref);
                so_far.node(node_record_ref, reveal_node_addr)
            });
        let gossip = builder.build();
        self.logger.trace(format!(
            "Created Gossip: {}",
            to_dot_graph(gossip.clone(), target, database.root().public_key().clone())
        ));
        gossip
    }
}

impl GossipProducerReal {
    pub fn new() -> GossipProducerReal {
        GossipProducerReal {
            logger: Logger::new("GossipProducerReal"),
        }
    }

    pub fn choose_introductions<'a>(
        &self,
        database: &'a NeighborhoodDatabase,
        target: &NodeRecord,
    ) -> Vec<&'a PublicKey> {
        let target_standard_neighbors = target
            .neighbors()
            .iter()
            .filter(|key| match database.node_by_key(key) {
                Some(node) => !node.is_bootstrap_node(),
                None => unimplemented!(), // we don't know this node, so we should assume it is not a bootstrap node
            })
            .count();

        if !target.is_bootstrap_node()
            && database.root().neighbors().contains(target.public_key())
            && target_standard_neighbors < MINIMUM_NEIGHBORS
        {
            let mut possible_introducees: Vec<&PublicKey> = database
                .root()
                .neighbors()
                .iter()
                .filter(|key| !target.neighbors().contains(key))
                .filter(|key| target.public_key() != *key)
                .filter(|key| {
                    !database
                        .node_by_key(key)
                        .expect("Key magically disappeared")
                        .is_bootstrap_node()
                })
                .collect();

            possible_introducees.sort_by(|l, r| {
                database
                    .node_by_key(l)
                    .expect("Key magically disappeared")
                    .neighbors()
                    .len()
                    .cmp(
                        &database
                            .node_by_key(r)
                            .expect("Key magically disappeared")
                            .neighbors()
                            .len(),
                    )
            });

            possible_introducees
                .into_iter()
                .take(MINIMUM_NEIGHBORS - target_standard_neighbors)
                .collect()
        } else {
            vec![]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::gossip::GossipNodeRecord;
    use super::super::neighborhood_test_utils::*;
    use super::*;
    use sub_lib::cryptde_null::CryptDENull;
    use test_utils::logging::init_test_logging;
    use test_utils::logging::TestLogHandler;
    use test_utils::test_utils::assert_contains;
    use test_utils::test_utils::cryptde;

    #[test]
    #[should_panic(expected = "Target node AgMEBQ not in NeighborhoodDatabase")]
    fn produce_fails_for_target_not_in_database() {
        let this_node = make_node_record(1234, true, false);
        let target_node = make_node_record(2345, true, false);
        let database = NeighborhoodDatabase::new(
            this_node.public_key(),
            this_node.node_addr_opt().as_ref().unwrap(),
            this_node.earning_wallet(),
            this_node.consuming_wallet(),
            this_node.is_bootstrap_node(),
            cryptde(),
        );

        let subject = GossipProducerReal::new();

        subject.produce(&database, target_node.public_key());
    }

    #[test]
    fn database_produces_gossip_with_standard_gossip_handler_and_well_connected_target() {
        let mut this_node = make_node_record(1234, true, false);
        let mut first_neighbor = make_node_record(2345, true, false);
        let second_neighbor = make_node_record(3456, true, true);
        let mut target = make_node_record(4567, false, false);
        this_node
            .neighbors_mut()
            .push(first_neighbor.public_key().clone());
        this_node
            .neighbors_mut()
            .push(second_neighbor.public_key().clone());
        first_neighbor
            .neighbors_mut()
            .push(second_neighbor.public_key().clone());
        first_neighbor
            .neighbors_mut()
            .push(target.public_key().clone());
        target
            .neighbors_mut()
            .push(second_neighbor.public_key().clone());

        let mut database = NeighborhoodDatabase::new(
            this_node.public_key(),
            this_node.node_addr_opt().as_ref().unwrap(),
            this_node.earning_wallet(),
            this_node.consuming_wallet(),
            this_node.is_bootstrap_node(),
            &CryptDENull::from(this_node.public_key()),
        );

        database.add_node(&first_neighbor).unwrap();
        database.add_node(&second_neighbor).unwrap();
        database.add_node(&target).unwrap();
        database
            .add_neighbor(this_node.public_key(), first_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(this_node.public_key(), second_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(first_neighbor.public_key(), second_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(first_neighbor.public_key(), target.public_key())
            .unwrap();
        database
            .add_neighbor(target.public_key(), second_neighbor.public_key())
            .unwrap();
        let subject = GossipProducerReal::new();

        let result = subject.produce(&database, target.public_key());

        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&this_node, false),
        );
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&first_neighbor, true),
        );
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&second_neighbor, true),
        );
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&target, false),
        );
        assert_eq!(result.node_records.len(), 4);
    }

    #[test]
    fn database_produces_gossip_with_badly_connected_target() {
        let mut this_node = make_node_record(1234, true, false);
        let mut first_neighbor = make_node_record(2345, true, false);
        let second_neighbor = make_node_record(3456, true, true);
        let target = make_node_record(4567, false, false);
        this_node
            .neighbors_mut()
            .push(first_neighbor.public_key().clone());
        this_node
            .neighbors_mut()
            .push(second_neighbor.public_key().clone());
        first_neighbor
            .neighbors_mut()
            .push(second_neighbor.public_key().clone());
        let mut database = NeighborhoodDatabase::new(
            this_node.public_key(),
            this_node.node_addr_opt().as_ref().unwrap(),
            this_node.earning_wallet(),
            this_node.consuming_wallet(),
            this_node.is_bootstrap_node(),
            &CryptDENull::from(this_node.public_key()),
        );
        database.add_node(&first_neighbor).unwrap();
        database.add_node(&second_neighbor).unwrap();
        database.add_node(&target).unwrap();
        database
            .add_neighbor(this_node.public_key(), first_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(this_node.public_key(), second_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(first_neighbor.public_key(), second_neighbor.public_key())
            .unwrap();
        let subject = GossipProducerReal::new();

        let result = subject.produce(&database, target.public_key());

        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&this_node, false),
        );
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&first_neighbor, false),
        );
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&second_neighbor, false),
        );
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&target, false),
        );
        assert_eq!(result.node_records.len(), 4);
    }

    #[test]
    fn gossip_producer_filters_out_target_connections_to_bootstrap_nodes() {
        //but keeps target connections from bootstrap nodes
        let mut this_node = make_node_record(1234, true, false);
        let mut bootstrap = make_node_record(3456, true, true);
        let mut target = make_node_record(4567, false, false);
        this_node
            .neighbors_mut()
            .push(bootstrap.public_key().clone());
        bootstrap.neighbors_mut().push(target.public_key().clone());
        target.neighbors_mut().push(bootstrap.public_key().clone());
        let mut database = NeighborhoodDatabase::new(
            this_node.public_key(),
            this_node.node_addr_opt().as_ref().unwrap(),
            this_node.earning_wallet(),
            this_node.consuming_wallet(),
            this_node.is_bootstrap_node(),
            &CryptDENull::from(this_node.public_key()),
        );
        database.add_node(&bootstrap).unwrap();
        database.add_node(&target).unwrap();
        database
            .add_neighbor(this_node.public_key(), bootstrap.public_key())
            .unwrap();
        database
            .add_neighbor(target.public_key(), bootstrap.public_key())
            .unwrap();
        database
            .add_neighbor(bootstrap.public_key(), target.public_key())
            .unwrap();
        let subject = GossipProducerReal::new();

        let result = subject.produce(&database, target.public_key());

        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&this_node, false),
        );
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&bootstrap, true),
        );
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&target, false),
        );
        assert_eq!(result.node_records.len(), 3);
    }

    #[test]
    fn gossip_producer_masks_ip_addrs_for_nodes_not_directly_connected_to_target() {
        let mut this_node = make_node_record(1234, true, false);
        let mut first_neighbor = make_node_record(2345, true, false);
        let second_neighbor = make_node_record(3456, true, false);
        let mut target = make_node_record(4567, false, false);
        this_node
            .neighbors_mut()
            .push(first_neighbor.public_key().clone());
        this_node
            .neighbors_mut()
            .push(second_neighbor.public_key().clone());
        first_neighbor
            .neighbors_mut()
            .push(second_neighbor.public_key().clone());
        first_neighbor
            .neighbors_mut()
            .push(target.public_key().clone());
        target
            .neighbors_mut()
            .push(second_neighbor.public_key().clone());
        let mut database = NeighborhoodDatabase::new(
            this_node.public_key(),
            this_node.node_addr_opt().as_ref().unwrap(),
            this_node.earning_wallet(),
            this_node.consuming_wallet(),
            this_node.is_bootstrap_node(),
            &CryptDENull::from(this_node.public_key()),
        );
        database.add_node(&first_neighbor).unwrap();
        database.add_node(&second_neighbor).unwrap();
        database.add_node(&target).unwrap();
        database
            .add_neighbor(this_node.public_key(), first_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(this_node.public_key(), second_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(first_neighbor.public_key(), second_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(first_neighbor.public_key(), target.public_key())
            .unwrap();
        database
            .add_neighbor(target.public_key(), second_neighbor.public_key())
            .unwrap();
        let subject = GossipProducerReal::new();

        let result = subject.produce(&database, target.public_key());

        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&this_node, false),
        );
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&first_neighbor, true),
        );
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&second_neighbor, true),
        );
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&target, false),
        );
        assert_eq!(result.node_records.len(), 4);
    }

    #[test]
    fn gossip_producer_reveals_ip_addr_to_introduce_target_to_more_nodes() {
        let mut this_node = make_node_record(1234, true, false);
        let mut first_neighbor = make_node_record(2345, true, false);
        let mut second_neighbor = make_node_record(3456, true, false);
        let mut target = make_node_record(4567, true, false);
        this_node
            .neighbors_mut()
            .push(first_neighbor.public_key().clone());
        this_node
            .neighbors_mut()
            .push(second_neighbor.public_key().clone());
        this_node.neighbors_mut().push(target.public_key().clone());
        first_neighbor
            .neighbors_mut()
            .push(this_node.public_key().clone());
        first_neighbor
            .neighbors_mut()
            .push(second_neighbor.public_key().clone());
        second_neighbor
            .neighbors_mut()
            .push(first_neighbor.public_key().clone());
        second_neighbor
            .neighbors_mut()
            .push(this_node.public_key().clone());
        target.neighbors_mut().push(this_node.public_key().clone());
        let mut database = NeighborhoodDatabase::new(
            this_node.public_key(),
            this_node.node_addr_opt().as_ref().unwrap(),
            this_node.earning_wallet(),
            this_node.consuming_wallet(),
            this_node.is_bootstrap_node(),
            &CryptDENull::from(this_node.public_key()),
        );
        database.add_node(&first_neighbor).unwrap();
        database.add_node(&second_neighbor).unwrap();
        database.add_node(&target).unwrap();
        database
            .add_neighbor(this_node.public_key(), first_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(first_neighbor.public_key(), this_node.public_key())
            .unwrap();
        database
            .add_neighbor(this_node.public_key(), second_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(second_neighbor.public_key(), this_node.public_key())
            .unwrap();
        database
            .add_neighbor(first_neighbor.public_key(), second_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(second_neighbor.public_key(), first_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(this_node.public_key(), target.public_key())
            .unwrap();
        database
            .add_neighbor(target.public_key(), this_node.public_key())
            .unwrap();

        let subject = GossipProducerReal::new();

        let result = subject.produce(&database, target.public_key());

        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&first_neighbor, true),
        );
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&this_node, true),
        );
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&second_neighbor, true),
        );
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&target, false),
        );
        assert_eq!(result.node_records.len(), 4);
    }

    #[test]
    fn gossip_producer_does_not_introduce_bootstrap_target_to_more_nodes() {
        let mut this_node = make_node_record(1234, true, false);
        let mut first_neighbor = make_node_record(2345, true, false);
        let mut second_neighbor = make_node_record(3456, true, false);
        let mut target = make_node_record(4567, true, true);
        this_node
            .neighbors_mut()
            .push(first_neighbor.public_key().clone());
        this_node
            .neighbors_mut()
            .push(second_neighbor.public_key().clone());
        this_node.neighbors_mut().push(target.public_key().clone());
        first_neighbor
            .neighbors_mut()
            .push(this_node.public_key().clone());
        first_neighbor
            .neighbors_mut()
            .push(second_neighbor.public_key().clone());
        second_neighbor
            .neighbors_mut()
            .push(first_neighbor.public_key().clone());
        second_neighbor
            .neighbors_mut()
            .push(this_node.public_key().clone());
        target.neighbors_mut().push(this_node.public_key().clone());
        let mut database = NeighborhoodDatabase::new(
            this_node.public_key(),
            this_node.node_addr_opt().as_ref().unwrap(),
            this_node.earning_wallet(),
            this_node.consuming_wallet(),
            this_node.is_bootstrap_node(),
            &CryptDENull::from(this_node.public_key()),
        );
        database.add_node(&first_neighbor).unwrap();
        database.add_node(&second_neighbor).unwrap();
        database.add_node(&target).unwrap();
        database
            .add_neighbor(this_node.public_key(), first_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(first_neighbor.public_key(), this_node.public_key())
            .unwrap();
        database
            .add_neighbor(this_node.public_key(), second_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(second_neighbor.public_key(), this_node.public_key())
            .unwrap();
        database
            .add_neighbor(first_neighbor.public_key(), second_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(second_neighbor.public_key(), first_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(this_node.public_key(), target.public_key())
            .unwrap();
        database
            .add_neighbor(target.public_key(), this_node.public_key())
            .unwrap();

        let subject = GossipProducerReal::new();

        let result = subject.produce(&database, target.public_key());

        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&this_node, true),
        );
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&first_neighbor, false),
        );
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&second_neighbor, false),
        );
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&target, false),
        );
        assert_eq!(result.node_records.len(), 4);
    }

    #[test]
    fn gossip_producer_makes_introductions_based_on_targets_number_of_connections_to_standard_nodes_only(
    ) {
        let mut this_node = make_node_record(1234, true, false);
        let mut first_neighbor = make_node_record(2345, true, false);
        let mut second_neighbor = make_node_record(3456, true, false);
        let first_bootstrap = make_node_record(5678, false, true);
        let second_bootstrap = make_node_record(6789, false, true);
        let third_bootstrap = make_node_record(7890, false, true);
        let mut target = make_node_record(4567, true, false);
        this_node
            .neighbors_mut()
            .push(first_neighbor.public_key().clone());
        this_node
            .neighbors_mut()
            .push(second_neighbor.public_key().clone());
        this_node.neighbors_mut().push(target.public_key().clone());
        first_neighbor
            .neighbors_mut()
            .push(this_node.public_key().clone());
        first_neighbor
            .neighbors_mut()
            .push(second_neighbor.public_key().clone());
        second_neighbor
            .neighbors_mut()
            .push(first_neighbor.public_key().clone());
        second_neighbor
            .neighbors_mut()
            .push(this_node.public_key().clone());
        target.neighbors_mut().push(this_node.public_key().clone());
        target
            .neighbors_mut()
            .push(first_bootstrap.public_key().clone());
        target
            .neighbors_mut()
            .push(second_bootstrap.public_key().clone());
        target
            .neighbors_mut()
            .push(third_bootstrap.public_key().clone());
        let mut database = NeighborhoodDatabase::new(
            this_node.public_key(),
            this_node.node_addr_opt().as_ref().unwrap(),
            this_node.earning_wallet(),
            this_node.consuming_wallet(),
            this_node.is_bootstrap_node(),
            &CryptDENull::from(this_node.public_key()),
        );
        database.add_node(&first_neighbor).unwrap();
        database.add_node(&second_neighbor).unwrap();
        database.add_node(&target).unwrap();
        database.add_node(&first_bootstrap).unwrap();
        database.add_node(&second_bootstrap).unwrap();
        database.add_node(&third_bootstrap).unwrap();
        database
            .add_neighbor(this_node.public_key(), first_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(first_neighbor.public_key(), this_node.public_key())
            .unwrap();
        database
            .add_neighbor(this_node.public_key(), second_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(second_neighbor.public_key(), this_node.public_key())
            .unwrap();
        database
            .add_neighbor(first_neighbor.public_key(), second_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(second_neighbor.public_key(), first_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(this_node.public_key(), target.public_key())
            .unwrap();
        database
            .add_neighbor(target.public_key(), this_node.public_key())
            .unwrap();
        database
            .add_neighbor(target.public_key(), first_bootstrap.public_key())
            .unwrap();
        database
            .add_neighbor(target.public_key(), second_bootstrap.public_key())
            .unwrap();
        database
            .add_neighbor(target.public_key(), third_bootstrap.public_key())
            .unwrap();

        let subject = GossipProducerReal::new();

        let result = subject.produce(&database, target.public_key());

        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&this_node, true),
        );
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&first_neighbor, true),
        );
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&second_neighbor, true),
        );
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&target, false),
        );
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&first_bootstrap, false),
        );
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&second_bootstrap, false),
        );
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&third_bootstrap, false),
        );
        assert_eq!(result.node_records.len(), 7);
    }

    #[test]
    fn gossip_producer_introduces_target_to_less_connected_neighbors() {
        let mut this_node = make_node_record(1234, true, false);
        let mut first_neighbor = make_node_record(2345, true, false);
        let mut second_neighbor = make_node_record(3456, true, false);
        let mut target = make_node_record(4567, true, false);
        let target_neighbor = make_node_record(5678, true, false);
        this_node
            .neighbors_mut()
            .push(first_neighbor.public_key().clone());
        this_node
            .neighbors_mut()
            .push(target_neighbor.public_key().clone());
        this_node
            .neighbors_mut()
            .push(second_neighbor.public_key().clone());
        this_node.neighbors_mut().push(target.public_key().clone());
        first_neighbor
            .neighbors_mut()
            .push(this_node.public_key().clone());
        first_neighbor
            .neighbors_mut()
            .push(second_neighbor.public_key().clone());
        first_neighbor
            .neighbors_mut()
            .push(target_neighbor.public_key().clone());
        second_neighbor
            .neighbors_mut()
            .push(first_neighbor.public_key().clone());
        second_neighbor
            .neighbors_mut()
            .push(this_node.public_key().clone());
        target.neighbors_mut().push(this_node.public_key().clone());
        target
            .neighbors_mut()
            .push(target_neighbor.public_key().clone());

        let mut database = NeighborhoodDatabase::new(
            this_node.public_key(),
            this_node.node_addr_opt().as_ref().unwrap(),
            this_node.earning_wallet(),
            this_node.consuming_wallet(),
            this_node.is_bootstrap_node(),
            &CryptDENull::from(this_node.public_key()),
        );
        database.add_node(&first_neighbor).unwrap();
        database.add_node(&second_neighbor).unwrap();
        database.add_node(&target).unwrap();
        database.add_node(&target_neighbor).unwrap();
        database
            .add_neighbor(this_node.public_key(), first_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(this_node.public_key(), target_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(first_neighbor.public_key(), this_node.public_key())
            .unwrap();
        database
            .add_neighbor(first_neighbor.public_key(), target_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(this_node.public_key(), second_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(second_neighbor.public_key(), this_node.public_key())
            .unwrap();
        database
            .add_neighbor(first_neighbor.public_key(), second_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(second_neighbor.public_key(), first_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(this_node.public_key(), target.public_key())
            .unwrap();
        database
            .add_neighbor(target.public_key(), this_node.public_key())
            .unwrap();
        database
            .add_neighbor(target.public_key(), target_neighbor.public_key())
            .unwrap();

        let subject = GossipProducerReal::new();

        let result = subject.produce(&database, target.public_key());

        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&this_node, true),
        );
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&first_neighbor, false),
        ); // this is the introduction because first_neighbor has fewer connections than second_neighbor
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&second_neighbor, true),
        );
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&target, false),
        );
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&target_neighbor, true),
        );
        assert_eq!(result.node_records.len(), 5);
    }

    #[test]
    fn gossip_producer_does_not_introduce_target_to_bootstrap_nodes() {
        let mut this_node = make_node_record(1234, true, false);
        let mut first_neighbor = make_node_record(2345, true, false);
        let mut second_neighbor = make_node_record(3456, true, true);
        let mut target = make_node_record(4567, true, false);
        this_node
            .neighbors_mut()
            .push(first_neighbor.public_key().clone());
        this_node
            .neighbors_mut()
            .push(second_neighbor.public_key().clone());
        this_node.neighbors_mut().push(target.public_key().clone());
        first_neighbor
            .neighbors_mut()
            .push(this_node.public_key().clone());
        first_neighbor
            .neighbors_mut()
            .push(second_neighbor.public_key().clone());
        second_neighbor
            .neighbors_mut()
            .push(first_neighbor.public_key().clone());
        second_neighbor
            .neighbors_mut()
            .push(this_node.public_key().clone());
        target.neighbors_mut().push(this_node.public_key().clone());
        let mut database = NeighborhoodDatabase::new(
            this_node.public_key(),
            this_node.node_addr_opt().as_ref().unwrap(),
            this_node.earning_wallet(),
            this_node.consuming_wallet(),
            this_node.is_bootstrap_node(),
            &CryptDENull::from(this_node.public_key()),
        );
        database.add_node(&first_neighbor).unwrap();
        database.add_node(&second_neighbor).unwrap();
        database.add_node(&target).unwrap();
        database
            .add_neighbor(this_node.public_key(), first_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(first_neighbor.public_key(), this_node.public_key())
            .unwrap();
        database
            .add_neighbor(this_node.public_key(), second_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(second_neighbor.public_key(), this_node.public_key())
            .unwrap();
        database
            .add_neighbor(first_neighbor.public_key(), second_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(second_neighbor.public_key(), first_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(this_node.public_key(), target.public_key())
            .unwrap();
        database
            .add_neighbor(target.public_key(), this_node.public_key())
            .unwrap();

        let subject = GossipProducerReal::new();

        let result = subject.produce(&database, target.public_key());

        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&this_node, true),
        );
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&first_neighbor, true),
        );
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&second_neighbor, false),
        );
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&target, false),
        );
        assert_eq!(result.node_records.len(), 4);
    }

    #[test]
    fn gossip_producer_does_not_introduce_target_to_more_nodes_than_it_needs() {
        let mut this_node = make_node_record(1234, true, false);
        let mut first_neighbor = make_node_record(2345, true, false);
        let mut second_neighbor = make_node_record(3456, true, false);
        let mut target = make_node_record(4567, true, false);
        let target_neighbor = make_node_record(5678, true, false);
        this_node
            .neighbors_mut()
            .push(first_neighbor.public_key().clone());
        this_node
            .neighbors_mut()
            .push(second_neighbor.public_key().clone());
        this_node
            .neighbors_mut()
            .push(target_neighbor.public_key().clone());
        this_node.neighbors_mut().push(target.public_key().clone());
        first_neighbor
            .neighbors_mut()
            .push(this_node.public_key().clone());
        first_neighbor
            .neighbors_mut()
            .push(second_neighbor.public_key().clone());
        second_neighbor
            .neighbors_mut()
            .push(first_neighbor.public_key().clone());
        second_neighbor
            .neighbors_mut()
            .push(this_node.public_key().clone());
        target.neighbors_mut().push(this_node.public_key().clone());
        target
            .neighbors_mut()
            .push(target_neighbor.public_key().clone());
        let mut database = NeighborhoodDatabase::new(
            this_node.public_key(),
            this_node.node_addr_opt().as_ref().unwrap(),
            this_node.earning_wallet(),
            this_node.consuming_wallet(),
            this_node.is_bootstrap_node(),
            &CryptDENull::from(this_node.public_key()),
        );
        database.add_node(&first_neighbor).unwrap();
        database.add_node(&second_neighbor).unwrap();
        database.add_node(&target).unwrap();
        database.add_node(&target_neighbor).unwrap();
        database
            .add_neighbor(this_node.public_key(), first_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(first_neighbor.public_key(), this_node.public_key())
            .unwrap();
        database
            .add_neighbor(this_node.public_key(), second_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(second_neighbor.public_key(), this_node.public_key())
            .unwrap();
        database
            .add_neighbor(this_node.public_key(), target_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(first_neighbor.public_key(), second_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(second_neighbor.public_key(), first_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(this_node.public_key(), target.public_key())
            .unwrap();
        database
            .add_neighbor(target.public_key(), this_node.public_key())
            .unwrap();
        database
            .add_neighbor(target.public_key(), target_neighbor.public_key())
            .unwrap();

        let subject = GossipProducerReal::new();

        let result = subject.produce(&database, target.public_key());

        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&this_node, true),
        );
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&target, false),
        );
        assert_contains(
            &result.node_records,
            &GossipNodeRecord::from(&target_neighbor, true),
        );

        // first_neighbor and second_neighbor have the same number of connections, so choosing which to introduce is non-deterministic
        let first_neighbor_gossip = result
            .node_records
            .iter()
            .filter(|gnr| gnr.inner.public_key == *first_neighbor.public_key())
            .next()
            .unwrap();
        let second_neighbor_gossip = result
            .node_records
            .iter()
            .filter(|gnr| gnr.inner.public_key == *second_neighbor.public_key())
            .next()
            .unwrap();
        assert_ne!(
            first_neighbor_gossip.inner.node_addr_opt.is_some(),
            second_neighbor_gossip.inner.node_addr_opt.is_some(),
            "exactly one neighbor should be introduced (both or neither actually were)"
        );

        assert_eq!(result.node_records.len(), 5);
    }

    // TODO test about assuming that unknown target neighbors are not bootstrap when deciding how many introductions to make
    // ^^^ (not possible to set up yet because we can't add_neighbor a key for target that we don't already have in the DB as a NodeRecord)
    // This test will drive out the unimplemented!() in choose_introducees

    #[test]
    fn produce_logs_about_the_resulting_gossip() {
        init_test_logging();
        let this_node = make_node_record(1234, true, true);
        let first_neighbor = make_node_record(2345, true, false);
        let target = make_node_record(4567, true, false);
        let mut database = NeighborhoodDatabase::new(
            this_node.public_key(),
            this_node.node_addr_opt().as_ref().unwrap(),
            this_node.earning_wallet(),
            this_node.consuming_wallet(),
            this_node.is_bootstrap_node(),
            &CryptDENull::from(this_node.public_key()),
        );
        database.add_node(&first_neighbor).unwrap();
        database.add_node(&target).unwrap();
        database
            .add_neighbor(this_node.public_key(), first_neighbor.public_key())
            .unwrap();
        database
            .add_neighbor(first_neighbor.public_key(), this_node.public_key())
            .unwrap();
        database
            .add_neighbor(first_neighbor.public_key(), target.public_key())
            .unwrap();
        database
            .add_neighbor(this_node.public_key(), target.public_key())
            .unwrap();
        database
            .add_neighbor(target.public_key(), this_node.public_key())
            .unwrap();
        database
            .add_neighbor(target.public_key(), first_neighbor.public_key())
            .unwrap();

        let subject = GossipProducerReal::new();

        let _result = subject.produce(&database, target.public_key());

        TestLogHandler::new().await_log_containing("Created Gossip: digraph db { ", 1000);
        TestLogHandler::new().await_log_containing(
            "\"AQIDBA\" [label=\"AQIDBA\\n1.2.3.4:1234\\nbootstrap\"] [style=filled];",
            500,
        );
        TestLogHandler::new()
            .await_log_containing("\"BAUGBw\" [label=\"BAUGBw\"] [shape=box];", 1000);
        TestLogHandler::new()
            .await_log_containing("\"AgMEBQ\" [label=\"AgMEBQ\\n2.3.4.5:2345\"];", 1000);
        TestLogHandler::new().await_log_containing("\"AgMEBQ\" -> \"AQIDBA\" [style=dashed];", 1000);
        TestLogHandler::new().await_log_containing("\"BAUGBw\" -> \"AQIDBA\" [style=dashed];", 1000);
        TestLogHandler::new().await_log_containing("\"BAUGBw\" -> \"AgMEBQ\";", 1000);
        TestLogHandler::new().await_log_containing("\"AQIDBA\" -> \"AgMEBQ\" [style=dashed];", 1000);
        TestLogHandler::new().await_log_containing("\"AQIDBA\" -> \"BAUGBw\" [style=dashed];", 1000);
    }
}
