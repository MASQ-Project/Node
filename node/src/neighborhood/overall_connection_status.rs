// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::neighborhood::{ConnectionProgressEvent, NodeDescriptor};
use openssl::init;
use std::collections::HashSet;
use std::ops::Deref;

#[derive(PartialEq, Debug)]
pub enum ConnectionStageErrors {
    TcpConnectionFailed,
    NoGossipResponseReceived,
}

#[derive(PartialEq, Debug)]
pub enum ConnectionStage {
    StageZero,
    TcpConnectionEstablished,
    NeighborshipEstablished,
    Failed(ConnectionStageErrors),
}

#[derive(PartialEq, Debug)]
pub struct ConnectionProgress {
    pub starting_descriptor: NodeDescriptor,
    pub current_descriptor: NodeDescriptor,
    pub connection_stage: ConnectionStage,
}

impl ConnectionProgress {
    pub fn new(node_descriptor: NodeDescriptor) -> Self {
        Self {
            starting_descriptor: node_descriptor.clone(),
            current_descriptor: node_descriptor,
            connection_stage: ConnectionStage::StageZero,
        }
    }

    pub fn update_stage(&mut self, connection_stage: ConnectionStage) {
        self.connection_stage = connection_stage;
        // todo!("Add checks whether it should be allowed to change stage or not");
    }

    pub fn handle_pass_gossip(&mut self, new_node_descriptor: NodeDescriptor) {
        unimplemented!(
            "Update the current_descriptor and reset the stage to StageZero,\
         iff the current_stage is TcpConnectionEstablished"
        )
    }
}

#[derive(PartialEq, Debug)]
enum OverallConnectionStage {
    NotConnected,        // Not connected to any neighbor.
    ConnectedToNeighbor, // Neighborship established. Same as No 3 hops route found.
    ThreeHopsRouteFound, // check_connectedness() returned true, data can now be relayed.
}

// TODO: Migrate this struct and code related to it to a new module and make that module public only for neighborhood
#[derive(PartialEq, Debug)]
pub struct OverallConnectionStatus {
    // Becomes true iff three hops route was found.
    can_make_routes: bool,
    // Stores one of the three stages of enum OverallConnectionStage.
    stage: OverallConnectionStage,
    // Stores the progress for initial node descriptors,
    // each element may or may not be corresponding to the descriptors entered by user.
    pub progress: Vec<ConnectionProgress>,
    // previous_pass_targets is used to stop the cycle of infinite pass gossips
    // in case it receives a node descriptor that is already a part of this hash set.
    previous_pass_targets: HashSet<NodeDescriptor>,
}

impl OverallConnectionStatus {
    pub fn new(initial_node_descriptors: Vec<NodeDescriptor>) -> Self {
        let progress = initial_node_descriptors
            .iter()
            .map(|node_descriptor| ConnectionProgress {
                starting_descriptor: node_descriptor.clone(),
                current_descriptor: node_descriptor.clone(),
                connection_stage: ConnectionStage::StageZero,
            })
            .collect();

        Self {
            can_make_routes: false,
            stage: OverallConnectionStage::NotConnected,
            progress,
            previous_pass_targets: HashSet::new(),
        }
    }

    pub fn iter_starting_descriptors(&self) -> impl Iterator<Item = &NodeDescriptor> {
        self.progress
            .iter()
            .map(|connection_progress| &connection_progress.starting_descriptor)
    }

    pub fn update_connection_stage(
        &mut self,
        public_key: PublicKey,
        event: ConnectionProgressEvent,
    ) {
        let mut connection_progress_to_modify = self
            .progress
            .iter_mut()
            .find(|connection_progress| {
                connection_progress.current_descriptor.encryption_public_key == public_key
            })
            .expect(&*format!(
                "Unable to find the node in connections with public key: {}",
                public_key
            ));

        match event {
            ConnectionProgressEvent::TcpConnectionSuccessful => {
                connection_progress_to_modify
                    .update_stage(ConnectionStage::TcpConnectionEstablished);
            }
            _ => todo!("Write logic for updating the connection progress"),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.progress.is_empty()
    }

    pub fn remove(&mut self, index: usize) -> NodeDescriptor {
        let removed_connection_progress = self.progress.remove(index);
        removed_connection_progress.starting_descriptor
    }
}

// Some Steps to follow ==>
// 1. Increase the count for Stage Zero
// 2. Initiate a TCP Connection. OK() -> TcpConnectionEstablished, Err() -> Failed and throw TcpConnectionFailed
// 3. Send a Debut Gossip
// 4. Waiting Period. IntroductionGossip -> Move to Next Step,
//    PassGossip -> Update the NodeConnection and retry the whole process,
//    TimeOut -> Failed and throw NoResponseReceived
// 5. Check for check_connectedness(), true -> Fully Connected, false -> Not able to Route

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::main_cryptde;
    use masq_lib::blockchains::chains::Chain;

    #[test]
    fn able_to_create_overall_connection_status() {
        let node_desc_1 = NodeDescriptor::try_from((
            main_cryptde(), // Used to provide default cryptde
            "masq://eth-ropsten:AQIDBA@1.2.3.4:1234/2345",
        ))
        .unwrap();
        let node_desc_2 = NodeDescriptor::try_from((
            main_cryptde(),
            "masq://eth-ropsten:AgMEBQ@1.2.3.5:1234/2345",
        ))
        .unwrap();
        let initial_node_descriptors = vec![node_desc_1.clone(), node_desc_2.clone()];

        let subject = OverallConnectionStatus::new(initial_node_descriptors);

        assert_eq!(
            subject,
            OverallConnectionStatus {
                can_make_routes: false,
                stage: OverallConnectionStage::NotConnected,
                progress: vec![
                    ConnectionProgress {
                        starting_descriptor: node_desc_1.clone(),
                        current_descriptor: node_desc_1,
                        connection_stage: ConnectionStage::StageZero,
                    },
                    ConnectionProgress {
                        starting_descriptor: node_desc_2.clone(),
                        current_descriptor: node_desc_2,
                        connection_stage: ConnectionStage::StageZero,
                    }
                ],
                previous_pass_targets: HashSet::new()
            }
        );
    }

    #[test]
    fn overall_connection_status_identifies_as_empty() {
        let subject = OverallConnectionStatus::new(vec![]);

        assert_eq!(subject.is_empty(), true);
    }

    #[test]
    fn overall_connection_status_identifies_as_non_empty() {
        let node_desc = NodeDescriptor::try_from((
            main_cryptde(),
            "masq://eth-ropsten:AQIDBA@1.2.3.4:1234/2345",
        ))
        .unwrap();

        let initial_node_descriptors = vec![node_desc.clone()];

        let subject = OverallConnectionStatus::new(initial_node_descriptors);

        assert_eq!(subject.is_empty(), false);
    }

    #[test]
    fn starting_descriptors_are_iterable() {
        let node_desc_1 = NodeDescriptor::try_from((
            main_cryptde(),
            "masq://eth-ropsten:AQIDBA@1.2.3.4:1234/2345",
        ))
        .unwrap();
        let node_desc_2 = NodeDescriptor::try_from((
            main_cryptde(),
            "masq://eth-ropsten:AgMEBQ@1.2.3.5:1234/2345",
        ))
        .unwrap();
        let initial_node_descriptors = vec![node_desc_1.clone(), node_desc_2.clone()];
        let mut subject = OverallConnectionStatus::new(initial_node_descriptors);

        let mut result = subject.iter_starting_descriptors();

        assert_eq!(result.next(), Some(&node_desc_1));
        assert_eq!(result.next(), Some(&node_desc_2));
        assert_eq!(result.next(), None);
    }

    #[test]
    fn remove_deletes_descriptor_s_progress_and_returns_node_descriptor() {
        let node_desc_1 = NodeDescriptor::try_from((
            main_cryptde(),
            "masq://eth-ropsten:AQIDBA@1.2.3.4:1234/2345",
        ))
        .unwrap();
        let node_desc_2 = NodeDescriptor::try_from((
            main_cryptde(),
            "masq://eth-ropsten:AgMEBQ@1.2.3.5:1234/2345",
        ))
        .unwrap();
        let initial_node_descriptors = vec![node_desc_1.clone(), node_desc_2.clone()];
        let mut subject = OverallConnectionStatus::new(initial_node_descriptors);

        let removed_desc_1 = subject.remove(0);
        let removed_desc_2 = subject.remove(0);

        assert_eq!(removed_desc_1, node_desc_1);
        assert_eq!(removed_desc_2, node_desc_2);
        assert_eq!(subject, OverallConnectionStatus::new(vec![]));
    }

    #[test]
    fn updates_the_connection_stage_to_tcp_connection_established() {
        let node_decriptor = NodeDescriptor {
            blockchain: Chain::EthRopsten,
            encryption_public_key: PublicKey::from(vec![0, 0, 0]),
            node_addr_opt: None,
        };
        let initial_node_descriptors = vec![node_decriptor.clone()];
        let mut subject = OverallConnectionStatus::new(initial_node_descriptors);

        subject.update_connection_stage(
            node_decriptor.encryption_public_key.clone(),
            ConnectionProgressEvent::TcpConnectionSuccessful,
        );

        assert_eq!(
            subject,
            OverallConnectionStatus {
                can_make_routes: false,
                stage: OverallConnectionStage::NotConnected,
                progress: vec![ConnectionProgress {
                    starting_descriptor: node_decriptor.clone(),
                    current_descriptor: node_decriptor,
                    connection_stage: ConnectionStage::TcpConnectionEstablished
                }],
                previous_pass_targets: Default::default()
            }
        )
    }

    #[test]
    #[should_panic(expected = "Unable to find the node in connections with public key")]
    fn panics_at_updating_the_connection_stage_if_a_node_is_not_a_part_of_connections() {
        let node_decriptor = NodeDescriptor {
            blockchain: Chain::EthRopsten,
            encryption_public_key: PublicKey::from(vec![0, 0, 0]),
            node_addr_opt: None,
        };
        let initial_node_descriptors = vec![node_decriptor.clone()];
        let non_existing_node_s_pub_key = PublicKey::from(vec![1, 1, 1]);
        let mut subject = OverallConnectionStatus::new(initial_node_descriptors);

        subject.update_connection_stage(
            non_existing_node_s_pub_key,
            ConnectionProgressEvent::TcpConnectionSuccessful,
        );
    }
}
