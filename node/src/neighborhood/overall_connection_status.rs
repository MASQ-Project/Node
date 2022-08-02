// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::neighborhood::overall_connection_status::ConnectionStageErrors::{
    NoGossipResponseReceived, PassLoopFound, TcpConnectionFailed,
};
use crate::sub_lib::neighborhood::{ConnectionProgressEvent, NodeDescriptor};
use actix::Recipient;
use masq_lib::messages::{ToMessageBody, UiConnectionChangeBroadcast, UiConnectionStage};
use masq_lib::ui_gateway::{MessageTarget, NodeToUiMessage};
use std::net::IpAddr;
use std::string::String;

#[derive(PartialEq, Debug, Clone)]
pub enum ConnectionStageErrors {
    TcpConnectionFailed,
    NoGossipResponseReceived,
    PassLoopFound,
}

#[derive(PartialEq, Debug, Clone)]
pub enum ConnectionStage {
    StageZero,
    TcpConnectionEstablished,
    NeighborshipEstablished,
    Failed(ConnectionStageErrors),
}

impl TryFrom<&ConnectionStage> for usize {
    type Error = ();

    fn try_from(connection_stage: &ConnectionStage) -> Result<Self, Self::Error> {
        match connection_stage {
            ConnectionStage::StageZero => Ok(0),
            ConnectionStage::TcpConnectionEstablished => Ok(1),
            ConnectionStage::NeighborshipEstablished => Ok(2),
            ConnectionStage::Failed(_) => Err(()),
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct ConnectionProgress {
    pub initial_node_descriptor: NodeDescriptor,
    pub current_peer_addr: IpAddr,
    pub connection_stage: ConnectionStage,
}

impl ConnectionProgress {
    pub fn new(node_descriptor: NodeDescriptor) -> Self {
        let peer_addr = node_descriptor
            .node_addr_opt
            .as_ref()
            .unwrap_or_else(|| {
                panic!(
                    "Unable to receive node addr for the descriptor {:?}",
                    node_descriptor
                )
            })
            .ip_addr();
        Self {
            initial_node_descriptor: node_descriptor,
            current_peer_addr: peer_addr,
            connection_stage: ConnectionStage::StageZero,
        }
    }

    pub fn update_stage(&mut self, connection_stage: ConnectionStage) {
        // TODO: We may prefer to use an enum with variants "Up, Down, StageZero, Failure", for transitions instead of checks
        let current_stage = usize::try_from(&self.connection_stage);
        let new_stage = usize::try_from(&connection_stage);

        if let (Ok(current_stage_num), Ok(new_stage_num)) = (current_stage, new_stage) {
            if new_stage_num != current_stage_num + 1 {
                panic!(
                    "Can't update the stage from {:?} to {:?}",
                    self.connection_stage, connection_stage
                )
            }
        }

        self.connection_stage = connection_stage;
    }

    pub fn handle_pass_gossip(&mut self, new_pass_target: IpAddr) {
        if self.connection_stage != ConnectionStage::TcpConnectionEstablished {
            panic!(
                "Can't update the stage from {:?} to {:?}",
                self.connection_stage,
                ConnectionStage::StageZero
            )
        };

        self.connection_stage = ConnectionStage::StageZero;
        self.current_peer_addr = new_pass_target;
    }
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum OverallConnectionStage {
    NotConnected = 0,
    ConnectedToNeighbor = 1, // When an Introduction or Standard Gossip (acceptance) is received
    ThreeHopsRouteFound = 2, // Data can be relayed once this stage is reached
}

impl From<OverallConnectionStage> for UiConnectionStage {
    fn from(stage: OverallConnectionStage) -> UiConnectionStage {
        match stage {
            OverallConnectionStage::NotConnected => UiConnectionStage::NotConnected,
            OverallConnectionStage::ConnectedToNeighbor => UiConnectionStage::ConnectedToNeighbor,
            OverallConnectionStage::ThreeHopsRouteFound => UiConnectionStage::ThreeHopsRouteFound,
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct OverallConnectionStatus {
    // The check_connectedness() updates the boolean when three hops route is found
    pub can_make_routes: bool,
    // Transition depends on the ConnectionProgressMessage & check_connectedness(), they may not be in sync
    pub stage: OverallConnectionStage,
    // Corresponds to the initial_node_descriptors, that are entered by the user using --neighbors
    pub progress: Vec<ConnectionProgress>,
}

impl OverallConnectionStatus {
    pub fn new(initial_node_descriptors: Vec<NodeDescriptor>) -> Self {
        let progress = initial_node_descriptors
            .into_iter()
            .map(ConnectionProgress::new)
            .collect();

        Self {
            can_make_routes: false,
            stage: OverallConnectionStage::NotConnected,
            progress,
        }
    }

    pub fn iter_initial_node_descriptors(&self) -> impl Iterator<Item = &NodeDescriptor> {
        self.progress
            .iter()
            .map(|connection_progress| &connection_progress.initial_node_descriptor)
    }

    pub fn get_connection_progress_by_ip(
        &mut self,
        peer_addr: IpAddr,
    ) -> Result<&mut ConnectionProgress, String> {
        let connection_progress_res = self
            .progress
            .iter_mut()
            .find(|connection_progress| connection_progress.current_peer_addr == peer_addr);

        match connection_progress_res {
            Some(connection_progress) => Ok(connection_progress),
            None => Err(format!(
                "Unable to find the Node in connections with IP Address: {}",
                peer_addr
            )),
        }
    }

    pub fn get_connection_progress_by_desc(
        &mut self,
        initial_node_descriptor: &NodeDescriptor,
    ) -> Result<&mut ConnectionProgress, String> {
        let connection_progress = self.progress.iter_mut().find(|connection_progress| {
            &connection_progress.initial_node_descriptor == initial_node_descriptor
        });

        match connection_progress {
            Some(connection_progress) => Ok(connection_progress),
            None => Err(format!(
                "Unable to find the Node in connections with Node Descriptor: {:?}",
                initial_node_descriptor
            )),
        }
    }

    pub fn update_connection_stage(
        connection_progress: &mut ConnectionProgress,
        event: ConnectionProgressEvent,
    ) {
        let mut modify_connection_progress =
            |stage: ConnectionStage| connection_progress.update_stage(stage);

        match event {
            ConnectionProgressEvent::TcpConnectionSuccessful => {
                modify_connection_progress(ConnectionStage::TcpConnectionEstablished)
            }
            ConnectionProgressEvent::TcpConnectionFailed => {
                modify_connection_progress(ConnectionStage::Failed(TcpConnectionFailed))
            }
            ConnectionProgressEvent::IntroductionGossipReceived(_new_node) => {
                modify_connection_progress(ConnectionStage::NeighborshipEstablished);
            }
            ConnectionProgressEvent::StandardGossipReceived => {
                modify_connection_progress(ConnectionStage::NeighborshipEstablished);
            }
            ConnectionProgressEvent::PassGossipReceived(new_pass_target) => {
                connection_progress.handle_pass_gossip(new_pass_target);
            }
            ConnectionProgressEvent::PassLoopFound => {
                modify_connection_progress(ConnectionStage::Failed(PassLoopFound));
            }
            ConnectionProgressEvent::NoGossipResponseReceived => {
                modify_connection_progress(ConnectionStage::Failed(NoGossipResponseReceived));
            }
        }
    }

    pub fn update_ocs_stage_and_send_message_to_ui(
        &mut self,
        node_to_ui_recipient: &Recipient<NodeToUiMessage>,
    ) {
        // For now, this function is only called when Standard or Introduction Gossip
        // is received, as it is implemented only for the advancing transitions right now
        // TODO: Modify this fn when you're implementing the regressing transitions and try to
        // write a more generalized fn, which can be called when any stage gets updated
        let prev_stage = self.stage;
        if self.can_make_routes() {
            self.stage = OverallConnectionStage::ThreeHopsRouteFound;
        } else {
            self.stage = OverallConnectionStage::ConnectedToNeighbor;
        }
        if self.stage as usize > prev_stage as usize {
            OverallConnectionStatus::send_message_to_ui(self.stage.into(), node_to_ui_recipient);
        }
    }

    fn send_message_to_ui(
        stage: UiConnectionStage,
        node_to_ui_recipient: &Recipient<NodeToUiMessage>,
    ) {
        let message = NodeToUiMessage {
            target: MessageTarget::AllClients,
            body: UiConnectionChangeBroadcast { stage }.tmb(0),
        };

        node_to_ui_recipient
            .try_send(message)
            .expect("UI Gateway is unbound.");
    }

    pub fn is_empty(&self) -> bool {
        self.progress.is_empty()
    }

    pub fn remove(&mut self, index: usize) -> NodeDescriptor {
        let removed_connection_progress = self.progress.remove(index);
        removed_connection_progress.initial_node_descriptor
    }

    pub fn can_make_routes(&self) -> bool {
        self.can_make_routes
    }

    pub fn update_can_make_routes(&mut self, can_make_routes: bool) {
        self.can_make_routes = can_make_routes;
    }

    pub fn stage(&self) -> OverallConnectionStage {
        self.stage
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::neighborhood::overall_connection_status::ConnectionStageErrors::{
        PassLoopFound, TcpConnectionFailed,
    };
    use crate::neighborhood::PublicKey;
    use crate::test_utils::neighborhood_test_utils::{make_ip, make_node, make_node_descriptor};
    use crate::test_utils::unshared_test_utils::make_node_to_ui_recipient;
    use actix::System;
    use masq_lib::blockchains::chains::Chain;
    use masq_lib::messages::{ToMessageBody, UiConnectionChangeBroadcast, UiConnectionStage};
    use masq_lib::ui_gateway::MessageTarget;

    #[test]
    #[should_panic(
        expected = "Unable to receive node addr for the descriptor NodeDescriptor { blockchain: EthRopsten, encryption_public_key: AAAA, node_addr_opt: None }"
    )]
    fn can_not_create_a_new_connection_without_node_addr() {
        let descriptor_with_no_ip_address = NodeDescriptor {
            blockchain: Chain::EthRopsten,
            encryption_public_key: PublicKey::from(vec![0, 0, 0]),
            node_addr_opt: None,
        };
        let _connection_progress = ConnectionProgress::new(descriptor_with_no_ip_address);
    }

    #[test]
    fn connection_progress_handles_pass_gossip_correctly() {
        let ip_addr = make_ip(1);
        let initial_node_descriptor = make_node_descriptor(ip_addr);
        let mut subject = ConnectionProgress::new(initial_node_descriptor.clone());
        let pass_target = make_ip(2);
        subject.update_stage(ConnectionStage::TcpConnectionEstablished);

        subject.handle_pass_gossip(pass_target);

        assert_eq!(
            subject,
            ConnectionProgress {
                initial_node_descriptor,
                current_peer_addr: pass_target,
                connection_stage: ConnectionStage::StageZero
            }
        )
    }

    #[test]
    #[should_panic(expected = "Can't update the stage from StageZero to StageZero")]
    fn connection_progress_panics_while_handling_pass_gossip_in_case_tcp_connection_is_not_established(
    ) {
        let ip_addr = make_ip(1);
        let initial_node_descriptor = make_node_descriptor(ip_addr);
        let mut subject = ConnectionProgress::new(initial_node_descriptor);
        let pass_target = make_ip(2);

        subject.handle_pass_gossip(pass_target);
    }

    #[test]
    fn overall_connection_stage_can_be_converted_into_usize_and_can_be_compared() {
        assert!(
            OverallConnectionStage::ConnectedToNeighbor as usize
                > OverallConnectionStage::NotConnected as usize
        );
        assert!(
            OverallConnectionStage::ThreeHopsRouteFound as usize
                > OverallConnectionStage::ConnectedToNeighbor as usize
        );
    }

    #[test]
    fn able_to_create_overall_connection_status() {
        let node_desc_1 = make_node_descriptor(make_ip(1));
        let node_desc_2 = make_node_descriptor(make_ip(2));
        let initial_node_descriptors = vec![node_desc_1.clone(), node_desc_2.clone()];

        let subject = OverallConnectionStatus::new(initial_node_descriptors);

        assert_eq!(
            subject,
            OverallConnectionStatus {
                can_make_routes: false,
                stage: OverallConnectionStage::NotConnected,
                progress: vec![
                    ConnectionProgress::new(node_desc_1),
                    ConnectionProgress::new(node_desc_2)
                ],
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
        let node_desc = make_node_descriptor(make_ip(1));
        let initial_node_descriptors = vec![node_desc];

        let subject = OverallConnectionStatus::new(initial_node_descriptors);

        assert_eq!(subject.is_empty(), false);
    }

    #[test]
    fn can_recieve_a_result_of_connection_progress_from_peer_addr() {
        let peer_1_ip = make_ip(1);
        let peer_2_ip = make_ip(2);
        let desc_1 = make_node_descriptor(peer_1_ip);
        let desc_2 = make_node_descriptor(peer_2_ip);
        let initial_node_descriptors = vec![desc_1.clone(), desc_2.clone()];

        let mut subject = OverallConnectionStatus::new(initial_node_descriptors);

        let res_1 = subject.get_connection_progress_by_ip(peer_1_ip);
        assert_eq!(res_1, Ok(&mut ConnectionProgress::new(desc_1)));
        let res_2 = subject.get_connection_progress_by_ip(peer_2_ip);
        assert_eq!(res_2, Ok(&mut ConnectionProgress::new(desc_2)));
    }

    #[test]
    fn receives_an_error_in_receiving_connection_progress_from_unknown_ip_address() {
        let peer = make_ip(1);
        let desc = make_node_descriptor(peer);
        let initial_node_descriptors = vec![desc];
        let unknown_peer = make_ip(2);

        let mut subject = OverallConnectionStatus::new(initial_node_descriptors);

        let res = subject.get_connection_progress_by_ip(unknown_peer);
        assert_eq!(
            res,
            Err(format!(
                "Unable to find the Node in connections with IP Address: {}",
                unknown_peer
            ))
        );
    }

    #[test]
    fn can_receive_connection_progress_from_initial_node_desc() {
        let desc_1 = make_node_descriptor(make_ip(1));
        let desc_2 = make_node_descriptor(make_ip(2));
        let initial_node_descriptors = vec![desc_1.clone(), desc_2.clone()];

        let mut subject = OverallConnectionStatus::new(initial_node_descriptors);

        assert_eq!(
            subject.get_connection_progress_by_desc(&desc_1),
            Ok(&mut ConnectionProgress::new(desc_1))
        );
        assert_eq!(
            subject.get_connection_progress_by_desc(&desc_2),
            Ok(&mut ConnectionProgress::new(desc_2))
        );
    }

    #[test]
    fn receives_an_error_in_receiving_connection_progress_from_unknown_initial_node_desc() {
        let known_desc = make_node_descriptor(make_ip(1));
        let unknown_desc = make_node_descriptor(make_ip(2));
        let initial_node_descriptors = vec![known_desc];

        let mut subject = OverallConnectionStatus::new(initial_node_descriptors);

        assert_eq!(
            subject.get_connection_progress_by_desc(&unknown_desc),
            Err(format!(
                "Unable to find the Node in connections with Node Descriptor: {:?}",
                unknown_desc
            ))
        );
    }

    #[test]
    fn starting_descriptors_are_iterable() {
        let node_desc_1 = make_node_descriptor(make_ip(1));
        let node_desc_2 = make_node_descriptor(make_ip(2));
        let initial_node_descriptors = vec![node_desc_1.clone(), node_desc_2.clone()];
        let subject = OverallConnectionStatus::new(initial_node_descriptors);

        let mut result = subject.iter_initial_node_descriptors();

        assert_eq!(result.next(), Some(&node_desc_1));
        assert_eq!(result.next(), Some(&node_desc_2));
        assert_eq!(result.next(), None);
    }

    #[test]
    fn remove_deletes_descriptor_s_progress_and_returns_node_descriptor() {
        let node_desc_1 = make_node_descriptor(make_ip(1));
        let node_desc_2 = make_node_descriptor(make_ip(2));
        let initial_node_descriptors = vec![node_desc_1.clone(), node_desc_2.clone()];
        let mut subject = OverallConnectionStatus::new(initial_node_descriptors);

        let removed_desc = subject.remove(1);

        assert_eq!(removed_desc, node_desc_2);
    }

    #[test]
    fn updates_the_connection_stage_to_tcp_connection_established() {
        let (node_ip_addr, node_descriptor) = make_node(1);
        let mut subject = OverallConnectionStatus::new(vec![node_descriptor.clone()]);

        OverallConnectionStatus::update_connection_stage(
            subject.get_connection_progress_by_ip(node_ip_addr).unwrap(),
            ConnectionProgressEvent::TcpConnectionSuccessful,
        );

        assert_eq!(
            subject,
            OverallConnectionStatus {
                can_make_routes: false,
                stage: OverallConnectionStage::NotConnected,
                progress: vec![ConnectionProgress {
                    initial_node_descriptor: node_descriptor,
                    current_peer_addr: node_ip_addr,
                    connection_stage: ConnectionStage::TcpConnectionEstablished
                }],
            }
        )
    }

    #[test]
    fn updates_the_connection_stage_to_failed_when_tcp_connection_fails() {
        let (node_ip_addr, node_descriptor) = make_node(1);
        let mut subject = OverallConnectionStatus::new(vec![node_descriptor.clone()]);
        let connection_progress_to_modify =
            subject.get_connection_progress_by_ip(node_ip_addr).unwrap();

        OverallConnectionStatus::update_connection_stage(
            connection_progress_to_modify,
            ConnectionProgressEvent::TcpConnectionFailed,
        );

        assert_eq!(
            subject,
            OverallConnectionStatus {
                can_make_routes: false,
                stage: OverallConnectionStage::NotConnected,
                progress: vec![ConnectionProgress {
                    initial_node_descriptor: node_descriptor,
                    current_peer_addr: node_ip_addr,
                    connection_stage: ConnectionStage::Failed(TcpConnectionFailed)
                }],
            }
        )
    }

    #[test]
    fn updates_the_connection_stage_to_neighborship_established_when_introduction_gossip_is_received(
    ) {
        let (node_ip_addr, node_descriptor) = make_node(1);
        let mut subject = OverallConnectionStatus::new(vec![node_descriptor.clone()]);
        let connection_progress = subject.get_connection_progress_by_ip(node_ip_addr).unwrap();
        OverallConnectionStatus::update_connection_stage(
            connection_progress,
            ConnectionProgressEvent::TcpConnectionSuccessful,
        );

        OverallConnectionStatus::update_connection_stage(
            connection_progress,
            ConnectionProgressEvent::IntroductionGossipReceived(make_ip(1)),
        );

        assert_eq!(
            connection_progress,
            &mut ConnectionProgress {
                initial_node_descriptor: node_descriptor,
                current_peer_addr: node_ip_addr,
                connection_stage: ConnectionStage::NeighborshipEstablished
            }
        )
    }

    #[test]
    fn updates_the_connection_stage_to_neighborship_established_when_standard_gossip_is_received() {
        let (node_ip_addr, node_descriptor) = make_node(1);
        let mut subject = OverallConnectionStatus::new(vec![node_descriptor.clone()]);
        let connection_progress = subject.get_connection_progress_by_ip(node_ip_addr).unwrap();
        OverallConnectionStatus::update_connection_stage(
            connection_progress,
            ConnectionProgressEvent::TcpConnectionSuccessful,
        );

        OverallConnectionStatus::update_connection_stage(
            connection_progress,
            ConnectionProgressEvent::StandardGossipReceived,
        );

        assert_eq!(
            connection_progress,
            &mut ConnectionProgress {
                initial_node_descriptor: node_descriptor,
                current_peer_addr: node_ip_addr,
                connection_stage: ConnectionStage::NeighborshipEstablished
            }
        )
    }

    #[test]
    fn updates_the_connection_stage_to_stage_zero_when_pass_gossip_is_received() {
        let (node_ip_addr, node_descriptor) = make_node(1);
        let mut subject = OverallConnectionStatus::new(vec![node_descriptor.clone()]);
        let pass_target = make_ip(1);
        let connection_progress_to_modify =
            subject.get_connection_progress_by_ip(node_ip_addr).unwrap();
        OverallConnectionStatus::update_connection_stage(
            connection_progress_to_modify,
            ConnectionProgressEvent::TcpConnectionSuccessful,
        );

        OverallConnectionStatus::update_connection_stage(
            connection_progress_to_modify,
            ConnectionProgressEvent::PassGossipReceived(pass_target),
        );

        assert_eq!(
            subject,
            OverallConnectionStatus {
                can_make_routes: false,
                stage: OverallConnectionStage::NotConnected,
                progress: vec![ConnectionProgress {
                    initial_node_descriptor: node_descriptor,
                    current_peer_addr: pass_target,
                    connection_stage: ConnectionStage::StageZero
                }],
            }
        )
    }

    #[test]
    fn updates_connection_stage_to_failed_when_pass_loop_is_found() {
        let (node_ip_addr, node_descriptor) = make_node(1);
        let mut subject = OverallConnectionStatus::new(vec![node_descriptor.clone()]);
        let connection_progress_to_modify =
            subject.get_connection_progress_by_ip(node_ip_addr).unwrap();
        OverallConnectionStatus::update_connection_stage(
            connection_progress_to_modify,
            ConnectionProgressEvent::TcpConnectionSuccessful,
        );

        OverallConnectionStatus::update_connection_stage(
            connection_progress_to_modify,
            ConnectionProgressEvent::PassLoopFound,
        );

        assert_eq!(
            subject,
            OverallConnectionStatus {
                can_make_routes: false,
                stage: OverallConnectionStage::NotConnected,
                progress: vec![ConnectionProgress {
                    initial_node_descriptor: node_descriptor,
                    current_peer_addr: node_ip_addr,
                    connection_stage: ConnectionStage::Failed(PassLoopFound)
                }],
            }
        )
    }

    #[test]
    fn updates_connection_stage_to_failed_when_no_gossip_response_is_received() {
        let (node_ip_addr, node_descriptor) = make_node(1);
        let mut subject = OverallConnectionStatus::new(vec![node_descriptor.clone()]);
        let connection_progress_to_modify =
            subject.get_connection_progress_by_ip(node_ip_addr).unwrap();
        OverallConnectionStatus::update_connection_stage(
            connection_progress_to_modify,
            ConnectionProgressEvent::TcpConnectionSuccessful,
        );

        OverallConnectionStatus::update_connection_stage(
            connection_progress_to_modify,
            ConnectionProgressEvent::NoGossipResponseReceived,
        );

        assert_eq!(
            subject,
            OverallConnectionStatus {
                can_make_routes: false,
                stage: OverallConnectionStage::NotConnected,
                progress: vec![ConnectionProgress {
                    initial_node_descriptor: node_descriptor,
                    current_peer_addr: node_ip_addr,
                    connection_stage: ConnectionStage::Failed(NoGossipResponseReceived)
                }],
            }
        )
    }

    #[test]
    fn connection_stage_can_be_converted_to_number() {
        assert_eq!(usize::try_from(&ConnectionStage::StageZero), Ok(0));
        assert_eq!(
            usize::try_from(&ConnectionStage::TcpConnectionEstablished),
            Ok(1)
        );
        assert_eq!(
            usize::try_from(&ConnectionStage::NeighborshipEstablished),
            Ok(2)
        );
        assert_eq!(
            usize::try_from(&ConnectionStage::Failed(TcpConnectionFailed)),
            Err(())
        );
    }

    #[test]
    #[should_panic(expected = "Can't update the stage from StageZero to NeighborshipEstablished")]
    fn can_t_establish_neighborhsip_without_having_a_tcp_connection() {
        let (node_ip_addr, node_descriptor) = make_node(1);
        let mut subject = OverallConnectionStatus::new(vec![node_descriptor]);
        let connection_progress_to_modify =
            subject.get_connection_progress_by_ip(node_ip_addr).unwrap();

        OverallConnectionStatus::update_connection_stage(
            connection_progress_to_modify,
            ConnectionProgressEvent::IntroductionGossipReceived(make_ip(1)),
        );
    }

    #[test]
    fn converts_connected_to_neighbor_stage_into_ui_connection_change_stage() {
        let connected_to_neighbor = OverallConnectionStage::ConnectedToNeighbor;

        let connected_to_neighbor_converted: UiConnectionStage = connected_to_neighbor.into();

        assert_eq!(
            connected_to_neighbor_converted,
            UiConnectionStage::ConnectedToNeighbor
        );
    }

    #[test]
    fn converts_three_hops_route_found_stage_into_ui_connection_change_stage() {
        let three_hops_route_found = OverallConnectionStage::ThreeHopsRouteFound;

        let three_hops_route_found_converted: UiConnectionStage = three_hops_route_found.into();

        assert_eq!(
            three_hops_route_found_converted,
            UiConnectionStage::ThreeHopsRouteFound
        );
    }

    #[test]
    fn converts_not_connected_into_ui_connection_change_stage() {
        let not_connected = OverallConnectionStage::NotConnected;

        let not_connected_converted: UiConnectionStage = not_connected.into();

        assert_eq!(not_connected_converted, UiConnectionStage::NotConnected);
    }

    #[test]
    fn we_can_ask_about_can_make_routes() {
        let node_descriptor = make_node_descriptor(make_ip(1));
        let subject = OverallConnectionStatus::new(vec![node_descriptor]);

        let can_make_routes = subject.can_make_routes();

        assert_eq!(can_make_routes, false);
    }

    #[test]
    fn can_update_the_boolean_can_make_routes() {
        let node_descriptor = make_node_descriptor(make_ip(1));
        let mut subject = OverallConnectionStatus::new(vec![node_descriptor]);
        let can_make_routes_initially = subject.can_make_routes();

        subject.update_can_make_routes(true);

        let can_make_routes_finally = subject.can_make_routes();
        assert_eq!(can_make_routes_initially, false);
        assert_eq!(can_make_routes_finally, true);
    }

    #[test]
    fn updates_the_stage_to_three_hops_route_found_in_case_introduction_or_standard_gossip_is_received_and_flag_is_true(
    ) {
        let initial_stage = OverallConnectionStage::NotConnected;
        let can_make_routes = true;

        let (stage, message_opt) =
            assert_stage_and_node_to_ui_message(
                initial_stage,
                can_make_routes,
                "updates_the_stage_to_three_hops_route_found_in_case_introduction_or_standard_gossip_is_received_and_flag_is_true"
            );

        assert_eq!(stage, OverallConnectionStage::ThreeHopsRouteFound);
        assert_eq!(
            message_opt,
            Some(NodeToUiMessage {
                target: MessageTarget::AllClients,
                body: UiConnectionChangeBroadcast {
                    stage: UiConnectionStage::ThreeHopsRouteFound
                }
                .tmb(0)
            })
        );
    }

    #[test]
    fn updates_the_stage_to_connected_to_neighbor_in_case_introduction_or_standard_gossip_is_received_and_flag_is_false(
    ) {
        let initial_stage = OverallConnectionStage::NotConnected;
        let can_make_routes = false;

        let (stage, message_opt) =
            assert_stage_and_node_to_ui_message(
                initial_stage,
                can_make_routes,
                "updates_the_stage_to_connected_to_neighbor_in_case_introduction_or_standard_gossip_is_received_and_flag_is_false"
            );

        assert_eq!(stage, OverallConnectionStage::ConnectedToNeighbor);
        assert_eq!(
            message_opt,
            Some(NodeToUiMessage {
                target: MessageTarget::AllClients,
                body: UiConnectionChangeBroadcast {
                    stage: UiConnectionStage::ConnectedToNeighbor
                }
                .tmb(0)
            })
        );
    }

    #[test]
    fn doesn_t_send_message_to_the_ui_in_case_introduction_or_standard_gossip_is_received_but_stage_hasn_t_updated(
    ) {
        let initial_stage = OverallConnectionStage::ConnectedToNeighbor;
        let can_make_routes = false;

        let (stage, message_opt) = assert_stage_and_node_to_ui_message(
            initial_stage,
            can_make_routes,
            "doesn_t_send_message_to_the_ui_in_case_introduction_or_standard_gossip_is_received_but_stage_hasn_t_updated",
        );

        assert_eq!(stage, initial_stage);
        assert_eq!(message_opt, None);
    }

    #[test]
    fn doesn_t_send_a_message_to_ui_in_case_connection_drops_from_three_hops_to_connected_to_neighbor(
    ) {
        let initial_stage = OverallConnectionStage::ThreeHopsRouteFound;
        let can_make_routes = false;

        let (stage, message_opt) =
            assert_stage_and_node_to_ui_message(
                initial_stage,
                can_make_routes,
                "doesn_t_send_a_message_to_ui_in_case_connection_drops_from_three_hops_to_connected_to_neighbor"
            );

        assert_eq!(stage, OverallConnectionStage::ConnectedToNeighbor);
        assert_eq!(message_opt, None);
    }

    #[test]
    fn getter_fn_for_the_stage_of_overall_connection_status_exists() {
        let subject = OverallConnectionStatus::new(vec![make_node_descriptor(make_ip(1))]);
        assert_eq!(subject.stage(), OverallConnectionStage::NotConnected);
    }

    fn assert_stage_and_node_to_ui_message(
        initial_stage: OverallConnectionStage,
        can_make_routes: bool,
        test_name: &str,
    ) -> (OverallConnectionStage, Option<NodeToUiMessage>) {
        let mut subject =
            OverallConnectionStatus::new(vec![make_node_descriptor(make_ip(u8::MAX))]);
        let (node_to_ui_recipient, node_to_ui_recording_arc) = make_node_to_ui_recipient();
        subject.stage = initial_stage;
        let system = System::new(test_name);

        subject.update_can_make_routes(can_make_routes);
        subject.update_ocs_stage_and_send_message_to_ui(&node_to_ui_recipient);

        System::current().stop();
        assert_eq!(system.run(), 0);
        let stage = subject.stage;
        let recording = node_to_ui_recording_arc.lock().unwrap();
        let message_opt = recording.get_record_opt::<NodeToUiMessage>(0).cloned();

        (stage, message_opt)
    }
}
