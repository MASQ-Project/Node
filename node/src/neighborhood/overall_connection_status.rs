// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::neighborhood::overall_connection_status::ConnectionStageErrors::{
    NoGossipResponseReceived, PassLoopFound, TcpConnectionFailed,
};
use crate::sub_lib::neighborhood::{
    ConnectionProgressEvent, ConnectionProgressMessage, NodeDescriptor,
};
use actix::Recipient;
use masq_lib::logger::Logger;
use masq_lib::messages::{ToMessageBody, UiConnectionChangeBroadcast, UiConnectionStage};
use masq_lib::ui_gateway::{MessageTarget, NodeToUiMessage};
use std::net::IpAddr;
use std::string::String;

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum ConnectionStageErrors {
    TcpConnectionFailed,
    NoGossipResponseReceived,
    PassLoopFound,
}

#[derive(PartialEq, Eq, Debug, Clone)]
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

#[derive(PartialEq, Eq, Debug, Clone)]
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

    pub fn update_stage(&mut self, logger: &Logger, connection_stage: ConnectionStage) {
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

        debug!(
            logger,
            "The connection stage for Node with IP address {:?} has been updated from {:?} to {:?}.",
            self.current_peer_addr,
            self.connection_stage,
            connection_stage
        );

        self.connection_stage = connection_stage;
    }

    pub fn handle_pass_gossip(&mut self, logger: &Logger, new_pass_target: IpAddr) {
        let preliminary_msg = format!(
            "Pass gossip received from Node with IP Address {:?} to a Node with IP Address {:?}",
            self.current_peer_addr, new_pass_target,
        );
        match self.connection_stage {
            ConnectionStage::StageZero => {
                error!(
                    logger,
                    "{preliminary_msg}. Requested to update the stage from StageZero to StageZero.",
                )
            }
            ConnectionStage::TcpConnectionEstablished => {
                debug!(
                    logger,
                    "{preliminary_msg}. Updating the stage from TcpConnectionEstablished to StageZero.",
                )
            }
            _ => panic!(
                "{preliminary_msg}. Can't update the stage from {:?} to StageZero",
                self.connection_stage,
            ),
        }

        self.connection_stage = ConnectionStage::StageZero;
        self.current_peer_addr = new_pass_target;
    }
}

#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum OverallConnectionStage {
    NotConnected = 0,
    ConnectedToNeighbor = 1, // When an Introduction or Standard Gossip (acceptance) is received
    RouteFound = 2,          // Data can be relayed once this stage is reached
}

impl From<OverallConnectionStage> for UiConnectionStage {
    fn from(stage: OverallConnectionStage) -> UiConnectionStage {
        match stage {
            OverallConnectionStage::NotConnected => UiConnectionStage::NotConnected,
            OverallConnectionStage::ConnectedToNeighbor => UiConnectionStage::ConnectedToNeighbor,
            OverallConnectionStage::RouteFound => UiConnectionStage::RouteFound,
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct OverallConnectionStatus {
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
        logger: &Logger,
    ) {
        let mut modify_connection_progress =
            |stage: ConnectionStage| connection_progress.update_stage(logger, stage);

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
                connection_progress.handle_pass_gossip(logger, new_pass_target);
            }
            ConnectionProgressEvent::PassLoopFound => {
                modify_connection_progress(ConnectionStage::Failed(PassLoopFound));
            }
            ConnectionProgressEvent::NoGossipResponseReceived => {
                modify_connection_progress(ConnectionStage::Failed(NoGossipResponseReceived));
            }
        }
    }

    pub fn get_peer_addrs(&self) -> Vec<IpAddr> {
        self.progress
            .iter()
            .map(|connection_progress| connection_progress.current_peer_addr)
            .collect()
    }

    pub fn get_connection_progress_to_modify(
        &mut self,
        msg: &ConnectionProgressMessage,
    ) -> Result<&mut ConnectionProgress, String> {
        if let ConnectionProgressEvent::PassGossipReceived(pass_target) = msg.event {
            // Check if Pass Target can potentially create a duplicate ConnectionProgress
            let is_duplicate = self.get_peer_addrs().contains(&pass_target);

            if is_duplicate {
                return Err(format!(
                    "Pass target with IP Address: {:?} is already a \
                    part of different connection progress.",
                    pass_target
                ));
            }
        };

        if let Ok(connection_progress) = self.get_connection_progress_by_ip(msg.peer_addr) {
            Ok(connection_progress)
        } else {
            Err(format!(
                "No peer found with the IP Address: {:?}",
                msg.peer_addr
            ))
        }
    }

    pub fn update_ocs_stage_and_send_message_to_ui(
        &mut self,
        new_stage: OverallConnectionStage,
        node_to_ui_recipient: &Recipient<NodeToUiMessage>,
        logger: &Logger,
    ) {
        let prev_stage = self.stage;
        if new_stage != prev_stage {
            self.stage = new_stage;
            OverallConnectionStatus::send_message_to_ui(self.stage.into(), node_to_ui_recipient);
            debug!(
                logger,
                "The stage of OverallConnectionStatus has been changed \
                from {:?} to {:?}. A message to the UI was also sent.",
                prev_stage,
                new_stage
            );
        } else {
            trace!(
                logger,
                "There was an attempt to update the stage of OverallConnectionStatus \
                from {:?} to {:?}. The request has been discarded.",
                prev_stage,
                new_stage
            )
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
        self.stage() == OverallConnectionStage::RouteFound
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
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::ui_gateway::MessageTarget;

    #[test]
    #[should_panic(
        expected = "Unable to receive node addr for the descriptor NodeDescriptor { blockchain: EthRopsten, encryption_public_key: 0x000000, node_addr_opt: None }"
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
    fn connection_progress_handles_pass_gossip_correctly_and_performs_logging_in_order() {
        init_test_logging();
        let test_name =
            "connection_progress_handles_pass_gossip_correctly_and_performs_logging_in_order";
        let ip_addr = make_ip(1);
        let initial_node_descriptor = make_node_descriptor(ip_addr);
        let mut subject = ConnectionProgress::new(initial_node_descriptor.clone());
        let pass_target = make_ip(2);
        let logger = Logger::new(test_name);
        subject.update_stage(&logger, ConnectionStage::TcpConnectionEstablished);

        subject.handle_pass_gossip(&logger, pass_target);

        assert_eq!(
            subject,
            ConnectionProgress {
                initial_node_descriptor,
                current_peer_addr: pass_target,
                connection_stage: ConnectionStage::StageZero
            }
        );
        TestLogHandler::new().assert_logs_contain_in_order(vec![
            &format!(
                "DEBUG: {test_name}: The connection stage \
                for Node with IP address {:?} has been updated from {:?} to {:?}.",
                ip_addr,
                ConnectionStage::StageZero,
                ConnectionStage::TcpConnectionEstablished
            ),
            &format!(
                "DEBUG: {test_name}: Pass gossip received from Node with IP Address {:?} to a Node with \
                IP Address {:?}. Updating the stage from TcpConnectionEstablished to StageZero.",
                ip_addr, pass_target
            ),
        ]);
    }

    #[test]
    fn connection_progress_logs_error_while_handling_pass_gossip_in_case_tcp_connection_is_not_established(
    ) {
        init_test_logging();
        let test_name = "connection_progress_logs_error_while_handling_pass_gossip_in_case_tcp_connection_is_not_established";
        let ip_addr = make_ip(1);
        let initial_node_descriptor = make_node_descriptor(ip_addr);
        let mut subject = ConnectionProgress::new(initial_node_descriptor.clone());
        let pass_target = make_ip(2);

        subject.handle_pass_gossip(&Logger::new(test_name), pass_target);

        assert_eq!(
            subject,
            ConnectionProgress {
                initial_node_descriptor,
                current_peer_addr: pass_target,
                connection_stage: ConnectionStage::StageZero
            }
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: {test_name}: Pass gossip received from Node with IP Address 1.1.1.1 to a Node \
            with IP Address 1.1.1.2. Requested to update the stage from StageZero to StageZero."
        ));
    }

    #[test]
    #[should_panic(
        expected = "Pass gossip received from Node with IP Address 1.1.1.1 to a Node \
        with IP Address 1.1.1.2. Can't update the stage from NeighborshipEstablished to StageZero"
    )]
    fn connection_progress_panics_while_handling_pass_gossip_in_case_tcp_connection_is_not_established(
    ) {
        let ip_addr = make_ip(1);
        let initial_node_descriptor = make_node_descriptor(ip_addr);
        let mut subject = ConnectionProgress::new(initial_node_descriptor);
        subject.connection_stage = ConnectionStage::NeighborshipEstablished;
        let pass_target = make_ip(2);

        subject.handle_pass_gossip(&Logger::new("test"), pass_target);
    }

    #[test]
    fn overall_connection_stage_can_be_converted_into_usize_and_can_be_compared() {
        assert!(
            OverallConnectionStage::ConnectedToNeighbor as usize
                > OverallConnectionStage::NotConnected as usize
        );
        assert!(
            OverallConnectionStage::RouteFound as usize
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
    fn can_receive_a_result_of_connection_progress_from_peer_addr() {
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
    fn can_receive_current_peer_addrs() {
        let peer_1 = make_ip(1);
        let peer_2 = make_ip(2);
        let peer_3 = make_ip(3);
        let subject = OverallConnectionStatus::new(vec![
            make_node_descriptor(peer_1),
            make_node_descriptor(peer_2),
            make_node_descriptor(peer_3),
        ]);

        let result = subject.get_peer_addrs();

        assert_eq!(result, vec![peer_1, peer_2, peer_3]);
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
    fn updates_the_connection_stage_to_tcp_connection_established_and_performs_logging() {
        init_test_logging();
        let (node_ip_addr, node_descriptor) = make_node(1);
        let mut subject = OverallConnectionStatus::new(vec![node_descriptor.clone()]);

        OverallConnectionStatus::update_connection_stage(
            subject.get_connection_progress_by_ip(node_ip_addr).unwrap(),
            ConnectionProgressEvent::TcpConnectionSuccessful,
            &Logger::new(
                "updates_the_connection_stage_to_tcp_connection_established_and_performs_logging",
            ),
        );

        assert_eq!(
            subject,
            OverallConnectionStatus {
                stage: OverallConnectionStage::NotConnected,
                progress: vec![ConnectionProgress {
                    initial_node_descriptor: node_descriptor,
                    current_peer_addr: node_ip_addr,
                    connection_stage: ConnectionStage::TcpConnectionEstablished
                }],
            }
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: updates_the_connection_stage_to_tcp_connection_established_and_performs_logging\
            : The connection stage for Node with IP address 1.1.1.1 has been updated from {:?} to {:?}.",
            ConnectionStage::StageZero,
            ConnectionStage::TcpConnectionEstablished
        ));
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
            &Logger::new("updates_the_connection_stage_to_failed_when_tcp_connection_fails"),
        );

        assert_eq!(
            subject,
            OverallConnectionStatus {
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
        let logger = Logger::new("updates_the_connection_stage_to_neighborship_established_when_introduction_gossip_is_received");
        OverallConnectionStatus::update_connection_stage(
            connection_progress,
            ConnectionProgressEvent::TcpConnectionSuccessful,
            &logger,
        );

        OverallConnectionStatus::update_connection_stage(
            connection_progress,
            ConnectionProgressEvent::IntroductionGossipReceived(make_ip(1)),
            &logger,
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
        let logger = Logger::new("updates_the_connection_stage_to_neighborship_established_when_standard_gossip_is_received");
        OverallConnectionStatus::update_connection_stage(
            connection_progress,
            ConnectionProgressEvent::TcpConnectionSuccessful,
            &logger,
        );

        OverallConnectionStatus::update_connection_stage(
            connection_progress,
            ConnectionProgressEvent::StandardGossipReceived,
            &logger,
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
        let logger =
            Logger::new("updates_the_connection_stage_to_stage_zero_when_pass_gossip_is_received");
        OverallConnectionStatus::update_connection_stage(
            connection_progress_to_modify,
            ConnectionProgressEvent::TcpConnectionSuccessful,
            &logger,
        );

        OverallConnectionStatus::update_connection_stage(
            connection_progress_to_modify,
            ConnectionProgressEvent::PassGossipReceived(pass_target),
            &logger,
        );

        assert_eq!(
            subject,
            OverallConnectionStatus {
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
        let logger = Logger::new("updates_connection_stage_to_failed_when_pass_loop_is_found");
        OverallConnectionStatus::update_connection_stage(
            connection_progress_to_modify,
            ConnectionProgressEvent::TcpConnectionSuccessful,
            &logger,
        );

        OverallConnectionStatus::update_connection_stage(
            connection_progress_to_modify,
            ConnectionProgressEvent::PassLoopFound,
            &logger,
        );

        assert_eq!(
            subject,
            OverallConnectionStatus {
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
        let logger =
            Logger::new("updates_connection_stage_to_failed_when_no_gossip_response_is_received");
        OverallConnectionStatus::update_connection_stage(
            connection_progress_to_modify,
            ConnectionProgressEvent::TcpConnectionSuccessful,
            &logger,
        );

        OverallConnectionStatus::update_connection_stage(
            connection_progress_to_modify,
            ConnectionProgressEvent::NoGossipResponseReceived,
            &logger,
        );

        assert_eq!(
            subject,
            OverallConnectionStatus {
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
            &Logger::new("can_t_establish_neighborhsip_without_having_a_tcp_connection"),
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
        let route_found = OverallConnectionStage::RouteFound;

        let route_found_converted: UiConnectionStage = route_found.into();

        assert_eq!(route_found_converted, UiConnectionStage::RouteFound);
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
        let mut subject = OverallConnectionStatus::new(vec![node_descriptor]);

        let initial_flag = subject.can_make_routes();
        subject.stage = OverallConnectionStage::RouteFound;
        let final_flag = subject.can_make_routes();

        assert_eq!(initial_flag, false);
        assert_eq!(final_flag, true);
    }

    #[test]
    fn updates_the_ocs_stage_to_three_hops_route_found() {
        init_test_logging();
        let test_name = "updates_the_ocs_stage_to_three_hops_route_found";
        let initial_stage = OverallConnectionStage::NotConnected;
        let new_stage = OverallConnectionStage::RouteFound;

        let (stage, message_opt) =
            assert_stage_and_node_to_ui_message(initial_stage, new_stage, test_name);

        assert_eq!(stage, new_stage);
        assert_eq!(
            message_opt,
            Some(NodeToUiMessage {
                target: MessageTarget::AllClients,
                body: UiConnectionChangeBroadcast {
                    stage: new_stage.into()
                }
                .tmb(0)
            })
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {}: The stage of OverallConnectionStatus has been changed \
                from {:?} to {:?}. A message to the UI was also sent.",
            test_name, initial_stage, new_stage,
        ));
    }

    #[test]
    fn updates_the_ocs_stage_to_connected_to_neighbor() {
        init_test_logging();
        let test_name = "updates_the_ocs_stage_to_connected_to_neighbor";
        let initial_stage = OverallConnectionStage::NotConnected;
        let new_stage = OverallConnectionStage::ConnectedToNeighbor;

        let (stage, message_opt) =
            assert_stage_and_node_to_ui_message(initial_stage, new_stage, test_name);

        assert_eq!(stage, new_stage);
        assert_eq!(
            message_opt,
            Some(NodeToUiMessage {
                target: MessageTarget::AllClients,
                body: UiConnectionChangeBroadcast {
                    stage: new_stage.into()
                }
                .tmb(0)
            })
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {}: The stage of OverallConnectionStatus has been changed \
                from {:?} to {:?}. A message to the UI was also sent.",
            test_name, initial_stage, new_stage
        ));
    }

    #[test]
    fn does_not_send_message_to_the_ui_in_case_the_stage_has_not_updated() {
        init_test_logging();
        let test_name = "does_not_send_message_to_the_ui_in_case_the_stage_has_not_updated";
        let initial_stage = OverallConnectionStage::ConnectedToNeighbor;
        let new_stage = initial_stage;

        let (stage, message_opt) =
            assert_stage_and_node_to_ui_message(initial_stage, new_stage, test_name);

        assert_eq!(stage, initial_stage);
        assert_eq!(message_opt, None);
        TestLogHandler::new().exists_log_containing(&format!(
            "TRACE: {}: There was an attempt to update the stage of OverallConnectionStatus \
            from {:?} to {:?}. The request has been discarded.",
            test_name, initial_stage, new_stage
        ));
    }

    #[test]
    fn sends_a_message_to_ui_in_case_connection_drops_from_three_hops_to_connected_to_neighbor() {
        init_test_logging();
        let test_name = "sends_a_message_to_ui_in_case_connection_drops_from_three_hops_to_connected_to_neighbor";
        let initial_stage = OverallConnectionStage::RouteFound;
        let new_stage = OverallConnectionStage::ConnectedToNeighbor;

        let (stage, message_opt) =
            assert_stage_and_node_to_ui_message(initial_stage, new_stage, test_name);

        assert_eq!(stage, new_stage);
        assert_eq!(
            message_opt,
            Some(NodeToUiMessage {
                target: MessageTarget::AllClients,
                body: UiConnectionChangeBroadcast {
                    stage: new_stage.into()
                }
                .tmb(0)
            })
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {}: The stage of OverallConnectionStatus has been changed \
                from {:?} to {:?}. A message to the UI was also sent.",
            test_name, initial_stage, new_stage
        ));
    }

    #[test]
    fn getter_fn_for_the_stage_of_overall_connection_status_exists() {
        let subject = OverallConnectionStatus::new(vec![make_node_descriptor(make_ip(1))]);
        assert_eq!(subject.stage(), OverallConnectionStage::NotConnected);
    }

    fn assert_stage_and_node_to_ui_message(
        initial_stage: OverallConnectionStage,
        new_stage: OverallConnectionStage,
        test_name: &str,
    ) -> (OverallConnectionStage, Option<NodeToUiMessage>) {
        let mut subject =
            OverallConnectionStatus::new(vec![make_node_descriptor(make_ip(u8::MAX))]);
        let (node_to_ui_recipient, node_to_ui_recording_arc) = make_node_to_ui_recipient();
        subject.stage = initial_stage;
        let system = System::new(test_name);

        subject.update_ocs_stage_and_send_message_to_ui(
            new_stage,
            &node_to_ui_recipient,
            &Logger::new(test_name),
        );

        System::current().stop();
        assert_eq!(system.run(), 0);
        let stage = subject.stage;
        let recording = node_to_ui_recording_arc.lock().unwrap();
        let message_opt = recording.get_record_opt::<NodeToUiMessage>(0).cloned();

        (stage, message_opt)
    }
}
