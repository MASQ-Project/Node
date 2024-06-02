// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::communications::connection_manager::OutgoingMessageType;
use crossbeam_channel::{RecvTimeoutError, Sender};
use masq_lib::ui_gateway::{MessageBody, MessagePath};
use masq_lib::ui_traffic_converter::UnmarshalError;
use std::fmt::{Debug, Formatter};
use std::time::Duration;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientError {
    // TODO: Perhaps this can be combined with NodeConversationTermination
    NoServer(u16, String),
    ConnectionDropped,
    FallbackFailed(String),
    PacketType(String),
    Deserialization(UnmarshalError),
    Timeout(u64),
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum NodeConversationTermination {
    Graceful,
    Resend,
    Fatal,
    FiredAndForgotten,
}

pub struct NodeConversation {
    context_id: u64,
    conversations_to_manager_tx: UnboundedSender<OutgoingMessageType>,
    manager_to_conversation_rx:
        crossbeam_channel::Receiver<Result<MessageBody, NodeConversationTermination>>,
}

impl Drop for NodeConversation {
    fn drop(&mut self) {
        let _ = self
            .conversations_to_manager_tx
            .send(OutgoingMessageType::SignOff(self.context_id()));
    }
}

impl Debug for NodeConversation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Conversation {}", self.context_id)
    }
}

impl NodeConversation {
    pub fn new(
        context_id: u64,
        conversations_to_manager_tx: UnboundedSender<OutgoingMessageType>,
        manager_to_conversation_rx: crossbeam_channel::Receiver<
            Result<MessageBody, NodeConversationTermination>,
        >,
    ) -> Self {
        Self {
            context_id,
            conversations_to_manager_tx,
            manager_to_conversation_rx,
        }
    }

    pub fn context_id(&self) -> u64 {
        self.context_id
    }

    pub fn send(&self, outgoing_msg: MessageBody) -> Result<(), ClientError> {
        if let MessagePath::Conversation(_) = outgoing_msg.path {
            panic! ("Cannot use NodeConversation::send() to send message with MessagePath::Conversation(_). Use NodeConversation::transact() instead.")
        }
        match self
            .conversations_to_manager_tx
            .send(OutgoingMessageType::FireAndForgetMessage(
                outgoing_msg.clone(),
                self.context_id,
            )) {
            Ok(_) => match self.manager_to_conversation_rx.recv() {
                Ok(Ok(_)) => panic!("Fire-and-forget messages should not receive responses"),
                Ok(Err(NodeConversationTermination::Graceful)) => Ok(()),
                Ok(Err(NodeConversationTermination::Resend)) => self.send(outgoing_msg),
                Ok(Err(NodeConversationTermination::Fatal)) => Ok(()),
                Ok(Err(NodeConversationTermination::FiredAndForgotten)) => Ok(()),
                Err(e) => panic!("ConnectionManager is dead: {:?}", e),
            },
            Err(_) => Err(ClientError::ConnectionDropped),
        }
    }

    pub fn transact(
        &self,
        mut outgoing_msg: MessageBody,
        timeout_millis: u64,
    ) -> Result<MessageBody, ClientError> {
        if outgoing_msg.path == MessagePath::FireAndForget {
            panic! ("Cannot use NodeConversation::transact() to send message with MessagePath::FireAndForget. Use NodeConversation::send() instead.")
        }
        outgoing_msg.path = MessagePath::Conversation(self.context_id());
        match self
            .conversations_to_manager_tx
            .send(OutgoingMessageType::ConversationMessage(
                outgoing_msg.clone(),
            )) {
            Ok(_) => {
                let recv_result = self
                    .manager_to_conversation_rx
                    .recv_timeout(Duration::from_millis(timeout_millis));
                match recv_result {
                    Ok(Ok(body)) => Ok(body),
                    Ok(Err(NodeConversationTermination::Graceful)) => {
                        Err(ClientError::ConnectionDropped)
                    }
                    Ok(Err(NodeConversationTermination::Resend)) => {
                        self.transact(outgoing_msg, timeout_millis)
                    }
                    Ok(Err(NodeConversationTermination::Fatal)) => {
                        Err(ClientError::ConnectionDropped)
                    }
                    Ok(Err(NodeConversationTermination::FiredAndForgotten)) => {
                        panic!("Two-way transaction should never result in FiredAndForgotten")
                    }
                    Err(RecvTimeoutError::Timeout) => Err(ClientError::Timeout(timeout_millis)),
                    Err(_) => Err(ClientError::ConnectionDropped),
                }
            }
            Err(_) => Err(ClientError::ConnectionDropped),
        }
    }

    #[cfg(test)]
    pub fn tx_rx(
        &self,
    ) -> (
        UnboundedSender<OutgoingMessageType>,
        crossbeam_channel::Receiver<Result<MessageBody, NodeConversationTermination>>,
    ) {
        (
            self.conversations_to_manager_tx.clone(),
            self.manager_to_conversation_rx.clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::communications::node_conversation::NodeConversationTermination::FiredAndForgotten;
    use crossbeam_channel::unbounded;
    use masq_lib::messages::FromMessageBody;
    use masq_lib::messages::ToMessageBody;
    use masq_lib::messages::{UiShutdownRequest, UiShutdownResponse, UiUnmarshalError};
    use masq_lib::test_utils::utils::make_rt;
    use tokio::sync::mpsc::unbounded_channel;

    fn make_subject() -> (
        NodeConversation,
        Sender<Result<MessageBody, NodeConversationTermination>>,
        UnboundedReceiver<OutgoingMessageType>,
    ) {
        let (message_body_send_tx, message_body_send_rx) = unbounded_channel();
        let (message_body_receive_tx, message_body_receive_rx) = unbounded();
        let subject = NodeConversation::new(42, message_body_send_tx, message_body_receive_rx);
        (subject, message_body_receive_tx, message_body_send_rx)
    }

    #[test]
    fn transact_handles_successful_transaction() {
        let (subject, message_body_receive_tx, mut message_body_send_rx) = make_subject();
        message_body_receive_tx
            .send(Ok(UiShutdownResponse {}.tmb(42)))
            .unwrap();

        let result = subject.transact(UiShutdownRequest {}.tmb(0), 1000).unwrap();

        assert_eq!(result, UiShutdownResponse {}.tmb(42));
        let outgoing_message = make_rt().block_on(message_body_send_rx.recv()).unwrap();
        assert_eq!(
            outgoing_message,
            OutgoingMessageType::ConversationMessage(UiShutdownRequest {}.tmb(42))
        );
    }

    #[test]
    #[should_panic(
        expected = "Cannot use NodeConversation::transact() to send message with MessagePath::FireAndForget. Use NodeConversation::send() instead."
    )]
    fn transact_rejects_fire_and_forget_message() {
        let (subject, _, _) = make_subject();
        let message = UiUnmarshalError {
            message: "Message".to_string(),
            bad_data: "Data".to_string(),
        };

        let _ = subject.transact(message.tmb(0), 1000);
    }

    #[test]
    fn transact_handles_gracefully_closed_conversation() {
        let (subject, message_body_receive_tx, _) = make_subject();
        message_body_receive_tx
            .send(Err(NodeConversationTermination::Graceful))
            .unwrap();
        message_body_receive_tx
            .send(Ok(UiShutdownResponse {}.tmb(42)))
            .unwrap();

        let result = subject
            .transact(UiShutdownRequest {}.tmb(0), 1000)
            .err()
            .unwrap();

        assert_eq!(result, ClientError::ConnectionDropped);
    }

    #[test]
    fn transact_handles_resend_order() {
        let (subject, message_body_receive_tx, mut message_body_send_rx) = make_subject();
        message_body_receive_tx
            .send(Err(NodeConversationTermination::Resend))
            .unwrap();
        message_body_receive_tx
            .send(Ok(UiShutdownResponse {}.tmb(42)))
            .unwrap();

        let result = subject.transact(UiShutdownRequest {}.tmb(0), 1000).unwrap();

        assert_eq!(result, UiShutdownResponse {}.tmb(42));
        let outgoing_message = message_body_send_rx.try_recv().unwrap();
        assert_eq!(
            outgoing_message,
            OutgoingMessageType::ConversationMessage(UiShutdownRequest {}.tmb(42))
        );
        let outgoing_message = message_body_send_rx.try_recv().unwrap();
        assert_eq!(
            outgoing_message,
            OutgoingMessageType::ConversationMessage(UiShutdownRequest {}.tmb(42))
        );
        assert_eq!(
            message_body_send_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        );
    }

    #[test]
    fn transact_handles_broken_connection() {
        let (subject, message_body_receive_tx, mut message_body_send_rx) = make_subject();
        message_body_receive_tx
            .send(Err(NodeConversationTermination::Fatal))
            .unwrap();

        let result = subject.transact(UiShutdownRequest {}.tmb(0), 1000);

        assert_eq!(result, Err(ClientError::ConnectionDropped));
        let outgoing_message = match make_rt().block_on(message_body_send_rx.recv()).unwrap() {
            OutgoingMessageType::ConversationMessage(message_body) => message_body,
            x => panic!("Expected ConversationMessage; got {:?}", x),
        };
        assert_eq!(outgoing_message, UiShutdownRequest {}.tmb(42));
    }

    #[test]
    fn transact_handles_send_error() {
        let (subject, _, _) = make_subject();

        let result = subject
            .transact(UiShutdownRequest {}.tmb(0), 1000)
            .err()
            .unwrap();

        assert_eq!(result, ClientError::ConnectionDropped);
    }

    #[test]
    fn transact_handles_receive_error() {
        let (message_body_send_tx, _) = unbounded_channel();
        let (_, message_body_receive_rx) = unbounded();
        let subject = NodeConversation::new(42, message_body_send_tx, message_body_receive_rx);

        let result = subject
            .transact(UiShutdownRequest {}.tmb(24), 1000)
            .err()
            .unwrap();

        assert_eq!(result, ClientError::ConnectionDropped);
    }

    #[test]
    fn transact_handles_timeout() {
        let (subject, _message_body_receive_tx, _message_body_send_rx) = make_subject();

        let result = subject
            .transact(UiShutdownRequest {}.tmb(24), 100)
            .err()
            .unwrap();

        assert_eq!(result, ClientError::Timeout(100));
    }

    #[test]
    fn send_handles_successful_transmission() {
        let (subject, message_body_send_tx, mut message_body_send_rx) = make_subject();
        let message = UiUnmarshalError {
            message: "Message".to_string(),
            bad_data: "Data".to_string(),
        };
        let _ = message_body_send_tx.send(Err(FiredAndForgotten));

        subject.send(message.clone().tmb(0)).unwrap();

        let (outgoing_message, context_id) =
            match make_rt().block_on(message_body_send_rx.recv()).unwrap() {
                OutgoingMessageType::FireAndForgetMessage(message_body, context_id) => {
                    (message_body, context_id)
                }
                x => panic!("Expected FireAndForgetMessage, got {:?}", x),
            };
        assert_eq!(
            UiUnmarshalError::fmb(outgoing_message).unwrap(),
            (message, 0)
        );
        assert_eq!(context_id, 42);
    }

    #[test]
    #[should_panic(
        expected = "Cannot use NodeConversation::send() to send message with MessagePath::Conversation(_). Use NodeConversation::transact() instead."
    )]
    fn send_rejects_conversation_message() {
        let (subject, _, _) = make_subject();
        let message = UiShutdownRequest {};

        let _ = subject.send(message.tmb(0));
    }

    #[test]
    fn send_handles_graceful() {
        let (subject, message_body_receive_tx, _message_body_send_rx) = make_subject();
        let message = UiUnmarshalError {
            message: "Message".to_string(),
            bad_data: "Data".to_string(),
        };
        message_body_receive_tx
            .send(Err(NodeConversationTermination::Graceful))
            .unwrap();

        let result = subject.send(message.clone().tmb(0));

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn send_handles_resend() {
        let (subject, message_body_receive_tx, _message_body_send_rx) = make_subject();
        let message = UiUnmarshalError {
            message: "Message".to_string(),
            bad_data: "Data".to_string(),
        };
        message_body_receive_tx
            .send(Err(NodeConversationTermination::Resend))
            .unwrap();
        message_body_receive_tx
            .send(Err(NodeConversationTermination::FiredAndForgotten))
            .unwrap();

        let result = subject.send(message.clone().tmb(0));

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn send_handles_fatal() {
        let (subject, message_body_receive_tx, _message_body_send_rx) = make_subject();
        let message = UiUnmarshalError {
            message: "Message".to_string(),
            bad_data: "Data".to_string(),
        };
        message_body_receive_tx
            .send(Err(NodeConversationTermination::Fatal))
            .unwrap();

        let result = subject.send(message.clone().tmb(0));

        assert_eq!(result, Ok(()));
    }
}
