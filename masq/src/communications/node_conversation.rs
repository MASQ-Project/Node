// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::communications::connection_manager::OutgoingMessageType;
use masq_lib::ui_gateway::{MessageBody, MessagePath};
use masq_lib::ui_traffic_converter::UnmarshalError;
use std::fmt::{Debug, Formatter};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

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
    conversations_to_manager_tx: async_channel::Sender<OutgoingMessageType>,
    manager_to_conversation_rx: ManagerToConversationReceiver,
    closing_stage: Arc<AtomicBool>,
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

pub type ManagerToConversationReceiver =
    async_channel::Receiver<Result<MessageBody, NodeConversationTermination>>;

pub type ManagerToConversationSender =
    async_channel::Sender<Result<MessageBody, NodeConversationTermination>>;

impl NodeConversation {
    pub fn new(
        context_id: u64,
        conversations_to_manager_tx: async_channel::Sender<OutgoingMessageType>,
        manager_to_conversation_rx: ManagerToConversationReceiver,
        closing_stage: Arc<AtomicBool>,
    ) -> Self {
        Self {
            context_id,
            conversations_to_manager_tx,
            manager_to_conversation_rx,
            closing_stage,
        }
    }

    pub fn context_id(&self) -> u64 {
        self.context_id
    }

    pub async fn send(&self, outgoing_msg: MessageBody) -> Result<(), ClientError> {
        if let MessagePath::Conversation(_) = outgoing_msg.path {
            panic! ("Cannot use NodeConversation::send() to send message with MessagePath::Conversation(_). Use NodeConversation::transact() instead.")
        }

        if self.closing_stage.load(Ordering::Relaxed) {
            return Err(ClientError::ConnectionDropped);
        }

        match self
            .conversations_to_manager_tx
            .send(OutgoingMessageType::FireAndForgetMessage(
                outgoing_msg.clone(),
                self.context_id,
            ))
            .await
        {
            Ok(_) => match self.manager_to_conversation_rx.recv().await {
                Ok(Ok(_)) => panic!("Fire-and-forget messages should not receive responses"),
                Ok(Err(NodeConversationTermination::Graceful)) => Ok(()),
                Ok(Err(NodeConversationTermination::Resend)) => {
                    Box::pin(self.send(outgoing_msg)).await
                }
                Ok(Err(NodeConversationTermination::Fatal)) => Ok(()),
                Ok(Err(NodeConversationTermination::FiredAndForgotten)) => Ok(()),
                Err(e) => panic!("Channel to ConnectionManager is already closed"), //TODO tested???
            },
            Err(_) => Err(ClientError::ConnectionDropped),
        }
    }

    pub async fn transact(
        &self,
        mut outgoing_msg: MessageBody,
        timeout_millis: u64,
    ) -> Result<MessageBody, ClientError> {
        if outgoing_msg.path == MessagePath::FireAndForget {
            panic! ("Cannot use NodeConversation::transact() to send message with MessagePath::FireAndForget. Use NodeConversation::send() instead.")
        }

        if self.closing_stage.load(Ordering::Relaxed) {
            return Err(ClientError::ConnectionDropped);
        }

        outgoing_msg.path = MessagePath::Conversation(self.context_id());
        match self
            .conversations_to_manager_tx
            .send(OutgoingMessageType::ConversationMessage(
                outgoing_msg.clone(),
            ))
            .await
        {
            Ok(_) => {
                let fut = self.manager_to_conversation_rx.recv();
                // (Duration::from_millis(timeout_millis))
                let time_out = Instant::now() + Duration::from_millis(timeout_millis);
                let recv_result = match tokio::time::timeout_at(time_out, fut).await {
                    Ok(result) => result,
                    Err(_) => return Err(ClientError::Timeout(timeout_millis)),
                };
                // let recv_result = self
                //     .manager_to_conversation_rx
                //     .recv_timeout(Duration::from_millis(timeout_millis));
                //TODO go through all the cases and see if each fails on a panic as there is always a test relating to them
                match recv_result {
                    Ok(Ok(body)) => Ok(body),
                    Ok(Err(NodeConversationTermination::Graceful)) => {
                        Err(ClientError::ConnectionDropped)
                    }
                    Ok(Err(NodeConversationTermination::Resend)) => {
                        Box::pin(self.transact(outgoing_msg, timeout_millis)).await
                    }
                    Ok(Err(NodeConversationTermination::Fatal)) => {
                        Err(ClientError::ConnectionDropped)
                    }
                    Ok(Err(NodeConversationTermination::FiredAndForgotten)) => {
                        panic!("Two-way transaction should never result in FiredAndForgotten")
                    }
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
        async_channel::Sender<OutgoingMessageType>,
        async_channel::Receiver<Result<MessageBody, NodeConversationTermination>>,
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
    use async_channel::TryRecvError;
    use masq_lib::messages::FromMessageBody;
    use masq_lib::messages::ToMessageBody;
    use masq_lib::messages::{UiShutdownRequest, UiShutdownResponse, UiUnmarshalError};
    use masq_lib::test_utils::utils::make_rt;
    use tokio::sync::mpsc::unbounded_channel;

    fn make_subject() -> (
        NodeConversation,
        ManagerToConversationSender,
        async_channel::Receiver<OutgoingMessageType>,
    ) {
        let (message_body_send_tx, message_body_send_rx) = async_channel::unbounded();
        let (message_body_receive_tx, message_body_receive_rx) = async_channel::unbounded();
        let subject = NodeConversation::new(
            42,
            message_body_send_tx,
            message_body_receive_rx,
            Arc::new(AtomicBool::new(false)),
        );
        (subject, message_body_receive_tx, message_body_send_rx)
    }

    #[tokio::test]
    async fn transact_handles_successful_transaction() {
        let (subject, message_body_receive_tx, mut message_body_send_rx) = make_subject();
        message_body_receive_tx
            .send(Ok(UiShutdownResponse {}.tmb(42)))
            .await
            .unwrap();

        let result = subject
            .transact(UiShutdownRequest {}.tmb(0), 1000)
            .await
            .unwrap();

        assert_eq!(result, UiShutdownResponse {}.tmb(42));
        let outgoing_message = message_body_send_rx.recv().await.unwrap();
        assert_eq!(
            outgoing_message,
            OutgoingMessageType::ConversationMessage(UiShutdownRequest {}.tmb(42))
        );
    }

    #[tokio::test]
    #[should_panic(
        expected = "Cannot use NodeConversation::transact() to send message with MessagePath::FireAndForget. Use NodeConversation::send() instead."
    )]
    async fn transact_rejects_fire_and_forget_message() {
        let (subject, _, _) = make_subject();
        let message = UiUnmarshalError {
            message: "Message".to_string(),
            bad_data: "Data".to_string(),
        };

        let _ = subject.transact(message.tmb(0), 1000).await;
    }

    #[tokio::test]
    async fn transact_handles_gracefully_closed_conversation() {
        let (subject, message_body_receive_tx, _) = make_subject();
        message_body_receive_tx
            .send(Err(NodeConversationTermination::Graceful))
            .await
            .unwrap();
        message_body_receive_tx
            .send(Ok(UiShutdownResponse {}.tmb(42)))
            .await
            .unwrap();

        let result = subject
            .transact(UiShutdownRequest {}.tmb(0), 1000)
            .await
            .err()
            .unwrap();

        assert_eq!(result, ClientError::ConnectionDropped);
    }

    #[tokio::test]
    async fn transact_handles_resend_order() {
        let (subject, message_body_receive_tx, mut message_body_send_rx) = make_subject();
        message_body_receive_tx
            .send(Err(NodeConversationTermination::Resend))
            .await
            .unwrap();
        message_body_receive_tx
            .send(Ok(UiShutdownResponse {}.tmb(42)))
            .await
            .unwrap();

        let result = subject
            .transact(UiShutdownRequest {}.tmb(0), 1000)
            .await
            .unwrap();

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
        assert_eq!(message_body_send_rx.try_recv(), Err(TryRecvError::Empty));
    }

    #[tokio::test]
    async fn transact_handles_broken_connection() {
        let (subject, message_body_receive_tx, mut message_body_send_rx) = make_subject();
        message_body_receive_tx
            .send(Err(NodeConversationTermination::Fatal))
            .await
            .unwrap();

        let result = subject.transact(UiShutdownRequest {}.tmb(0), 1000).await;

        assert_eq!(result, Err(ClientError::ConnectionDropped));
        let outgoing_message = match message_body_send_rx.recv().await.unwrap() {
            OutgoingMessageType::ConversationMessage(message_body) => message_body,
            x => panic!("Expected ConversationMessage; got {:?}", x),
        };
        assert_eq!(outgoing_message, UiShutdownRequest {}.tmb(42));
    }

    #[tokio::test]
    async fn transact_handles_send_error() {
        let (subject, _, _) = make_subject();

        let result = subject
            .transact(UiShutdownRequest {}.tmb(0), 1000)
            .await
            .err()
            .unwrap();

        assert_eq!(result, ClientError::ConnectionDropped);
    }

    #[tokio::test]
    async fn transact_handles_receive_error() {
        let (message_body_send_tx, _) = async_channel::unbounded();
        let (_, message_body_receive_rx) = async_channel::unbounded();
        let subject = NodeConversation::new(
            42,
            message_body_send_tx,
            message_body_receive_rx,
            Arc::new(AtomicBool::new(false)),
        );

        let result = subject
            .transact(UiShutdownRequest {}.tmb(24), 1000)
            .await
            .err()
            .unwrap();

        assert_eq!(result, ClientError::ConnectionDropped);
    }

    #[tokio::test]
    async fn transact_handles_timeout() {
        let (subject, _message_body_receive_tx, _message_body_send_rx) = make_subject();

        let result = subject
            .transact(UiShutdownRequest {}.tmb(24), 100)
            .await
            .err()
            .unwrap();

        assert_eq!(result, ClientError::Timeout(100));
    }

    #[tokio::test]
    async fn send_handles_successful_transmission() {
        let (mut subject, message_body_send_tx, mut message_body_send_rx) = make_subject();
        let message = UiUnmarshalError {
            message: "Message".to_string(),
            bad_data: "Data".to_string(),
        };
        message_body_send_tx
            .send(Err(FiredAndForgotten))
            .await
            .unwrap();

        subject.send(message.clone().tmb(0)).await.unwrap();

        let (outgoing_message, context_id) = match message_body_send_rx.recv().await.unwrap() {
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

    #[tokio::test]
    #[should_panic(
        expected = "Cannot use NodeConversation::send() to send message with MessagePath::Conversation(_). Use NodeConversation::transact() instead."
    )]
    async fn send_rejects_conversation_message() {
        let (mut subject, _, _) = make_subject();
        let message = UiShutdownRequest {};

        let _ = subject.send(message.tmb(0)).await;
    }

    #[tokio::test]
    async fn send_handles_graceful() {
        let (mut subject, message_body_receive_tx, _message_body_send_rx) = make_subject();
        let message = UiUnmarshalError {
            message: "Message".to_string(),
            bad_data: "Data".to_string(),
        };
        message_body_receive_tx
            .send(Err(NodeConversationTermination::Graceful))
            .await
            .unwrap();

        let result = subject.send(message.clone().tmb(0)).await;

        assert_eq!(result, Ok(()));
    }

    #[tokio::test]
    async fn send_handles_resend() {
        let (mut subject, message_body_receive_tx, _message_body_send_rx) = make_subject();
        let message = UiUnmarshalError {
            message: "Message".to_string(),
            bad_data: "Data".to_string(),
        };
        message_body_receive_tx
            .send(Err(NodeConversationTermination::Resend))
            .await
            .unwrap();
        message_body_receive_tx
            .send(Err(NodeConversationTermination::FiredAndForgotten))
            .await
            .unwrap();

        let result = subject.send(message.clone().tmb(0)).await;

        assert_eq!(result, Ok(()));
    }

    #[tokio::test]
    async fn send_handles_fatal() {
        let (mut subject, message_body_receive_tx, _message_body_send_rx) = make_subject();
        let message = UiUnmarshalError {
            message: "Message".to_string(),
            bad_data: "Data".to_string(),
        };
        message_body_receive_tx
            .send(Err(NodeConversationTermination::Fatal))
            .await
            .unwrap();

        let result = subject.send(message.clone().tmb(0)).await;

        assert_eq!(result, Ok(()));
    }
}
