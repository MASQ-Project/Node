// Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::ContextError::ConnectionRefused;
use crate::communications::broadcast_handler::{
    BroadcastHandler, BroadcastHandlerReal, StreamFactory,
};
use crate::communications::connection_manager::ConnectionManager;
use crate::communications::node_conversation::ClientError;
use masq_lib::ui_gateway::MessageBody;
use std::io;
use std::io::{Read, Write};

#[derive(Clone, Debug, PartialEq)]
pub enum ContextError {
    ConnectionRefused(String),
    ConnectionDropped(String),
    PayloadError(u64, String),
    RedirectFailure(String),
    Other(String),
}

pub trait CommandContext {
    fn active_port(&self) -> u16;
    fn transact(&mut self, message: MessageBody) -> Result<MessageBody, ContextError>;
    fn stdin(&mut self) -> &mut dyn Read;
    fn stdout(&mut self) -> &mut dyn Write;
    fn stderr(&mut self) -> &mut dyn Write;
    fn close(&mut self);
}

pub struct CommandContextReal {
    connection: ConnectionManager,
    pub stdin: Box<dyn Read>,
    pub stdout: Box<dyn Write>,
    pub stderr: Box<dyn Write>,
}

impl CommandContext for CommandContextReal {
    fn active_port(&self) -> u16 {
        self.connection.active_ui_port()
    }

    fn transact(&mut self, outgoing_message: MessageBody) -> Result<MessageBody, ContextError> {
        let conversation = self.connection.start_conversation();
        let incoming_message_result = conversation.transact(outgoing_message);
        let incoming_message = match incoming_message_result {
            Err(ClientError::FallbackFailed(e)) => return Err(ContextError::ConnectionDropped(e)),
            Err(ClientError::ConnectionDropped) => {
                return Err(ContextError::ConnectionDropped(String::new()))
            }
            Err(e) => panic!("No provision for error {:?}", e),
            Ok(message) => match message.payload {
                Err((code, msg)) => return Err(ContextError::PayloadError(code, msg)),
                Ok(_) => message,
            },
        };
        Ok(incoming_message)
    }

    fn stdin(&mut self) -> &mut dyn Read {
        &mut self.stdin
    }

    fn stdout(&mut self) -> &mut dyn Write {
        &mut self.stdout
    }

    fn stderr(&mut self) -> &mut dyn Write {
        &mut self.stderr
    }

    fn close(&mut self) {
        self.connection.close();
    }
}

impl CommandContextReal {
    pub fn new(
        daemon_ui_port: u16,
        broadcast_stream_factory: Box<dyn StreamFactory>,
    ) -> Result<Self, ContextError> {
        let mut connection = ConnectionManager::new();
        let broadcast_handler = BroadcastHandlerReal::new();
        let broadcast_handle = broadcast_handler.start(broadcast_stream_factory);
        match connection.connect(daemon_ui_port, broadcast_handle) {
            Ok(_) => Ok(Self {
                connection,
                stdin: Box::new(io::stdin()),
                stdout: Box::new(io::stdout()),
                stderr: Box::new(io::stderr()),
            }),
            Err(e) => Err(ConnectionRefused(format!("{:?}", e))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::ContextError::{
        ConnectionDropped, ConnectionRefused, PayloadError,
    };
    use crate::communications::broadcast_handler::StreamFactoryReal;
    use crate::test_utils::mock_websockets_server::MockWebSocketsServer;
    use masq_lib::messages::{FromMessageBody, UiSetupRequest};
    use masq_lib::messages::{ToMessageBody, UiShutdownRequest, UiShutdownResponse};
    use masq_lib::test_utils::fake_stream_holder::{ByteArrayReader, ByteArrayWriter};
    use masq_lib::ui_gateway::MessageBody;
    use masq_lib::ui_gateway::MessagePath::Conversation;
    use masq_lib::utils::find_free_port;

    #[test]
    fn sets_active_port_correctly_initially() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let handle = server.start();

        let subject = CommandContextReal::new(port, Box::new(StreamFactoryReal::new())).unwrap();

        assert_eq!(subject.active_port(), port);
        handle.kill();
    }

    #[test]
    fn works_when_everythings_fine() {
        let port = find_free_port();
        let stdin = ByteArrayReader::new(b"This is stdin.");
        let stdout = ByteArrayWriter::new();
        let stdout_arc = stdout.inner_arc();
        let stderr = ByteArrayWriter::new();
        let stderr_arc = stderr.inner_arc();
        let server = MockWebSocketsServer::new(port).queue_response(UiShutdownResponse {}.tmb(1));
        let stop_handle = server.start();
        let mut subject =
            CommandContextReal::new(port, Box::new(StreamFactoryReal::new())).unwrap();
        subject.stdin = Box::new(stdin);
        subject.stdout = Box::new(stdout);
        subject.stderr = Box::new(stderr);

        let response = subject.transact(UiShutdownRequest {}.tmb(1)).unwrap();
        let mut input = String::new();
        subject.stdin().read_to_string(&mut input).unwrap();
        write!(subject.stdout(), "This is stdout.").unwrap();
        write!(subject.stderr(), "This is stderr.").unwrap();

        stop_handle.stop();
        assert_eq!(
            UiShutdownResponse::fmb(response).unwrap(),
            (UiShutdownResponse {}, 1)
        );
        assert_eq!(input, "This is stdin.".to_string());
        assert_eq!(
            stdout_arc.lock().unwrap().get_string(),
            "This is stdout.".to_string()
        );
        assert_eq!(
            stderr_arc.lock().unwrap().get_string(),
            "This is stderr.".to_string()
        );
    }

    #[test]
    fn works_when_server_isnt_present() {
        let port = find_free_port();

        let result = CommandContextReal::new(port, Box::new(StreamFactoryReal::new()));

        match result {
            Err(ConnectionRefused(_)) => (),
            Ok(_) => panic!("Succeeded when it should have failed"),
            Err(e) => panic!("Expected ConnectionRefused; got {:?}", e),
        }
    }

    #[test]
    fn works_when_server_sends_payload_error() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port).queue_response(MessageBody {
            opcode: "setup".to_string(),
            path: Conversation(1),
            payload: Err((101, "booga".to_string())),
        });
        let stop_handle = server.start();
        let mut subject =
            CommandContextReal::new(port, Box::new(StreamFactoryReal::new())).unwrap();

        let response = subject.transact(UiSetupRequest { values: vec![] }.tmb(1));

        assert_eq!(response, Err(PayloadError(101, "booga".to_string())));
        stop_handle.stop();
    }

    #[test] // TODO Segfaults on the Mac in Actions
    fn works_when_server_sends_connection_error() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port).queue_string("disconnect");
        let stop_handle = server.start();
        let mut subject =
            CommandContextReal::new(port, Box::new(StreamFactoryReal::new())).unwrap();

        let response = subject.transact(UiSetupRequest { values: vec![] }.tmb(1));

        stop_handle.stop();
        match response {
            Err(ConnectionDropped(_)) => (),
            x => panic!("Expected ConnectionDropped; got {:?} instead", x),
        }
    }
}
