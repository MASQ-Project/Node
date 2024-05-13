// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::terminal::terminal_interface::TerminalWrapper;
use masq_lib::messages::{UiConnectionChangeBroadcast, UiConnectionStage};
use masq_lib::short_writeln;
use std::io::Write;
use tokio::io::AsyncWrite;

pub struct ConnectionChangeNotification {}

impl ConnectionChangeNotification {
    pub async fn handle_broadcast(
        response: UiConnectionChangeBroadcast,
        stdout: &mut dyn Write,
        term_interface: &TerminalWrapper,
    ) {
        let _lock = term_interface.lock();
        let output_string = match response.stage {
            UiConnectionStage::NotConnected => {
                todo!("This code is unreachable before GH-623 gets implemented. Hence this todo should be replaced with some code once the card is played.")
            }
            UiConnectionStage::ConnectedToNeighbor => {
                "\nConnectedToNeighbor: Established neighborship with an external node.\n"
            }
            UiConnectionStage::RouteFound => {
                "\nRouteFound: You can now relay data over the network.\n"
            }
        };
        short_writeln!(stdout, "{}", output_string);
        stdout.flush().expect("flush failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::mocks::TerminalPassiveMock;
    use masq_lib::test_utils::fake_stream_holder::ByteArrayWriter;
    use masq_lib::utils::running_test;
    use std::sync::Arc;

    #[test]
    fn broadcasts_connected_to_neighbor() {
        running_test();
        let mut stdout = ByteArrayWriter::new();
        let stderr = ByteArrayWriter::new();
        let msg = UiConnectionChangeBroadcast {
            stage: UiConnectionStage::ConnectedToNeighbor,
        };
        let term_interface = TerminalWrapper::new(Arc::new(TerminalPassiveMock::new()));

        ConnectionChangeNotification::handle_broadcast(msg, &mut stdout, &term_interface);

        assert_eq!(
            stdout.get_string(),
            "\nConnectedToNeighbor: Established neighborship with an external node.\n\n"
        );
        assert_eq!(stderr.get_string(), "".to_string());
    }

    #[test]
    fn broadcasts_route_found() {
        running_test();
        let mut stdout = ByteArrayWriter::new();
        let stderr = ByteArrayWriter::new();
        let msg = UiConnectionChangeBroadcast {
            stage: UiConnectionStage::RouteFound,
        };
        let term_interface = TerminalWrapper::new(Arc::new(TerminalPassiveMock::new()));

        ConnectionChangeNotification::handle_broadcast(msg, &mut stdout, &term_interface);

        assert_eq!(
            stdout.get_string(),
            "\nRouteFound: You can now relay data over the network.\n\n"
        );
        assert_eq!(stderr.get_string(), "".to_string());
    }
}
