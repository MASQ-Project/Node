// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::terminal::terminal_interface::{TerminalWriter, WTermInterface};
use masq_lib::messages::{UiConnectionChangeBroadcast, UiConnectionStage};
use masq_lib::short_writeln;
use std::io::Write;

pub struct ConnectionChangeNotification {}

impl ConnectionChangeNotification {
    pub async fn handle_broadcast(
        response: UiConnectionChangeBroadcast,
        stdout: &TerminalWriter,
        stderr: &TerminalWriter,
    ) {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::mocks::make_terminal_writer;
    use masq_lib::test_utils::fake_stream_holder::ByteArrayWriter;
    use masq_lib::utils::running_test;
    use std::sync::Arc;

    #[tokio::test]
    async fn broadcasts_connected_to_neighbor() {
        running_test();
        let msg = UiConnectionChangeBroadcast {
            stage: UiConnectionStage::ConnectedToNeighbor,
        };
        let (stdout, stdout_handle) = make_terminal_writer();
        let (stderr, stderr_handle) = make_terminal_writer();

        ConnectionChangeNotification::handle_broadcast(msg, &stdout, &stderr).await;

        assert_eq!(
            stdout_handle.lock().unwrap().get_string(),
            "\nConnectedToNeighbor: Established neighborship with an external node.\n\n"
        );
        assert_eq!(stderr_handle.lock().unwrap().get_string(), "".to_string());
    }

    #[tokio::test]
    async fn broadcasts_route_found() {
        running_test();
        let msg = UiConnectionChangeBroadcast {
            stage: UiConnectionStage::RouteFound,
        };
        let (stdout, stdout_handle) = make_terminal_writer();
        let (stderr, stderr_handle) = make_terminal_writer();

        ConnectionChangeNotification::handle_broadcast(msg, &stdout, &stderr).await;

        assert_eq!(
            stdout_handle.lock().unwrap().get_string(),
            "\nRouteFound: You can now relay data over the network.\n\n"
        );
        assert_eq!(stderr_handle.lock().unwrap().get_string(), "".to_string());
    }
}
