// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::run_modes::CLIProgramEntering;
use crate::schema::app;
use crate::terminal::async_streams::AsyncStdStreams;
use crate::write_async_stream_and_flush;
use async_trait::async_trait;
use clap::error::ErrorKind;
use masq_lib::shared_schema::InsecurePort;
use tokio::io::AsyncWriteExt;

#[async_trait(?Send)]
pub trait InitialArgsParser {
    async fn parse_initialization_args(
        &self,
        args: &[String],
        std_streams: &mut AsyncStdStreams,
    ) -> CLIProgramEntering;
}

#[derive(Default)]
pub struct InitialArgsParserReal {}

#[async_trait(?Send)]
impl InitialArgsParser for InitialArgsParserReal {
    async fn parse_initialization_args(
        &self,
        args: &[String],
        std_streams: &mut AsyncStdStreams,
    ) -> CLIProgramEntering {
        let matches = match app().try_get_matches_from(args) {
            Ok(m) => m,
            Err(e) if e.kind() == ErrorKind::DisplayHelp => {
                let help = app().render_long_help();
                write_async_stream_and_flush!(std_streams.stdout, "{}", help);
                return CLIProgramEntering::Leave(0);
            }
            Err(e) if e.kind() == ErrorKind::DisplayVersion => {
                let version = app().render_long_version();
                write_async_stream_and_flush!(std_streams.stdout, "{}", version);
                return CLIProgramEntering::Leave(0);
            }
            Err(e) => {
                write_async_stream_and_flush!(std_streams.stderr, "{}", e);
                return CLIProgramEntering::Leave(1);
            }
        };
        let ui_port = matches
            .get_one::<InsecurePort>("ui-port")
            .expect("ui-port is not properly defaulted")
            .port;

        CLIProgramEntering::Enter(InitializationArgs::new(ui_port))
    }
}

#[derive(Debug)]
pub struct InitializationArgs {
    pub ui_port: u16,
}

impl InitializationArgs {
    pub fn new(ui_port: u16) -> Self {
        Self { ui_port }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::mocks::make_async_std_streams;
    use masq_lib::constants::DEFAULT_UI_PORT;

    #[tokio::test]
    async fn initial_args_parser_real_produces_default_values() {
        let (mut streams, handles) = make_async_std_streams(vec![]);

        let result = InitialArgsParserReal::default()
            .parse_initialization_args(
                &vec!["masq", "setup", "--chain"]
                    .iter()
                    .map(|str| str.to_string())
                    .collect::<Vec<String>>(),
                &mut streams,
            )
            .await;

        let init_args = match result {
            CLIProgramEntering::Enter(init_args) => init_args,
            x => panic!("we expected Enter with init args but got {:?}", x),
        };
        assert_eq!(init_args.ui_port, DEFAULT_UI_PORT);
        handles.assert_empty_stderr();
        handles.assert_empty_stdout();
    }

    #[tokio::test]
    async fn initial_args_parser_real_produces_custom_values() {
        let (mut streams, handles) = make_async_std_streams(vec![]);

        let result = InitialArgsParserReal::default()
            .parse_initialization_args(
                &vec!["masq", "--ui-port", "10000", "setup", "--log-level", "off"]
                    .iter()
                    .map(|str| str.to_string())
                    .collect::<Vec<String>>(),
                &mut streams,
            )
            .await;

        let init_args = match result {
            CLIProgramEntering::Enter(init_args) => init_args,
            x => panic!("we expected Enter with init args but got {:?}", x),
        };
        assert_eq!(init_args.ui_port, 10000);
        handles.assert_empty_stderr();
        handles.assert_empty_stdout();
    }

    #[tokio::test]
    async fn initial_args_parser_can_display_help() {
        let (mut streams, handles) = make_async_std_streams(vec![]);

        let result = InitialArgsParserReal::default()
            .parse_initialization_args(
                &vec!["masq", "--help"]
                    .iter()
                    .map(|str| str.to_string())
                    .collect::<Vec<String>>(),
                &mut streams,
            )
            .await;

        match result {
            CLIProgramEntering::Leave(0) => (),
            x => panic!("we expected Leave with exit code 0 but got {:?}", x),
        };
        handles.assert_empty_stderr();
        let stdout = handles.stdout_all_in_one();
        assert!(stdout.contains("Usage: masq [OPTIONS] [COMMAND]") &&
                    stdout.contains("configuration      Displays a running Node's current configuration.") &&
                    stdout.contains("setup              Establishes (if Node is not already running) and displays startup parameters for MASQNode.")
                , "We expected a help message but got: {}", stdout);
    }

    #[tokio::test]
    async fn initial_args_parser_can_display_version() {
        let (mut streams, handles) = make_async_std_streams(vec![]);

        let result = InitialArgsParserReal::default()
            .parse_initialization_args(
                &vec!["masq", "--version"]
                    .iter()
                    .map(|str| str.to_string())
                    .collect::<Vec<String>>(),
                &mut streams,
            )
            .await;

        match result {
            CLIProgramEntering::Leave(0) => (),
            x => panic!("we expected Leave with exit code 0 but got {:?}", x),
        };
        handles.assert_empty_stderr();
        let stdout = handles.stdout_all_in_one();
        assert_eq!(
            stdout, "masq 1.0.0\n",
            "We expected to see the MASQ's version but got: {}",
            stdout
        );
    }

    #[tokio::test]
    async fn initial_args_parser_catches_unintelligible_args() {
        let inputs = vec![
            (
                vec!["masq", "command"],
                "error: unrecognized subcommand 'command'",
            ),
            (
                vec!["masq", "--ui-port"],
                "a value is required for '--ui-port <UI-PORT>' but none",
            ),
            (
                vec!["masq", "--display-cartoons"],
                "error: unexpected argument '--display-cartoons'",
            ),
        ];
        for (args, expected_msg_fragment) in inputs {
            let (mut streams, handles) = make_async_std_streams(vec![]);

            let result = InitialArgsParserReal::default()
                .parse_initialization_args(
                    &args
                        .iter()
                        .map(|str| str.to_string())
                        .collect::<Vec<String>>(),
                    &mut streams,
                )
                .await;

            match result {
                CLIProgramEntering::Leave(1) => (),
                x => panic!("we expected Leave with exit code 1 but got {:?}", x),
            };
            handles.assert_empty_stdout();
            let stderr = handles.stderr_all_in_one();
            assert!(
                stderr.contains(expected_msg_fragment),
                "We expected to see this fragment of \
            an error message from Clap: '{}', but this was invoked instead: '{}'",
                expected_msg_fragment,
                stderr
            );
        }
    }
}
