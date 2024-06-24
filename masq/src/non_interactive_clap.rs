// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::schema::app;
use crate::terminal::async_streams::AsyncStdStreams;
use clap::error::ErrorKind;
use masq_lib::shared_schema::InsecurePort;

// pub trait NonInteractiveClapFactory: Send {
//     fn make(&self) -> Box<dyn InitialArgsParser>;
// }

// #[derive(Default)]
// pub struct NonInteractiveClapFactoryReal {}
//
// impl NonInteractiveClapFactory for NonInteractiveClapFactoryReal {
//     fn make(&self) -> Box<dyn InitialArgsParser> {
//         Box::new(InitialClapParserReal::default())
//     }
// }

pub trait InitialArgsParser {
    fn parse_initialization_args(
        &self,
        args: &[String],
        std_streams: &AsyncStdStreams,
    ) -> InitializationArgs;
}

#[derive(Default)]
pub struct InitialArgsParserReal {}

impl InitialArgsParser for InitialArgsParserReal {
    fn parse_initialization_args(
        &self,
        args: &[String],
        std_streams: &AsyncStdStreams,
    ) -> InitializationArgs {
        let matches = match app().try_get_matches_from(args) {
            Ok(m) => m,
            Err(e) if e.kind() == ErrorKind::DisplayHelp => {
                todo!()
            }
            Err(e) if e.kind() == ErrorKind::DisplayVersion => {
                todo!()
            }
            Err(e) => todo!(),
        };
        let ui_port = matches
            .get_one::<InsecurePort>("ui-port")
            .expect("ui-port is not properly defaulted")
            .port;
        InitializationArgs::new(ui_port)
    }
}

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
        let (streams, handles) = make_async_std_streams(vec![]);

        let result = InitialArgsParserReal::default().parse_initialization_args(
            &vec!["masq", "setup", "--chain"]
                .iter()
                .map(|str| str.to_string())
                .collect::<Vec<String>>(),
            &streams,
        );

        assert_eq!(result.ui_port, DEFAULT_UI_PORT);
        handles.assert_empty_stderr();
        handles.assert_empty_stdout();
    }

    #[tokio::test]
    async fn initial_args_parser_real_produces_custom_values() {
        let (streams, handles) = make_async_std_streams(vec![]);

        let result = InitialArgsParserReal::default().parse_initialization_args(
            &vec!["masq", "--ui-port", "10000", "setup", "--log-level", "off"]
                .iter()
                .map(|str| str.to_string())
                .collect::<Vec<String>>(),
            &streams,
        );

        assert_eq!(result.ui_port, 10000);
        handles.assert_empty_stderr();
        handles.assert_empty_stdout();
    }
}
