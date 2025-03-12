// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::{
    transaction, Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS,
};
use crate::masq_short_writeln;
use crate::terminal::TerminalWriter;
use async_trait::async_trait;
use clap::{Arg, Command as ClapCommand};
use masq_lib::implement_as_any;
use masq_lib::messages::{UiWalletAddressesRequest, UiWalletAddressesResponse};
#[cfg(test)]
use std::any::Any;

#[derive(Debug, PartialEq, Eq)]
pub struct WalletAddressesCommand {
    pub db_password: String,
}

impl WalletAddressesCommand {
    pub fn new(pieces: &[String]) -> Result<Self, String> {
        let matches = match wallet_addresses_subcommand().try_get_matches_from(pieces) {
            Ok(matches) => matches,
            Err(e) => return Err(format!("{}", e)),
        };
        Ok(Self {
            db_password: matches
                .get_one::<String>("db-password")
                .expect("db-password is not properly required")
                .to_string(),
        })
    }
}

const WALLET_ADDRESS_SUBCOMMAND_ABOUT: &str =
    "Provides addresses of consuming and earning wallets.\
     Only valid if the wallets were successfully generated (generate-wallets) or \
     recovered (recover-wallets).";
const DB_PASSWORD_ARG_HELP: &str =
    "The current database password (a password must be set to use this command).";

pub fn wallet_addresses_subcommand() -> ClapCommand {
    ClapCommand::new("wallet-addresses")
        .about(WALLET_ADDRESS_SUBCOMMAND_ABOUT)
        .arg(
            Arg::new("db-password")
                .help(DB_PASSWORD_ARG_HELP)
                .value_name("DB-PASSWORD")
                .required(true)
                .ignore_case(false),
        )
}

#[async_trait(?Send)]
impl Command for WalletAddressesCommand {
    async fn execute(
        self: Box<Self>,
        context: &dyn CommandContext,
        stdout: TerminalWriter,
        stderr: TerminalWriter,
    ) -> Result<(), CommandError> {
        let input = UiWalletAddressesRequest {
            db_password: self.db_password.clone(),
        };
        let msg: UiWalletAddressesResponse =
            transaction(input, context, &stderr, STANDARD_COMMAND_TIMEOUT_MILLIS).await?;
        masq_short_writeln!(
            stdout,
            "Your consuming wallet address: {}",
            msg.consuming_wallet_address
        );
        masq_short_writeln!(
            stdout,
            "Your   earning wallet address: {}",
            msg.earning_wallet_address
        );
        Ok(())
    }
    implement_as_any!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::ContextError;
    use crate::command_factory::{CommandFactory, CommandFactoryReal};
    use crate::commands::commands_common::{Command, CommandError};
    use crate::terminal::test_utils::allow_flushed_writings_to_finish;
    use crate::terminal::WTermInterface;
    use crate::test_utils::mocks::{CommandContextMock, TermInterfaceMock};
    use masq_lib::messages::{ToMessageBody, UiWalletAddressesRequest, UiWalletAddressesResponse};
    use std::sync::{Arc, Mutex};

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(
            WALLET_ADDRESS_SUBCOMMAND_ABOUT,
            "Provides addresses of consuming and earning wallets.\
             Only valid if the wallets were successfully generated \
             (generate-wallets) or recovered (recover-wallets)."
        );
        assert_eq!(
            DB_PASSWORD_ARG_HELP,
            "The current database password (a password must be set to use this command)."
        );
    }

    #[tokio::test]
    async fn wallet_addresses_with_password_right() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiWalletAddressesResponse {
                consuming_wallet_address: "0x464654jhkjhk6".to_string(),
                earning_wallet_address: "0x454654klljkjk".to_string(),
            }
            .tmb(0)));
        let (term_interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let (stdout, stdout_flush_handle) = term_interface.stdout();
        let (stderr, stderr_flush_handle) = term_interface.stderr();
        let factory = CommandFactoryReal::new();
        let subject = factory
            .make(&["wallet-addresses".to_string(), "bonkers".to_string()])
            .unwrap();

        let result = subject.execute(&mut context, stdout, stderr).await;

        allow_flushed_writings_to_finish(Some(stdout_flush_handle), Some(stderr_flush_handle))
            .await;
        assert_eq!(result, Ok(()));
        assert_eq!(
            stream_handles.stdout_flushed_strings(),
            vec!["Your consuming wallet address: 0x464654jhkjhk6\nYour   earning wallet address: 0x454654klljkjk\n".to_string()]
        );
        stream_handles.assert_empty_stderr();
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiWalletAddressesRequest {
                    db_password: "bonkers".to_string(),
                }
                .tmb(0),
                1000
            )]
        )
    }

    #[tokio::test]
    async fn wallet_addresses_handles_error_due_to_a_complain_from_database() {
        let mut context = CommandContextMock::new().transact_result(Err(
            ContextError::PayloadError(4644, "bad thing".to_string()),
        ));
        let (term_interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let (stdout, stdout_flush_handle) = term_interface.stdout();
        let (stderr, stderr_flush_handle) = term_interface.stderr();
        let factory = CommandFactoryReal::new();
        let subject = factory
            .make(&["wallet-addresses".to_string(), "some password".to_string()])
            .unwrap();

        let result = subject.execute(&mut context, stdout, stderr).await;

        allow_flushed_writings_to_finish(Some(stdout_flush_handle), Some(stderr_flush_handle))
            .await;
        assert_eq!(
            result,
            Err(CommandError::Payload(4644, "bad thing".to_string()))
        );
        stream_handles.assert_empty_stderr();
    }

    #[tokio::test]
    async fn wallet_addresses_handles_send_failure() {
        let mut context = CommandContextMock::new().transact_result(Err(
            ContextError::ConnectionDropped("tummyache".to_string()),
        ));
        let (term_interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let (stdout, stdout_flush_handle) = term_interface.stdout();
        let (stderr, stderr_flush_handle) = term_interface.stderr();
        let subject =
            WalletAddressesCommand::new(&["wallet-addresses".to_string(), "bonkers".to_string()])
                .unwrap();

        let result = Box::new(subject)
            .execute(&mut context, stdout, stderr)
            .await;

        allow_flushed_writings_to_finish(Some(stdout_flush_handle), Some(stderr_flush_handle))
            .await;
        assert_eq!(
            result,
            Err(CommandError::ConnectionProblem("tummyache".to_string()))
        );
        stream_handles.assert_empty_stderr()
    }
}
