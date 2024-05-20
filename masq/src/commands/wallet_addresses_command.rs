// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::{
    transaction, Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS,
};
use crate::terminal::terminal_interface::WTermInterface;
use async_trait::async_trait;
use clap::{Arg, Command as ClapCommand};
use masq_lib::messages::{UiWalletAddressesRequest, UiWalletAddressesResponse};
use masq_lib::{implement_as_any, short_writeln};
#[cfg(test)]
use std::any::Any;
use std::sync::Arc;

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

#[async_trait]
impl Command for WalletAddressesCommand {
    async fn execute(
        self: Box<Self>,
        context: &mut dyn CommandContext,
        term_interface: &mut dyn WTermInterface,
    ) -> Result<(), CommandError> {
        let (stdout, _stdout_flush_handle) = term_interface.stdout();
        let (stderr, _stderr_flush_handle) = term_interface.stderr();
        let input = UiWalletAddressesRequest {
            db_password: self.db_password.clone(),
        };
        let msg: UiWalletAddressesResponse =
            transaction(input, context, stderr, STANDARD_COMMAND_TIMEOUT_MILLIS).await?;
        short_writeln!(
            stdout,
            "Your consuming wallet address: {}",
            msg.consuming_wallet_address
        );
        short_writeln!(
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
    use crate::test_utils::mocks::{CommandContextMock, WTermInterfaceMock};
    use masq_lib::messages::{ToMessageBody, UiWalletAddressesRequest, UiWalletAddressesResponse};
    use masq_lib::test_utils::fake_stream_holder::ByteArrayHelperMethods;
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
        let mut term_interface = WTermInterfaceMock::default();
        let stdout_arc = term_interface.stdout_arc().clone();
        let stderr_arc = term_interface.stderr_arc().clone();
        let factory = CommandFactoryReal::new();
        let subject = factory
            .make(&["wallet-addresses".to_string(), "bonkers".to_string()])
            .unwrap();

        let result = subject.execute(&mut context, &mut term_interface).await;

        assert_eq!(result, Ok(()));
        assert_eq!(
            stdout_arc.lock().unwrap().get_string(),
            "Your consuming wallet address: 0x464654jhkjhk6\nYour   earning wallet address: 0x454654klljkjk\n"
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
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
            ContextError::PayloadError(4644, "bad bad bad thing".to_string()),
        ));
        let mut term_interface = WTermInterfaceMock::default();
        let stderr_arc = term_interface.stderr_arc().clone();
        let factory = CommandFactoryReal::new();
        let subject = factory
            .make(&["wallet-addresses".to_string(), "some password".to_string()])
            .unwrap();

        let result = subject.execute(&mut context, &mut term_interface).await;

        assert_eq!(
            result,
            Err(CommandError::Payload(4644, "bad bad bad thing".to_string()))
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
    }

    #[tokio::test]
    async fn wallet_addresses_handles_send_failure() {
        let mut context = CommandContextMock::new().transact_result(Err(
            ContextError::ConnectionDropped("tummyache".to_string()),
        ));
        let mut term_interface = WTermInterfaceMock::default();
        let subject =
            WalletAddressesCommand::new(&["wallet-addresses".to_string(), "bonkers".to_string()])
                .unwrap();

        let result = Box::new(subject)
            .execute(&mut context, &mut term_interface)
            .await;

        assert_eq!(
            result,
            Err(CommandError::ConnectionProblem("tummyache".to_string()))
        )
    }
}
