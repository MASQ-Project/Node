// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::database::db_initializer::{InitializationError, DATABASE_FILE};
use actix::{Actor, AsyncContext, Context, Handler, Message, SpawnHandle};
use clap::App;
use masq_lib::logger::Logger;
use masq_lib::messages::{FromMessageBody, UiCrashRequest};
use masq_lib::multi_config::{MultiConfig, VirtualCommandLine};
use masq_lib::shared_schema::ConfiguratorError;
use masq_lib::ui_gateway::NodeFromUiMessage;
use masq_lib::utils::type_name_of;
use std::io::ErrorKind;
use std::marker::PhantomData;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Networking::WinSock::{WSADESCRIPTION_LEN, WSASYS_STATUS_LEN};

#[cfg(target_os = "windows")]
mod win_cfg {
    pub use windows_sys::core::PSTR;
    pub use windows_sys::Win32::Networking::WinSock::WSAStartup;
    pub use windows_sys::Win32::Networking::WinSock::SO_MAX_MSG_SIZE;
}

static DEAD_STREAM_ERRORS: [ErrorKind; 5] = [
    ErrorKind::BrokenPipe,
    ErrorKind::ConnectionAborted,
    ErrorKind::ConnectionReset,
    ErrorKind::ConnectionRefused,
    ErrorKind::TimedOut,
];

pub static NODE_MAILBOX_CAPACITY: usize = 0; // 0 for unbound

macro_rules! recipient {
    ($addr:expr, $_type:ty) => {
        $addr.clone().recipient::<$_type>()
    };
}

macro_rules! send_bind_message {
    ($subs:expr, $peer_actors:expr) => {
        $subs
            .bind
            .try_send(BindMessage {
                peer_actors: $peer_actors.clone(),
            })
            .unwrap_or_else(|_| panic!("Actor for {:?} is dead", $subs));
    };
}

macro_rules! send_start_message {
    ($subs:expr) => {
        $subs
            .start
            .try_send(StartMessage {})
            .unwrap_or_else(|_| panic!("Actor for {:?} is dead", $subs));
    };
}

pub fn indicates_dead_stream(kind: ErrorKind) -> bool {
    DEAD_STREAM_ERRORS.contains(&kind)
}

pub fn time_t_timestamp() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("bad interval")
        .as_secs() as u32
}

pub fn make_printable_string(bytes: &[u8]) -> String {
    let strs: Vec<String> = bytes
        .iter()
        .map(|b| match b {
            nonprintable if b"\n\r\t".contains(nonprintable) => {
                format!("{}", *nonprintable as char)
            }
            nonprintable if *nonprintable < b' ' => format!("{:02X}", nonprintable),
            _ => format!("{}", *b as char),
        })
        .collect();
    strs.join("")
}

pub fn to_string(data: &[u8]) -> String {
    match String::from_utf8(data.to_owned()) {
        Ok(string) => make_printable_string(string.as_bytes()),
        Err(_) => format!("{:?}", data),
    }
}

pub fn to_string_s(data: &[u8]) -> String {
    match String::from_utf8(Vec::from(data)) {
        Ok(string) => make_printable_string(string.as_bytes()),
        Err(_) => format!("{:?}", data),
    }
}

pub fn make_new_multi_config<'a>(
    schema: &App<'a, 'a>,
    vcls: Vec<Box<dyn VirtualCommandLine>>,
) -> Result<MultiConfig<'a>, ConfiguratorError> {
    MultiConfig::try_new(schema, vcls)
}

#[track_caller]
pub fn handle_ui_crash_request(
    msg: NodeFromUiMessage,
    logger: &Logger,
    crashable: bool,
    crash_key: &str,
) {
    let crash_analyzer = crash_request_analyzer;
    if let Some(cr) = crash_analyzer(msg, logger, crashable, crash_key) {
        let processed_with = type_name_of(crash_analyzer);
        panic!("{} (processed with: {})", cr.panic_message, processed_with)
    }
}

fn crash_request_analyzer(
    msg: NodeFromUiMessage,
    logger: &Logger,
    crashable: bool,
    crash_key: &str,
) -> Option<UiCrashRequest> {
    if !crashable {
        if logger.debug_enabled() {
            match UiCrashRequest::fmb(msg.body) {
                Ok((msg, _)) if msg.actor == crash_key => {
                    debug!(
                        logger,
                        "Received a crash request intended for this actor \
                    '{}' but not set up to be crashable",
                        crash_key
                    )
                }
                _ => (),
            }
        }
        return None;
    }
    match UiCrashRequest::fmb(msg.body) {
        Err(_) => None,
        Ok((msg, _)) if msg.actor == crash_key => Some(msg),
        Ok((_, _)) => None,
    }
}

pub trait NotifyLaterHandle<M, A>
where
    A: Actor<Context = Context<A>>,
{
    fn notify_later(
        &self,
        msg: M,
        interval: Duration,
        ctx: &mut Context<A>,
    ) -> Box<dyn NLSpawnHandleHolder>;
    as_any_ref_in_trait!();
}

#[derive(Default)]
pub struct NotifyLaterHandleReal<M> {
    phantom: PhantomData<M>,
}

impl<T> NotifyLaterHandleReal<T> {
    pub fn new() -> Self {
        Self {
            phantom: PhantomData::default(),
        }
    }
}

impl<M, A> NotifyLaterHandle<M, A> for NotifyLaterHandleReal<M>
where
    M: Message + 'static,
    A: Actor<Context = Context<A>> + Handler<M>,
{
    fn notify_later(
        &self,
        msg: M,
        interval: Duration,
        ctx: &mut Context<A>,
    ) -> Box<dyn NLSpawnHandleHolder> {
        let handle = ctx.notify_later(msg, interval);
        Box::new(NLSpawnHandleHolderReal::new(handle))
    }
    as_any_ref_in_trait_impl!();
}

pub trait NotifyHandle<M, A>
where
    A: Actor<Context = Context<A>>,
{
    fn notify<'a>(&'a self, msg: M, ctx: &'a mut Context<A>);
    as_any_ref_in_trait!();
}

impl<M, A> Default for Box<dyn NotifyHandle<M, A>>
where
    M: Message + 'static,
    A: Actor<Context = Context<A>> + Handler<M>,
{
    fn default() -> Self {
        Box::new(NotifyHandleReal {
            phantom: PhantomData::default(),
        })
    }
}

pub trait NLSpawnHandleHolder {
    fn handle(self) -> SpawnHandle;
}

pub struct NLSpawnHandleHolderReal {
    handle: SpawnHandle,
}

impl NLSpawnHandleHolderReal {
    pub fn new(handle: SpawnHandle) -> Self {
        Self { handle }
    }
}

impl NLSpawnHandleHolder for NLSpawnHandleHolderReal {
    fn handle(self) -> SpawnHandle {
        self.handle
    }
}

pub struct NotifyHandleReal<M> {
    phantom: PhantomData<M>,
}

impl<M, A> NotifyHandle<M, A> for NotifyHandleReal<M>
where
    M: Message + 'static,
    A: Actor<Context = Context<A>> + Handler<M>,
{
    fn notify<'a>(&'a self, msg: M, ctx: &'a mut Context<A>) {
        ctx.notify(msg)
    }
    as_any_ref_in_trait_impl!();
}

pub fn db_connection_launch_panic(err: InitializationError, data_directory: &Path) -> ! {
    panic!(
        "Couldn't initialize database due to \"{:?}\" at {:?}",
        err,
        data_directory.join(DATABASE_FILE)
    )
}

#[derive(Message, Clone, PartialEq, Eq)]
pub struct MessageScheduler<M: Message> {
    pub scheduled_msg: M,
    pub delay: Duration,
}

#[cfg(target_os = "windows")]
pub fn wsa_startup_init() {
    let lp_vendor: *mut u8 = 0 as *mut u8;
    let wsdata: *mut windows_sys::Win32::Networking::WinSock::WSADATA =
        &mut windows_sys::Win32::Networking::WinSock::WSADATA {
            wVersion: 0x0202 as u16,
            wHighVersion: 0x0202 as u16,
            iMaxSockets: 0,
            iMaxUdpDg: win_cfg::SO_MAX_MSG_SIZE as u16,
            lpVendorInfo: lp_vendor as win_cfg::PSTR,
            szDescription: [0u8; WSADESCRIPTION_LEN as usize + 1usize],
            szSystemStatus: [0u8; WSASYS_STATUS_LEN as usize + 1usize],
        } as *mut windows_sys::Win32::Networking::WinSock::WSADATA;

    let wsa_startup_init: i32 = unsafe { wsa_startup_call(0x0202u16, wsdata) };

    match wsa_startup_init {
        0 => {},
        10091 => panic!("WSAStartup: The underlying network subsystem is not ready for network communication. Error code: 10091"),
        10092 => panic!("WSAStartup: The version of Windows Sockets support requested is not provided by this particular Windows Sockets implementation. Error code: 10092"),
        10036 => panic!("WSAStartup: A blocking Windows Sockets 1.1 operation is in progress. Error code: 10036"),
        10067 => panic!("WSAStartup: A limit on the number of tasks supported by the Windows Sockets implementation has been reached. Error code: 10067"),
        10014 => panic!("WSAStartup: The lpWSAData parameter is not a valid pointer. Error code: 10014"),
        x => panic!("WSAStartup: WSAStartup returned unimplemented error: {}", x)
    };
}

#[cfg(target_os = "windows")]
unsafe fn wsa_startup_call(
    version: u16,
    wsdata: *mut windows_sys::Win32::Networking::WinSock::WSADATA,
) -> i32 {
    win_cfg::WSAStartup(version, wsdata)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apps::app_node;
    use actix::{Handler, System};
    use crossbeam_channel::{unbounded, Sender};
    use log::Level;
    use masq_lib::messages::ToMessageBody;
    use masq_lib::multi_config::CommandLineVcl;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use std::ops::Sub;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[test]
    fn indicates_dead_stream_identifies_dead_stream_errors() {
        vec![
            ErrorKind::BrokenPipe,
            ErrorKind::ConnectionRefused,
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::TimedOut,
        ]
        .iter()
        .for_each(|kind| {
            let result = indicates_dead_stream(*kind);

            assert_eq!(
                result, true,
                "indicates_dead_stream ({:?}) should have been true but was false",
                kind
            )
        });
    }

    #[test]
    fn indicates_dead_stream_identifies_non_dead_stream_errors() {
        vec![
            ErrorKind::NotFound,
            ErrorKind::PermissionDenied,
            ErrorKind::NotConnected,
            ErrorKind::AddrInUse,
            ErrorKind::AddrNotAvailable,
            ErrorKind::AlreadyExists,
            ErrorKind::WouldBlock,
            ErrorKind::InvalidInput,
            ErrorKind::InvalidData,
            ErrorKind::WriteZero,
            ErrorKind::Interrupted,
            ErrorKind::Other,
            ErrorKind::UnexpectedEof,
        ]
        .iter()
        .for_each(|kind| {
            let result = indicates_dead_stream(*kind);

            assert_eq!(
                result, false,
                "indicates_dead_stream ({:?}) should have been false but was true",
                kind
            )
        });
    }

    #[test]
    fn node_mailbox_capacity_is_unbound() {
        assert_eq!(NODE_MAILBOX_CAPACITY, 0)
    }

    #[test]
    fn handle_ui_crash_message_does_not_crash_if_not_crashable() {
        init_test_logging();
        let mut logger = Logger::new("handle_ui_crash_message_does_not_crash_if_not_crashable");
        logger.set_level_for_test(Level::Info);
        let msg_body = UiCrashRequest {
            actor: "CRASHKEY".to_string(),
            panic_message: "Foiled again!".to_string(),
        }
        .tmb(0);
        let from_ui_message = NodeFromUiMessage {
            client_id: 0,
            body: msg_body,
        };

        handle_ui_crash_request(from_ui_message, &logger, false, "CRASHKEY");
        // no panic; test passes

        TestLogHandler::new().exists_no_log_containing(&format!(
            "handle_ui_crash_message_does_not_crash_if_not_crashable: Received a crash request",
        ));
    }

    #[test]
    fn handle_ui_crash_message_does_not_crash_if_not_crashable_but_logs_if_receives_a_crash_request_for_it_despite(
    ) {
        init_test_logging();
        let logger = Logger::new("handle_ui_crash_message_does_not_crash_if_not_crashable_but_logs_if_receives_a_crash_request_for_it_despite");
        let msg_body = UiCrashRequest {
            actor: "CRASHKEY".to_string(),
            panic_message: "Foiled again!".to_string(),
        }
        .tmb(0);
        let from_ui_message = NodeFromUiMessage {
            client_id: 0,
            body: msg_body,
        };

        handle_ui_crash_request(from_ui_message, &logger, false, "CRASHKEY");
        // no panic; test passes

        TestLogHandler::new().exists_log_containing(&format!("handle_ui_crash_message_does_not_crash_if_not_crashable_but_logs_if_receives_a_crash_request_for_it_despite: {} intended for this actor 'CRASHKEY' but not set up to be crashable", "Received a crash request"));
    }

    #[test]
    fn handle_ui_crash_message_does_not_crash_if_no_actor_match() {
        init_test_logging();
        let logger = Logger::new("Example");
        let msg_body = UiCrashRequest {
            actor: "CRASHKEY".to_string(),
            panic_message: "Foiled again!".to_string(),
        }
        .tmb(0);
        let from_ui_message = NodeFromUiMessage {
            client_id: 0,
            body: msg_body,
        };

        handle_ui_crash_request(from_ui_message, &logger, true, "mismatch");
        // no panic; test passes
    }

    #[test]
    #[should_panic(
        expected = "Foiled again! (processed with: node_lib::sub_lib::utils::crash_request_analyzer)"
    )]
    fn handle_ui_crash_message_crashes_if_everything_is_just_right() {
        let logger = Logger::new("Example");
        let msg_body = UiCrashRequest {
            actor: "CRASHKEY".to_string(),
            panic_message: "Foiled again!".to_string(),
        }
        .tmb(0);
        let from_ui_message = NodeFromUiMessage {
            client_id: 0,
            body: msg_body,
        };

        handle_ui_crash_request(from_ui_message, &logger, true, "CRASHKEY");
    }

    #[test]
    #[should_panic(expected = "The program's entry check failed to catch this.")]
    fn make_new_multi_config_should_panic_trying_to_process_help_request() {
        let app = app_node();
        let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![Box::new(CommandLineVcl::new(vec![
            String::from("program"),
            "--help".to_string(),
        ]))];

        let _ = make_new_multi_config(&app, vcls);
    }

    #[test]
    //this test won't work properly until we integrate Clap 3.x.x
    //now it calls process::exit internally though Clap's documentation tries to convince us that it doesn't
    #[should_panic(expected = "The program's entry check failed to catch this.")]
    fn make_new_multi_config_should_panic_trying_to_process_version_request() {
        let app = app_node();
        let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![Box::new(CommandLineVcl::new(vec![
            String::from("program"),
            "--version".to_string(),
        ]))];

        let _ = make_new_multi_config(&app, vcls);
    }

    struct NotifyHandlesTestActor {
        responder: Sender<FindingInfo>,
        message_counter: usize,
        notify_later_handle_real: NotifyLaterHandleReal<NotifyHandlesProbeMessage>,
        notify_handle_real: NotifyHandleReal<NotifyHandlesProbeMessage>,
    }

    struct FindingInfo {
        id: usize,
        started: SystemTime,
        received: SystemTime,
    }

    impl NotifyHandlesTestActor {
        fn new(responder: Sender<FindingInfo>) -> Self {
            Self {
                responder,
                message_counter: 0,
                notify_later_handle_real: NotifyLaterHandleReal {
                    phantom: Default::default(),
                },
                notify_handle_real: NotifyHandleReal {
                    phantom: Default::default(),
                },
            }
        }
    }

    const DELAYED: u64 = 55;

    impl Actor for NotifyHandlesTestActor {
        type Context = Context<Self>;

        fn started(&mut self, ctx: &mut Self::Context) {
            self.notify_handle_real
                .notify(NotifyHandlesProbeMessage::new(0), ctx);
            let interval = Duration::from_millis(DELAYED);
            self.notify_later_handle_real.notify_later(
                NotifyHandlesProbeMessage::new(1),
                interval,
                ctx,
            );
        }
    }

    #[derive(Message)]
    struct NotifyHandlesProbeMessage {
        id: usize,
        start_time: SystemTime,
    }

    impl NotifyHandlesProbeMessage {
        fn new(id: usize) -> Self {
            Self {
                id,
                start_time: SystemTime::now(),
            }
        }
    }

    impl Handler<NotifyHandlesProbeMessage> for NotifyHandlesTestActor {
        type Result = ();

        fn handle(
            &mut self,
            msg: NotifyHandlesProbeMessage,
            _ctx: &mut Self::Context,
        ) -> Self::Result {
            let info = FindingInfo {
                id: msg.id,
                started: msg.start_time,
                received: SystemTime::now(),
            };
            self.responder.send(info).unwrap();
            self.message_counter += 1;
            if self.message_counter == 2 {
                System::current().stop()
            }
        }
    }

    #[test]
    fn notify_handles_real_sends_their_messages_correctly() {
        let (sender, receiver) = unbounded();
        let test_actor = NotifyHandlesTestActor::new(sender);
        let _ = test_actor.start();
        let system = System::new("notify_handles_test");

        system.run();

        let mut data = Vec::new();
        (0..2).for_each(|_| data.push(receiver.recv_timeout(Duration::from_secs(60)).unwrap()));
        let first_message = data.remove(0);
        assert_eq!(first_message.id, 0);
        let notify_exec_duration = first_message
            .received
            .duration_since(first_message.started)
            .unwrap();
        let second_message = data.remove(0);
        let notify_later_exec_duration = second_message
            .received
            .duration_since(second_message.started)
            .unwrap();
        let safe_assumption = DELAYED - (DELAYED as f64 * 0.1) as u64;
        assert!(
            notify_exec_duration
                < notify_later_exec_duration.sub(Duration::from_millis(safe_assumption))
        );
        assert!(notify_exec_duration < Duration::from_millis(DELAYED));
        assert!(notify_later_exec_duration >= Duration::from_millis(DELAYED));
    }

    #[test]
    fn db_connection_initialization_panic_message_contains_full_path() {
        let path = Path::new("first_directory").join("second_directory");

        let caught_panic_err = catch_unwind(AssertUnwindSafe(|| {
            db_connection_launch_panic(
                InitializationError::SqliteError(rusqlite::Error::ExecuteReturnedResults),
                &path,
            );
        }));

        let caught_panic = caught_panic_err.unwrap_err();
        let panic_message = caught_panic.downcast_ref::<String>().unwrap();
        assert_eq!(
            panic_message,
            &format!(
                "Couldn't initialize database due to \"{:?}\" at {:?}",
                InitializationError::SqliteError(rusqlite::Error::ExecuteReturnedResults),
                path.join(DATABASE_FILE)
            )
        );
    }
}
