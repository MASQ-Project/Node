// Copyright (c) 2019-2021, MASQ (https://masq.ai). All rights reserved.

use crate::commands::change_password_command::ChangePasswordCommand;
use crate::commands::setup_command::SetupCommand;
use crate::communications::handle_node_not_running_for_fire_and_forget_on_the_way;
use crate::notifications::crashed_notification::CrashNotifier;
use crossbeam_channel::{unbounded, Receiver, RecvError, Sender};
use masq_lib::messages::{
    FromMessageBody, UiNewPasswordBroadcast, UiNodeCrashedBroadcast, UiSetupBroadcast,
    UiUndeliveredFireAndForget,
};
use masq_lib::ui_gateway::MessageBody;
use std::fmt::Debug;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::thread;

pub trait BroadcastHandle: Send {
    fn send(&self, message_body: MessageBody);
}

pub struct BroadcastHandleGeneric {
    message_tx: Sender<MessageBody>,
}

impl BroadcastHandle for BroadcastHandleGeneric {
    fn send(&self, message_body: MessageBody) {
        self.message_tx
            .send(message_body)
            .expect("Message send failed")
    }
}

pub trait BroadcastHandler {
    fn start(self, stream_factory: Box<dyn StreamFactory>) -> Box<dyn BroadcastHandle>;
}

pub struct BroadcastHandlerReal {
    output_synchronizer: Option<Arc<Mutex<()>>>,
}

impl BroadcastHandler for BroadcastHandlerReal {
    fn start(mut self, stream_factory: Box<dyn StreamFactory>) -> Box<dyn BroadcastHandle> {
        let (message_tx, message_rx) = unbounded();
        thread::spawn(move || {
            let (mut stdout, mut stderr) = stream_factory.make();
            let synchronizer = self.output_synchronizer.take().unwrap();
            loop {
                Self::thread_loop_guts(
                    &message_rx,
                    stdout.as_mut(),
                    stderr.as_mut(),
                    synchronizer.clone(),
                )
            }
        });
        Box::new(BroadcastHandleGeneric { message_tx })
    }
}

impl BroadcastHandlerReal {
    pub fn new(output_synchronizer: Option<Arc<Mutex<()>>>) -> Self {
        Self {
            output_synchronizer,
        }
    }

    fn handle_message_body(
        message_body_result: Result<MessageBody, RecvError>,
        stdout: &mut dyn Write,
        stderr: &mut dyn Write,
        synchronizer: Arc<Mutex<()>>,
    ) {
        match message_body_result {
            Err(_) => (), // Receiver died; masq is going down
            Ok(message_body) => {
                if let Ok((body, _)) = UiSetupBroadcast::fmb(message_body.clone()) {
                    SetupCommand::handle_broadcast(body, stdout, synchronizer);
                } else if let Ok((body, _)) = UiNodeCrashedBroadcast::fmb(message_body.clone()) {
                    CrashNotifier::handle_broadcast(body, stdout, synchronizer);
                } else if let Ok((body, _)) = UiNewPasswordBroadcast::fmb(message_body.clone()) {
                    ChangePasswordCommand::handle_broadcast(body, stdout, synchronizer);
                } else if let Ok((body, _)) = UiUndeliveredFireAndForget::fmb(message_body.clone())
                {
                    handle_node_not_running_for_fire_and_forget_on_the_way(
                        body,
                        stdout,
                        synchronizer,
                    );
                } else {
                    write!(
                        stderr,
                        "Discarding unrecognized broadcast with opcode '{}'\n\nmasq> ",
                        message_body.opcode
                    )
                    .expect("write! failed");
                }
            }
        }
    }

    fn thread_loop_guts(
        message_rx: &Receiver<MessageBody>,
        stdout: &mut dyn Write,
        stderr: &mut dyn Write,
        synchronizer: Arc<Mutex<()>>,
    ) {
        select! {
            recv(message_rx) -> message_body_result => Self::handle_message_body (message_body_result, stdout, stderr,synchronizer),
        }
    }
}

pub trait StreamFactory: Send + Debug {
    fn make(&self) -> (Box<dyn Write>, Box<dyn Write>);
}

#[derive(Clone, PartialEq, Debug)]
pub struct StreamFactoryReal {}

impl StreamFactory for StreamFactoryReal {
    fn make(&self) -> (Box<dyn Write>, Box<dyn Write>) {
        (Box::new(std::io::stdout()), Box::new(std::io::stderr()))
    }
}

impl Default for StreamFactoryReal {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamFactoryReal {
    pub fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::mocks::TestStreamFactory;
    use masq_lib::messages::{CrashReason, ToMessageBody, UiNodeCrashedBroadcast};
    use masq_lib::messages::{UiSetupBroadcast, UiSetupResponseValue, UiSetupResponseValueStatus};
    use masq_lib::ui_gateway::MessagePath;
    use std::fmt::Arguments;
    use std::time::Duration;

    #[test]
    fn broadcast_of_setup_triggers_correct_handler() {
        let (factory, handle) = TestStreamFactory::new();
        // This thread will leak, and will only stop when the tests stop running.
        let subject =
            BroadcastHandlerReal::new(Some(Arc::new(Mutex::new(())))).start(Box::new(factory));
        let message = UiSetupBroadcast {
            running: true,
            values: vec![],
            errors: vec![],
        }
        .tmb(0);

        subject.send(message);

        let stdout = handle.stdout_so_far();
        assert_eq!(
            stdout.contains("the Node is currently running"),
            true,
            "stdout: '{}' doesn't contain 'the Node is currently running'",
            stdout
        );
        assert_eq!(
            stdout.contains("masq> "),
            true,
            "stdout: '{}' doesn't contain 'masq> '",
            stdout
        );
        assert_eq!(
            handle.stderr_so_far(),
            "".to_string(),
            "stderr: '{}'",
            stdout
        );
    }

    #[test]
    fn broadcast_of_crashed_triggers_correct_handler() {
        let (factory, handle) = TestStreamFactory::new();
        // This thread will leak, and will only stop when the tests stop running.
        let subject =
            BroadcastHandlerReal::new(Some(Arc::new(Mutex::new(())))).start(Box::new(factory));
        let message = UiNodeCrashedBroadcast {
            process_id: 1234,
            crash_reason: CrashReason::Unrecognized("Unknown crash reason".to_string()),
        }
        .tmb(0);

        subject.send(message);

        let stdout = handle.stdout_so_far();
        assert_eq!(
            stdout,
            "\nThe Node running as process 1234 terminated:\n------\nUnknown crash reason\n------\nThe Daemon is once more accepting setup changes.\n\nmasq> ".to_string()
        );
        assert_eq!(
            handle.stderr_so_far(),
            "".to_string(),
            "stderr: '{}'",
            stdout
        );
    }

    #[test]
    fn broadcast_of_new_password_triggers_correct_handler() {
        let (factory, handle) = TestStreamFactory::new();
        // This thread will leak, and will only stop when the tests stop running.
        let subject =
            BroadcastHandlerReal::new(Some(Arc::new(Mutex::new(())))).start(Box::new(factory));
        let message = UiNewPasswordBroadcast {}.tmb(0);

        subject.send(message);

        let stdout = handle.stdout_so_far();
        assert_eq!(
            stdout,
            "\nThe Node's database password has changed.\n\nmasq> ".to_string()
        );
        assert_eq!(
            handle.stderr_so_far(),
            "".to_string(),
            "stderr: '{}'",
            stdout
        );
    }

    #[test]
    fn broadcast_of_undelivered_ff_message_triggers_correct_handler() {
        let (factory, handle) = TestStreamFactory::new();
        // This thread will leak, and will only stop when the tests stop running.
        let subject =
            BroadcastHandlerReal::new(Some(Arc::new(Mutex::new(())))).start(Box::new(factory));
        let message = UiUndeliveredFireAndForget {
            opcode: "uninventedMessage".to_string(),
        }
        .tmb(0);

        subject.send(message);

        let stdout = handle.stdout_so_far();
        assert_eq!(
            stdout,
            "\nCannot handle uninventedMessage request: Node is not running.\n\nmasq> ".to_string()
        );
        assert_eq!(
            handle.stderr_so_far(),
            "".to_string(),
            "stderr: '{}'",
            stdout
        );
    }

    #[test]
    fn unexpected_broadcasts_are_ineffectual_but_dont_kill_the_handler() {
        let (factory, handle) = TestStreamFactory::new();
        // This thread will leak, and will only stop when the tests stop running.
        let subject =
            BroadcastHandlerReal::new(Some(Arc::new(Mutex::new(())))).start(Box::new(factory));
        let bad_message = MessageBody {
            opcode: "unrecognized".to_string(),
            path: MessagePath::FireAndForget,
            payload: (Ok("".to_string())),
        };
        let good_message = UiSetupBroadcast {
            running: true,
            values: vec![],
            errors: vec![],
        }
        .tmb(0);

        subject.send(bad_message);

        assert_eq!(handle.stdout_so_far(), String::new());
        assert_eq!(
            handle.stderr_so_far(),
            ("Discarding unrecognized broadcast with opcode 'unrecognized'\n\nmasq> ")
        );

        subject.send(good_message);

        let stdout = handle.stdout_so_far();
        assert_eq!(
            stdout.contains("the Node is currently running"),
            true,
            "stdout: '{}' doesn't contain 'the Node is currently running'",
            stdout
        );
        assert_eq!(handle.stderr_so_far(), String::new());
    }

    #[test]
    fn setup_command_handle_broadcast_has_a_synchronizer_correctly_implemented() {
        let setup_body = UiSetupBroadcast {
            running: false,
            values: vec![UiSetupResponseValue {
                name: "ip".to_string(),
                value: "4.4.4.4".to_string(),
                status: UiSetupResponseValueStatus::Set,
            }],
            errors: vec![],
        };

        let broadcast_output = "Daemon setup has changed:

NAME                   VALUE                                                            STATUS
ip                     4.4.4.4                                                          Set

masq> ";

        test_generic_for_handle_broadcast(
            SetupCommand::handle_broadcast,
            setup_body,
            broadcast_output,
        )
    }

    #[test]
    fn crash_notifier_handle_broadcast_has_a_synchronizer_correctly_implemented() {
        let crash_notifier_body = UiNodeCrashedBroadcast {
            process_id: 100,
            crash_reason: CrashReason::NoInformation,
        };

        let broadcast_output = "\
The Node running as process 100 terminated.
The Daemon is once more accepting setup changes.

masq> ";

        test_generic_for_handle_broadcast(
            CrashNotifier::handle_broadcast,
            crash_notifier_body,
            broadcast_output,
        )
    }

    #[test]
    fn change_password_handle_broadcast_has_a_synchronizer_correctly_implemented() {
        let change_password_body = UiNewPasswordBroadcast {};

        let broadcast_output = "\
The Node's database password has changed.

masq> ";

        test_generic_for_handle_broadcast(
            ChangePasswordCommand::handle_broadcast,
            change_password_body,
            broadcast_output,
        )
    }

    #[test]
    fn ffm_undelivered_as_node_not_running_handle_broadcast_has_a_synchronizer_correctly_implemented(
    ) {
        let ffm_undelivered_body = UiUndeliveredFireAndForget {
            opcode: "crash".to_string(),
        };

        let broadcast_output = "\
Cannot handle crash request: Node is not running.

masq>";

        test_generic_for_handle_broadcast(
            handle_node_not_running_for_fire_and_forget_on_the_way,
            ffm_undelivered_body,
            broadcast_output,
        )
    }

    #[test]
    fn mixing_stdout_works() {
        let (tx, rv) = unbounded();
        let mut stdout = MixingStdout::new(tx);
        let mut stdout_clone = stdout.clone();
        let mut whole_text_buffered = String::new();
        let (sync_tx, sync_rx) = std::sync::mpsc::channel();
        let handle = thread::spawn(move || {
            sync_tx.send(()).unwrap();
            writeln!(stdout_clone, "+++++++++++++").unwrap();
            thread::sleep(Duration::from_millis(1));
            writeln!(stdout_clone, "+++++++++++++").unwrap();
            thread::sleep(Duration::from_millis(1));
            writeln!(stdout_clone, "+++++++++++++").unwrap();
            thread::sleep(Duration::from_millis(1));
            writeln!(stdout_clone, "+++++++++++++").unwrap();
            thread::sleep(Duration::from_millis(1));
            writeln!(stdout_clone, "+++++++++++++").unwrap();
        });
        sync_rx.recv().unwrap();
        thread::sleep(Duration::from_millis(1));
        write!(stdout, "-------------").unwrap();
        thread::sleep(Duration::from_millis(1));
        write!(stdout, "-------------").unwrap();
        thread::sleep(Duration::from_millis(1));
        write!(stdout, "-------------").unwrap();

        handle.join().unwrap();

        (0..9).for_each(|_| whole_text_buffered.push_str(&rv.try_recv().unwrap_or(String::new())));

        assert!(
            !whole_text_buffered.contains("---------------------------------------"),
            "{}",
            whole_text_buffered
        );
        assert!(whole_text_buffered.contains("-------------"));
        assert!(whole_text_buffered.contains("+++++++++++++"));
    }

    fn test_generic_for_handle_broadcast<T, U>(
        broadcast_handle: T,
        broadcast_message_body: U,
        broadcast_desired_output: &str,
    ) where
        T: FnOnce(U, &mut dyn Write, Arc<Mutex<()>>) + Copy,
        U: Debug + PartialEq + Clone,
    {
        let (tx, rx) = unbounded();
        let mut stdout = MixingStdout::new(tx);
        let stdout_clone = stdout.clone();
        let stdout_second_clone = stdout.clone();

        let synchronizer = Arc::new(Mutex::new(()));
        let synchronizer_clone_idle = synchronizer.clone();

        //synchronized part proving that the broadcast print is synchronized

        let full_stdout_output_sync = background_thread_making_interferences(
            true,
            &mut stdout,
            Box::new(stdout_clone),
            synchronizer,
            broadcast_handle,
            broadcast_message_body.clone(),
            rx.clone(),
        );

        assert!(
            full_stdout_output_sync.contains(broadcast_desired_output),
            "The message from the broadcast handle isn't correct or entire: {}",
            full_stdout_output_sync
        );
        //without synchronization it's a cut segment of these ten asterisks
        assert!(
            full_stdout_output_sync.starts_with("******************** "),
            "Each group of twenty asterisks must keep together: {}",
            full_stdout_output_sync
        );
        let asterisks_count = full_stdout_output_sync
            .chars()
            .filter(|char| *char == '*')
            .count();
        assert_eq!(
            asterisks_count, 60,
            "The count of asterisks isn't 60 but: {}",
            asterisks_count
        );

        //the second part
        //synchronized part proving that the broadcast print would be messed without synchronization
        let full_stdout_output_without_sync = background_thread_making_interferences(
            false,
            &mut stdout,
            Box::new(stdout_second_clone),
            synchronizer_clone_idle,
            broadcast_handle,
            broadcast_message_body,
            rx,
        );

        assert!(
            !full_stdout_output_without_sync.starts_with("******************** "),
            "There mustn't be 20 asterisks together: {}",
            full_stdout_output_without_sync
        );
        let asterisks_count = full_stdout_output_without_sync
            .chars()
            .filter(|char| *char == '*')
            .count();
        assert_eq!(
            asterisks_count, 60,
            "The count of asterisks isn't 60 but: {}",
            asterisks_count
        );
    }

    #[derive(Clone)]
    struct MixingStdout {
        channel_half: Sender<String>,
    }

    impl MixingStdout {
        fn new(sender: Sender<String>) -> Self {
            MixingStdout {
                channel_half: sender,
            }
        }
    }

    impl Write for MixingStdout {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.channel_half
                .send(std::str::from_utf8(buf).unwrap().to_string())
                .unwrap();
            Ok(0)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
        fn write_fmt(&mut self, fmt: Arguments<'_>) -> std::io::Result<()> {
            self.channel_half.send(fmt.to_string()).unwrap();
            Ok(())
        }
    }

    fn background_thread_making_interferences<U, T>(
        sync: bool,
        stdout: &mut dyn Write,
        mut stdout_clone: Box<dyn Write + Send>,
        synchronizer: Arc<Mutex<()>>,
        broadcast_handle: T,
        broadcast_message_body: U,
        rx: Receiver<String>,
    ) -> String
    where
        T: FnOnce(U, &mut dyn Write, Arc<Mutex<()>>) + Copy,
        U: Debug + PartialEq + Clone,
    {
        let synchronizer_clone = synchronizer.clone();
        let (sync_tx, sync_rx) = std::sync::mpsc::channel();
        let interference_thread_handle = thread::spawn(move || {
            sync_tx.send(()).unwrap();
            (0..3).into_iter().for_each(|_| {
                let _lock = if sync {
                    Some(synchronizer.lock().unwrap())
                } else {
                    None
                };
                (0..20).into_iter().for_each(|_| {
                    stdout_clone.write(b"*").unwrap();
                    thread::sleep(Duration::from_millis(1))
                });
                stdout_clone.write(b" ").unwrap();
                drop(_lock)
            })
        });
        sync_rx.recv().unwrap();
        thread::sleep(Duration::from_millis(30));
        broadcast_handle(broadcast_message_body.clone(), stdout, synchronizer_clone);

        interference_thread_handle.join().unwrap();

        let mut full_stdout_buffer = String::new();
        let full_stdout_output = loop {
            match rx.try_recv() {
                Ok(string) => full_stdout_buffer.push_str(&string),
                Err(_) => break full_stdout_buffer,
            }
        };
        full_stdout_output
    }
}
