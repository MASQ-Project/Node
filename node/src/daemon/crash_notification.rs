// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use masq_lib::messages::CrashReason;
use actix::{Message};
use lazy_static::lazy_static;

lazy_static! {
    static ref RECOGNIZERS: Vec<Box<dyn Recognizer>> = vec![
        Box::new (ChildWaitFailureRecognizer{}),
        Box::new (UnknownRecognizer{}),
    ];
}

trait Recognizer: Sync {
    fn try_convert (&self, exit_code: &Option<i32>, stderr: &Option<String>) -> Option<CrashReason>;
}

#[derive(Message, Clone, Debug, PartialEq)]
pub struct CrashNotification {
    pub process_id: u32,
    pub exit_code: Option<i32>,
    pub stderr: Option<String>,
}

impl CrashNotification {
    pub fn analyze (&self) -> CrashReason {
        let init: Option<CrashReason> = None;
        RECOGNIZERS.iter().fold(init, |sofar, recognizer| {
            match sofar {
                Some (_) => sofar,
                None => recognizer.try_convert (&self.exit_code, &self.stderr),
            }
        }).expect ("RECOGNIZERS isn't exhaustive")
    }
}

struct ChildWaitFailureRecognizer{}

const CHILD_WAIT_FAILURE_PREFIX: &str = "Child wait failure: ";

impl Recognizer for ChildWaitFailureRecognizer {
    fn try_convert(&self, exit_code: &Option<i32>, stderr: &Option<String>) -> Option<CrashReason> {
        if exit_code.is_some() {return None}
        if let Some (stderr) = stderr {
            if stderr.starts_with (CHILD_WAIT_FAILURE_PREFIX) {
                let err_msg = stderr[CHILD_WAIT_FAILURE_PREFIX.len()..].to_string();
                return Some(CrashReason::ChildWaitFailure(err_msg))
            }
        }
        None
    }
}

struct UnknownRecognizer{}

impl Recognizer for UnknownRecognizer {
    fn try_convert(&self, _exit_code: &Option<i32>, stderr: &Option<String>) -> Option<CrashReason> {
        match stderr {
            Some (stderr) => Some (CrashReason::Unknown(stderr.clone())),
            None => Some (CrashReason::Unknown(String::new())),
        }
    }
}

#[cfg (test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_wait_failure () {
        let subject = CrashNotification {
            process_id: 0,
            exit_code: None,
            stderr: Some ("Child wait failure: booga booga".to_string()),
        };

        let result = subject.analyze();

        assert_eq! (result, CrashReason::ChildWaitFailure("booga booga".to_string()))
    }

    #[test]
    fn eventually_gives_up () {
        let subject = CrashNotification {
            process_id: 0,
            exit_code: None,
            stderr: Some ("unrecognizable".to_string()),
        };

        let result = subject.analyze();

        assert_eq! (result, CrashReason::Unknown("unrecognizable".to_string()))
    }
}
