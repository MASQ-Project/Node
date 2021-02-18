// Copyright (c) 2019-2021, MASQ (https://masq.ai). All rights reserved.

use actix::Message;
use lazy_static::lazy_static;
use masq_lib::messages::CrashReason;

lazy_static! {
    static ref RECOGNIZERS: Vec<Box<dyn Recognizer>> = vec![
        Box::new(ChildWaitFailureRecognizer {}),
        Box::new(NoInformationRecognizer {}),
        Box::new(UnrecognizedRecognizer {}),
    ];
}

trait Recognizer: Sync {
    fn try_convert(&self, exit_code: Option<i32>, stderr: &Option<String>) -> Option<CrashReason>;
}

#[derive(Message, Clone, Debug, PartialEq)]
pub struct CrashNotification {
    pub process_id: u32,
    pub exit_code: Option<i32>,
    pub stderr: Option<String>,
}

impl CrashNotification {
    pub fn analyze(&self) -> CrashReason {
        let init: Option<CrashReason> = None;
        RECOGNIZERS
            .iter()
            .fold(init, |sofar, recognizer| match sofar {
                Some(_) => sofar,
                None => recognizer.try_convert(self.exit_code, &self.stderr),
            })
            .expect("RECOGNIZERS isn't exhaustive")
    }
}

struct ChildWaitFailureRecognizer {}

const CHILD_WAIT_FAILURE_PREFIX: &str = "Child wait failure: ";

impl Recognizer for ChildWaitFailureRecognizer {
    fn try_convert(
        &self,
        exit_code_opt: Option<i32>,
        stderr_opt: &Option<String>,
    ) -> Option<CrashReason> {
        if exit_code_opt.is_some() {
            return None;
        }
        if let Some(stderr) = stderr_opt {
            if stderr.starts_with(CHILD_WAIT_FAILURE_PREFIX) {
                let err_msg = stderr.trim_start_matches(CHILD_WAIT_FAILURE_PREFIX);
                return Some(CrashReason::ChildWaitFailure(err_msg.to_string()));
            }
        }
        None
    }
}

struct NoInformationRecognizer {}

impl Recognizer for NoInformationRecognizer {
    fn try_convert(&self, exit_code: Option<i32>, stderr: &Option<String>) -> Option<CrashReason> {
        if exit_code.is_none()
            && (stderr.is_none()
                || stderr
                    .as_ref()
                    .expect("should never happen")
                    .to_string()
                    .trim()
                    .is_empty())
        {
            Some(CrashReason::NoInformation)
        } else {
            None
        }
    }
}

struct UnrecognizedRecognizer {}

impl Recognizer for UnrecognizedRecognizer {
    fn try_convert(&self, _exit_code: Option<i32>, stderr: &Option<String>) -> Option<CrashReason> {
        match stderr {
            Some(stderr) => Some(CrashReason::Unrecognized(stderr.clone())),
            None => Some(CrashReason::Unrecognized(String::new())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_wait_failure() {
        let subject = CrashNotification {
            process_id: 0,
            exit_code: None,
            stderr: Some("Child wait failure: booga booga".to_string()),
        };

        let result = subject.analyze();

        assert_eq!(
            result,
            CrashReason::ChildWaitFailure("booga booga".to_string())
        )
    }

    #[test]
    fn recognizes_no_information() {
        vec![None, Some("".to_string()), Some(" \n\t ".to_string())]
            .into_iter()
            .for_each(|stderr| {
                let subject = CrashNotification {
                    process_id: 0,
                    exit_code: None,
                    stderr: stderr.clone(),
                };

                let result = subject.analyze();

                assert_eq!(
                    result,
                    CrashReason::NoInformation,
                    "Did not recognize {:?} as NoInformation",
                    stderr
                )
            })
    }

    #[test]
    fn eventually_gives_up() {
        let subject = CrashNotification {
            process_id: 0,
            exit_code: None,
            stderr: Some("unrecognizable".to_string()),
        };

        let result = subject.analyze();

        assert_eq!(
            result,
            CrashReason::Unrecognized("unrecognizable".to_string())
        )
    }
}
