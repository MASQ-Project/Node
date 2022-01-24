// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::masquerader::{MasqueradeError, Masquerader};
use crate::sub_lib::framer::Framer;
use masq_lib::logger::Logger;
use serde::__private::fmt::Debug;

#[derive(Debug, PartialEq, Clone)]
pub struct UnmaskedChunk {
    pub chunk: Vec<u8>,
    pub last_chunk: bool,
    pub sequenced: bool,
}

impl UnmaskedChunk {
    pub fn new(chunk: Vec<u8>, last_chunk: bool, sequenced: bool) -> UnmaskedChunk {
        UnmaskedChunk {
            chunk,
            last_chunk,
            sequenced,
        }
    }
}

pub trait DiscriminatorFactory: Send + Sync + Debug {
    fn make(&self) -> Discriminator;
    fn duplicate(&self) -> Box<dyn DiscriminatorFactory>;
}

impl Clone for Box<dyn DiscriminatorFactory> {
    fn clone(&self) -> Box<dyn DiscriminatorFactory> {
        self.duplicate()
    }
}

pub struct Discriminator {
    framer: Box<dyn Framer>,
    masqueraders: Vec<Box<dyn Masquerader>>,
    logger: Logger,
}

impl Discriminator {
    pub fn new(framer: Box<dyn Framer>, masqueraders: Vec<Box<dyn Masquerader>>) -> Discriminator {
        if masqueraders.is_empty() {
            panic!("Discriminator must be given at least one Masquerader");
        }
        Discriminator {
            framer,
            masqueraders,
            logger: Logger::new("Discriminator"),
        }
    }

    pub fn add_data(&mut self, data: &[u8]) {
        self.framer.add_data(data);
    }

    pub fn take_chunk(&mut self) -> Option<UnmaskedChunk> {
        let frame = match self.framer.take_frame() {
            Some(frame) => frame,
            None => return None,
        };
        for masquerader in &self.masqueraders {
            match masquerader.try_unmask(&frame.chunk[..]) {
                Ok(chunk) => return Some(chunk),
                Err(MasqueradeError::NotThisMasquerader) => (),
                Err(e) => {
                    warning!(self.logger, "{}", e);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::masquerader::MasqueradeError;
    use crate::sub_lib::framer::FramedChunk;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use std::cell::RefCell;
    use std::ops::DerefMut;
    use std::sync::Arc;
    use std::sync::Mutex;

    pub struct FramerMock {
        data: Vec<Vec<u8>>,
    }

    impl Framer for FramerMock {
        fn add_data(&mut self, data: &[u8]) {
            self.data.push(Vec::from(data))
        }

        fn take_frame(&mut self) -> Option<FramedChunk> {
            if self.data.is_empty() {
                None
            } else {
                Some(FramedChunk {
                    chunk: self.data.remove(0),
                    last_chunk: true,
                })
            }
        }
    }

    impl FramerMock {
        pub fn new() -> FramerMock {
            FramerMock { data: vec![] }
        }
    }

    // TODO: Remove this struct and replace with the MasqueraderMock from node_test_utils
    pub struct MasqueraderMock {
        try_unmask_results: RefCell<Vec<Result<UnmaskedChunk, MasqueradeError>>>,
        try_unmask_parameters: RefCell<Arc<Mutex<Vec<Vec<u8>>>>>,
    }

    impl Masquerader for MasqueraderMock {
        fn try_unmask(&self, item: &[u8]) -> Result<UnmaskedChunk, MasqueradeError> {
            let mut try_unmask_parameters_ref = self.try_unmask_parameters.borrow_mut();
            try_unmask_parameters_ref
                .deref_mut()
                .lock()
                .unwrap()
                .push(Vec::from(item));
            self.try_unmask_results.borrow_mut().remove(0)
        }

        fn mask(&self, _data: &[u8]) -> Result<Vec<u8>, MasqueradeError> {
            unimplemented!()
        }
    }

    impl MasqueraderMock {
        pub fn new() -> MasqueraderMock {
            MasqueraderMock {
                try_unmask_results: RefCell::new(vec![]),
                try_unmask_parameters: RefCell::new(Arc::new(Mutex::new(vec![]))),
            }
        }

        pub fn try_unmask_result(
            self,
            result: Result<UnmaskedChunk, MasqueradeError>,
        ) -> MasqueraderMock {
            self.try_unmask_results.borrow_mut().push(result);
            self
        }

        pub fn try_unmask_parameters(
            self,
            parameters: &mut Arc<Mutex<Vec<Vec<u8>>>>,
        ) -> MasqueraderMock {
            *parameters = self.try_unmask_parameters.borrow_mut().clone();
            self
        }
    }

    #[test]
    #[should_panic(expected = "Discriminator must be given at least one Masquerader")]
    fn complains_if_no_masqueraders() {
        Discriminator::new(Box::new(FramerMock::new()), vec![]);
    }

    #[test]
    fn returns_none_if_no_data_has_been_added() {
        let mut subject = Discriminator::new(
            Box::new(FramerMock::new()),
            vec![Box::new(MasqueraderMock::new())],
        );

        let result = subject.take_chunk();

        assert_eq!(result, None);
    }

    #[test]
    fn returns_none_if_all_masqueraders_say_no() {
        let framer = FramerMock::new();
        let mut first_try_unmask_parameters: Arc<Mutex<Vec<Vec<u8>>>> =
            Arc::new(Mutex::new(vec![]));
        let first_masquerader = MasqueraderMock::new()
            .try_unmask_result(Err(MasqueradeError::NotThisMasquerader))
            .try_unmask_parameters(&mut first_try_unmask_parameters);
        let mut second_try_unmask_parameters: Arc<Mutex<Vec<Vec<u8>>>> =
            Arc::new(Mutex::new(vec![]));
        let second_masquerader = MasqueraderMock::new()
            .try_unmask_result(Err(MasqueradeError::NotThisMasquerader))
            .try_unmask_parameters(&mut second_try_unmask_parameters);
        let mut subject = Discriminator::new(
            Box::new(framer),
            vec![Box::new(first_masquerader), Box::new(second_masquerader)],
        );
        subject.add_data(&b"booga"[..]);

        let result = subject.take_chunk();

        assert_eq!(result, None);
        let first_try_unmask_parameters_guard = first_try_unmask_parameters.lock().unwrap();
        assert_eq!(first_try_unmask_parameters_guard[0], &b"booga"[..]);
        assert_eq!(first_try_unmask_parameters_guard.len(), 1);
        let second_try_unmask_parameters_guard = second_try_unmask_parameters.lock().unwrap();
        assert_eq!(second_try_unmask_parameters_guard[0], &b"booga"[..]);
        assert_eq!(second_try_unmask_parameters_guard.len(), 1);
    }

    #[test]
    fn returns_first_data_if_all_masqueraders_say_yes() {
        let mut framer = FramerMock::new();
        framer.add_data(&b"booga"[..]);
        let mut first_try_unmask_parameters: Arc<Mutex<Vec<Vec<u8>>>> =
            Arc::new(Mutex::new(vec![]));
        let mut second_try_unmask_parameters: Arc<Mutex<Vec<Vec<u8>>>> =
            Arc::new(Mutex::new(vec![]));
        let first_masquerader = MasqueraderMock::new()
            .try_unmask_result(Ok(UnmaskedChunk::new(
                Vec::from(&b"choose me"[..]),
                true,
                true,
            )))
            .try_unmask_result(Err(MasqueradeError::NotThisMasquerader))
            .try_unmask_parameters(&mut first_try_unmask_parameters);
        let second_masquerader = MasqueraderMock::new()
            .try_unmask_result(Ok(UnmaskedChunk::new(
                Vec::from(&b"don't choose me"[..]),
                true,
                true,
            )))
            .try_unmask_result(Err(MasqueradeError::NotThisMasquerader))
            .try_unmask_parameters(&mut second_try_unmask_parameters);
        let mut subject = Discriminator::new(
            Box::new(framer),
            vec![Box::new(first_masquerader), Box::new(second_masquerader)],
        );

        let result = subject.take_chunk();

        assert_eq!(
            result,
            Some(UnmaskedChunk::new(Vec::from(&b"choose me"[..]), true, true))
        );
        let first_try_unmask_parameters_guard = first_try_unmask_parameters.lock().unwrap();
        assert_eq!(first_try_unmask_parameters_guard[0], &b"booga"[..]);
        assert_eq!(first_try_unmask_parameters_guard.len(), 1);
        let second_try_unmask_parameters_guard = second_try_unmask_parameters.lock().unwrap();
        assert_eq!(second_try_unmask_parameters_guard.len(), 0);
    }

    #[test]
    fn returns_third_data_if_first_masquerader_says_no_and_second_blows_up() {
        init_test_logging();
        let mut framer = FramerMock::new();
        framer.add_data(&b"booga"[..]);
        let mut first_try_unmask_parameters: Arc<Mutex<Vec<Vec<u8>>>> =
            Arc::new(Mutex::new(vec![]));
        let mut third_try_unmask_parameters: Arc<Mutex<Vec<Vec<u8>>>> =
            Arc::new(Mutex::new(vec![]));
        let first_masquerader = MasqueraderMock::new()
            .try_unmask_result(Err(MasqueradeError::NotThisMasquerader))
            .try_unmask_parameters(&mut first_try_unmask_parameters);
        let second_masquerader = MasqueraderMock::new().try_unmask_result(Err(
            MasqueradeError::HighLevelDataError("that didn't work".to_string()),
        ));
        let third_masquerader = MasqueraderMock::new()
            .try_unmask_result(Ok(UnmaskedChunk::new(
                Vec::from(&b"choose me"[..]),
                true,
                true,
            )))
            .try_unmask_result(Err(MasqueradeError::NotThisMasquerader))
            .try_unmask_parameters(&mut third_try_unmask_parameters);
        let mut subject = Discriminator::new(
            Box::new(framer),
            vec![
                Box::new(first_masquerader),
                Box::new(second_masquerader),
                Box::new(third_masquerader),
            ],
        );

        let result = subject.take_chunk();

        assert_eq!(
            result,
            Some(UnmaskedChunk::new(Vec::from(&b"choose me"[..]), true, true))
        );
        TestLogHandler::new()
            .exists_log_containing("WARN: Discriminator: High-level data error: that didn't work");
    }
}
