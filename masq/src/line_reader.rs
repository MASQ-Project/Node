// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::utils::MASQ_PROMPT;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use std::io;
use std::io::ErrorKind;
use std::io::{BufRead, Read};

pub struct LineReader {
    delegate: Box<dyn EditorTrait>,
}

impl Read for LineReader {
    fn read(&mut self, _: &mut [u8]) -> Result<usize, io::Error> {
        panic!("Should never be called");
    }
}

impl BufRead for LineReader {
    fn fill_buf(&mut self) -> Result<&[u8], io::Error> {
        panic!("Should never be called");
    }

    fn consume(&mut self, _: usize) {
        panic!("Should never be called");
    }

    fn read_line(&mut self, buf: &mut String) -> Result<usize, io::Error> {
        let line = match self.delegate.readline(MASQ_PROMPT) {
            Ok(line) => line,
            Err(e) => match e {
                ReadlineError::Eof => {
                    return Err(io::Error::new(ErrorKind::UnexpectedEof, "End of file"))
                }
                ReadlineError::Interrupted => {
                    return Err(io::Error::new(ErrorKind::Interrupted, "Interrupted"))
                }
                other => return Err(io::Error::new(ErrorKind::Other, format!("{}", other))),
            },
        };
        self.delegate.add_history_entry(&line);
        let len = line.len();
        buf.clear();
        buf.push_str(&line);
        Ok(len)
    }
}

impl Default for LineReader {
    fn default() -> Self {
        LineReader::new()
    }
}

impl LineReader {
    pub fn new() -> LineReader {
        LineReader {
            delegate: Box::new(EditorReal::default()),
        }
    }
}

trait EditorTrait {
    fn readline(&mut self, prompt: &str) -> Result<String, ReadlineError>;
    fn add_history_entry(&mut self, line: &str) -> bool;
}

struct EditorReal {
    delegate: Editor<()>,
}

impl EditorTrait for EditorReal {
    fn readline(&mut self, prompt: &str) -> Result<String, ReadlineError> {
        self.delegate.readline(prompt)
    }

    fn add_history_entry(&mut self, line: &str) -> bool {
        self.delegate.add_history_entry(line)
    }
}

impl Default for EditorReal {
    fn default() -> Self {
        EditorReal {
            delegate: Editor::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};

    struct EditorMock {
        readline_params: Arc<Mutex<Vec<String>>>,
        readline_results: RefCell<Vec<Result<String, ReadlineError>>>,
        add_history_entry_params: Arc<Mutex<Vec<String>>>,
        add_history_entry_results: RefCell<Vec<bool>>,
    }

    impl EditorTrait for EditorMock {
        fn readline(&mut self, prompt: &str) -> Result<String, ReadlineError> {
            self.readline_params
                .lock()
                .unwrap()
                .push(prompt.to_string());
            self.readline_results.borrow_mut().remove(0)
        }

        fn add_history_entry(&mut self, line: &str) -> bool {
            self.add_history_entry_params
                .lock()
                .unwrap()
                .push(line.to_string());
            self.add_history_entry_results.borrow_mut().remove(0)
        }
    }

    impl EditorMock {
        fn new() -> EditorMock {
            EditorMock {
                readline_params: Arc::new(Mutex::new(vec![])),
                readline_results: RefCell::new(vec![]),
                add_history_entry_params: Arc::new(Mutex::new(vec![])),
                add_history_entry_results: RefCell::new(vec![]),
            }
        }

        fn readline_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
            self.readline_params = params.clone();
            self
        }

        fn readline_result(self, result: Result<String, ReadlineError>) -> Self {
            self.readline_results.borrow_mut().push(result);
            self
        }

        fn add_history_entry_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
            self.add_history_entry_params = params.clone();
            self
        }

        fn add_history_entry_result(self, result: bool) -> Self {
            self.add_history_entry_results.borrow_mut().push(result);
            self
        }
    }

    #[test]
    #[should_panic(expected = "Should never be called")]
    fn read_doesnt_work() {
        let mut subject = LineReader::new();

        let _ = subject.read(&mut [0; 0]);
    }

    #[test]
    #[should_panic(expected = "Should never be called")]
    fn fill_buf_doesnt_work() {
        let mut subject = LineReader::new();

        let _ = subject.fill_buf();
    }

    #[test]
    #[should_panic(expected = "Should never be called")]
    fn consume_doesnt_work() {
        let mut subject = LineReader::new();

        let _ = subject.consume(0);
    }

    #[test]
    fn read_line_works_when_rustyline_succeeds() {
        let line = "Mary had a little lamb";
        let readline_params_arc = Arc::new(Mutex::new(vec![]));
        let add_history_entry_params_arc = Arc::new(Mutex::new(vec![]));
        let editor = EditorMock::new()
            .readline_params(&readline_params_arc)
            .readline_result(Ok(line.to_string()))
            .add_history_entry_params(&add_history_entry_params_arc)
            .add_history_entry_result(true);
        let mut subject = LineReader::new();
        subject.delegate = Box::new(editor);
        let mut buf = "this should be overwritten".to_string();

        let result = subject.read_line(&mut buf);

        assert_eq!(result.unwrap(), line.len());
        assert_eq!(buf, line.to_string());
        let readline_params = readline_params_arc.lock().unwrap();
        assert_eq!(*readline_params, vec![MASQ_PROMPT.to_string()]);
        let add_history_entry_params = add_history_entry_params_arc.lock().unwrap();
        assert_eq!(*add_history_entry_params, vec![line.to_string()]);
    }

    #[test]
    fn read_line_works_when_rustyline_says_eof() {
        let editor = EditorMock::new().readline_result(Err(ReadlineError::Eof));
        let mut subject = LineReader::new();
        subject.delegate = Box::new(editor);
        let mut buf = String::new();

        let result = subject.read_line(&mut buf);

        assert_eq!(result.err().unwrap().to_string(), "End of file".to_string());
        assert_eq!(buf, String::new());
    }

    #[test]
    fn read_line_works_when_rustyline_says_interrupted() {
        let editor = EditorMock::new().readline_result(Err(ReadlineError::Interrupted));
        let mut subject = LineReader::new();
        subject.delegate = Box::new(editor);
        let mut buf = String::new();

        let result = subject.read_line(&mut buf);

        assert_eq!(result.err().unwrap().to_string(), "Interrupted".to_string());
        assert_eq!(buf, String::new());
    }

    #[test]
    fn read_line_works_when_rustyline_says_something_else() {
        let editor = EditorMock::new().readline_result(Err(ReadlineError::Io(io::Error::new(
            ErrorKind::Other,
            "Booga!",
        ))));
        let mut subject = LineReader::new();
        subject.delegate = Box::new(editor);
        let mut buf = String::new();

        let result = subject.read_line(&mut buf);

        assert_eq!(result.err().unwrap().to_string(), "Booga!".to_string());
        assert_eq!(buf, String::new());
    }
}
