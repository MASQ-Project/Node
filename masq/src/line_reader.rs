// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::utils::MASQ_PROMPT;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use std::cell::RefCell;
use std::io;
use std::io::{BufRead, Read};
use std::io::{ErrorKind, Write};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

pub struct LineReader {
    output_synchronizer: Arc<Mutex<()>>,
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
        self.print_prompt_synchronized();
        let line = match self.delegate.readline() {
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

impl LineReader {
    pub fn new(output_synchronizer: Arc<Mutex<()>>) -> LineReader {
        LineReader {
            output_synchronizer,
            delegate: Box::new(EditorReal::new(Box::new(io::stdout()))),
        }
    }
    fn print_prompt_synchronized(&mut self) {
        let _lock = self
            .output_synchronizer
            .lock()
            .expect("Output synchronizer mutex poisoned");
        let stdout = self.delegate.stdout();
        let _ = stdout
            .borrow_mut()
            .write(MASQ_PROMPT.as_bytes())
            .expect("writing to stdout failed");
        stdout.borrow_mut().flush().expect("flushing stdout failed");
    }
}

trait EditorTrait {
    fn readline(&mut self) -> Result<String, ReadlineError>;
    fn add_history_entry(&mut self, line: &str) -> bool;
    fn stdout(&mut self) -> Rc<RefCell<Box<dyn Write>>>;
}

struct EditorReal {
    delegate: Editor<()>,
    stdout: Rc<RefCell<Box<dyn Write>>>,
}

impl EditorTrait for EditorReal {
    fn readline(&mut self) -> Result<String, ReadlineError> {
        self.delegate.readline("")
    }

    fn add_history_entry(&mut self, line: &str) -> bool {
        self.delegate.add_history_entry(line)
    }
    fn stdout(&mut self) -> Rc<RefCell<Box<dyn Write>>> {
        self.stdout.clone()
    }
}

impl EditorReal {
    fn new(stdout: Box<dyn Write>) -> Self {
        EditorReal {
            delegate: Editor::new(),
            stdout: Rc::new(RefCell::new(stdout)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};

    use crate::test_utils::mocks::MixingStdout;
    use crossbeam_channel::unbounded;
    use std::thread;

    struct EditorMock {
        readline_results: RefCell<Vec<Result<String, ReadlineError>>>,
        add_history_entry_params: Arc<Mutex<Vec<String>>>,
        add_history_entry_results: RefCell<Vec<bool>>,
        stdout_results: RefCell<Vec<Rc<RefCell<Box<dyn Write>>>>>,
    }

    impl EditorTrait for EditorMock {
        fn readline(&mut self) -> Result<String, ReadlineError> {
            self.readline_results.borrow_mut().remove(0)
        }

        fn add_history_entry(&mut self, line: &str) -> bool {
            self.add_history_entry_params
                .lock()
                .unwrap()
                .push(line.to_string());
            self.add_history_entry_results.borrow_mut().remove(0)
        }

        fn stdout(&mut self) -> Rc<RefCell<Box<dyn Write>>> {
            self.stdout_results.borrow_mut().remove(0)
        }
    }

    impl EditorMock {
        fn new() -> EditorMock {
            EditorMock {
                readline_results: RefCell::new(vec![]),
                add_history_entry_params: Arc::new(Mutex::new(vec![])),
                add_history_entry_results: RefCell::new(vec![]),
                stdout_results: RefCell::new(vec![]),
            }
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

        fn stdout_result(self, result: Rc<RefCell<Box<dyn Write>>>) -> Self {
            self.stdout_results.borrow_mut().push(result);
            self
        }
    }

    #[test]
    #[should_panic(expected = "Should never be called")]
    fn read_doesnt_work() {
        let mut subject = LineReader::new(Arc::new(Mutex::new(())));

        let _ = subject.read(&mut [0; 0]);
    }

    #[test]
    #[should_panic(expected = "Should never be called")]
    fn fill_buf_doesnt_work() {
        let mut subject = LineReader::new(Arc::new(Mutex::new(())));

        let _ = subject.fill_buf();
    }

    #[test]
    #[should_panic(expected = "Should never be called")]
    fn consume_doesnt_work() {
        let mut subject = LineReader::new(Arc::new(Mutex::new(())));

        let _ = subject.consume(0);
    }

    #[test]
    fn read_line_works_when_rustyline_succeeds() {
        let line = "Mary had a little lamb";
        //    let readline_params_arc = Arc::new(Mutex::new(vec![]));
        let add_history_entry_params_arc = Arc::new(Mutex::new(vec![]));
        let editor = EditorMock::new()
            //     .readline_params(&readline_params_arc)
            .readline_result(Ok(line.to_string()))
            .add_history_entry_params(&add_history_entry_params_arc)
            .add_history_entry_result(true)
            .stdout_result(Rc::new(RefCell::new(Box::new(vec![0u8])))) ///////////////TODO make one line
            .stdout_result(Rc::new(RefCell::new(Box::new(vec![0u8]))));
        let mut subject = LineReader::new(Arc::new(Mutex::new(())));
        subject.delegate = Box::new(editor);
        let mut buf = "this should be overwritten".to_string();

        let result = subject.read_line(&mut buf);

        assert_eq!(result.unwrap(), line.len());
        assert_eq!(buf, line.to_string());
        //  let readline_params = readline_params_arc.lock().unwrap();
        //   assert_eq!(*readline_params, vec![MASQ_PROMPT.to_string()]);
        let add_history_entry_params = add_history_entry_params_arc.lock().unwrap();
        assert_eq!(*add_history_entry_params, vec![line.to_string()]);
    }

    #[test]
    fn read_line_works_when_rustyline_says_eof() {
        let editor = EditorMock::new()
            .readline_result(Err(ReadlineError::Eof))
            .stdout_result(Rc::new(RefCell::new(Box::new(vec![0u8]))));
        let mut subject = LineReader::new(Arc::new(Mutex::new(())));
        subject.delegate = Box::new(editor);
        let mut buf = String::new();

        let result = subject.read_line(&mut buf);

        assert_eq!(result.err().unwrap().to_string(), "End of file".to_string());
        assert_eq!(buf, String::new());
    }

    #[test]
    fn read_line_works_when_rustyline_says_interrupted() {
        let editor = EditorMock::new()
            .readline_result(Err(ReadlineError::Interrupted))
            .stdout_result(Rc::new(RefCell::new(Box::new(vec![0u8]))));
        let mut subject = LineReader::new(Arc::new(Mutex::new(())));
        subject.delegate = Box::new(editor);
        let mut buf = String::new();

        let result = subject.read_line(&mut buf);

        assert_eq!(result.err().unwrap().to_string(), "Interrupted".to_string());
        assert_eq!(buf, String::new());
    }

    #[test]
    fn read_line_works_when_rustyline_says_something_else() {
        let editor = EditorMock::new()
            .readline_result(Err(ReadlineError::Io(io::Error::new(
                ErrorKind::Other,
                "Booga!",
            ))))
            .stdout_result(Rc::new(RefCell::new(Box::new(vec![0u8]))));
        let mut subject = LineReader::new(Arc::new(Mutex::new(())));
        subject.delegate = Box::new(editor);
        let mut buf = String::new();

        let result = subject.read_line(&mut buf);

        assert_eq!(result.err().unwrap().to_string(), "Booga!".to_string());
        assert_eq!(buf, String::new());
    }

    #[test]
    fn read_line_synchronization_works() {
        let synchronizer_arc = Arc::new(Mutex::new(()));
        let synchronizer_arc_clone = synchronizer_arc.clone();

        let (tx, rx) = unbounded();

        let thread_handle = thread::spawn(move || {
            let mut subject = LineReader::new(synchronizer_arc_clone);
            let buffer_arc = Box::new(MixingStdout::new(tx));
            let editor =
                EditorMock::new().stdout_result(Rc::new(RefCell::new(Box::new(buffer_arc))));
            subject.delegate = Box::new(editor);
            subject.print_prompt_synchronized();
        });
        let printed_string = rx.recv().unwrap();

        thread_handle.join().unwrap();

        assert_eq!(printed_string, "masq> ".to_string())
    }
}
