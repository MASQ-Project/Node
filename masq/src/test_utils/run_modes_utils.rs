// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::terminal::WTermInterfaceDupAndSend;
use crate::test_utils::mocks::AsyncTestStreamHandles;
use itertools::Either;
use std::fmt::Debug;

#[derive(Default)]
pub struct StdStreamsAssertion<'test> {
    incidental_std_streams_opt: Option<BareStreamsFromStreamFactoryAssertionMatrix<'test>>,
    processor_std_streams_opt: Option<BareStreamsFromStreamFactoryAssertionMatrix<'test>>,
    processor_term_interface_opt: Option<ProcessorTerminalInterfaceAssertion<'test>>,
    // This is the only one allowed to stay unpopulated
    broadcast_handler_term_interface_opt:
        Option<BroadcastHandlerTerminalInterfaceAssertionMatrix<'test>>,
}

impl<'test> StdStreamsAssertion<'test> {
    pub fn incidental_std_streams(
        mut self,
        assert: Assert<'test, BareStreamsFromStreamFactoryAssertionMatrix<'test>>,
    ) -> Self {
        self.incidental_std_streams_opt = Some(IntoAppeasingRustRules::into(assert));
        self
    }
    pub fn processor_aspiring_std_streams(
        mut self,
        assert: Assert<'test, BareStreamsFromStreamFactoryAssertionMatrix<'test>>,
    ) -> Self {
        self.processor_std_streams_opt = Some(IntoAppeasingRustRules::into(assert));
        self
    }

    pub fn processor_term_interface(
        mut self,
        assert: Assert<'test, ProcessorTerminalInterfaceAssertion<'test>>,
    ) -> Self {
        self.processor_term_interface_opt = Some(IntoAppeasingRustRules::into(assert));
        self
    }

    pub fn broadcast_handler_term_interface(
        mut self,
        assert: AssertBroadcastHandler<'test>,
    ) -> Self {
        self.broadcast_handler_term_interface_opt = Some(assert.into());
        self
    }
}

pub trait AssertableAlsoAsNotUsed<'test>
where
    Self: Sized,
{
    fn compose_assertion_matrix_for_not_used(stream_handles: &'test AsyncTestStreamHandles)
        -> Self;
    fn check_that_populated(expected_fully_defined: Self) -> Self;
}

pub enum Assert<'test, Assertion: AssertableAlsoAsNotUsed<'test>> {
    Expected(Assertion),
    NotUsed(&'test AsyncTestStreamHandles),
}

trait IntoAppeasingRustRules<SomeType> {
    fn into(self) -> SomeType;
}

impl<'test, Assertion: AssertableAlsoAsNotUsed<'test>> IntoAppeasingRustRules<Assertion>
    for Assert<'test, Assertion>
{
    fn into(self) -> Assertion {
        match self {
            Assert::Expected(fully_defined) => fully_defined,
            Assert::NotUsed(stream_handles) => {
                Assertion::compose_assertion_matrix_for_not_used(stream_handles)
            }
        }
    }
}

pub enum AssertBroadcastHandler<'test> {
    Expected(BroadcastHandlerTerminalInterfaceAssertionMatrix<'test>),
    NotUsed {
        intercepted_broadcast_handler_term_interface_opt:
            Option<&'test Box<dyn WTermInterfaceDupAndSend>>,
        stream_handles: &'test AsyncTestStreamHandles,
    },
    // It's not present in the non-interactive mode
    Nonexistent(Option<&'test Box<dyn WTermInterfaceDupAndSend>>),
}

impl<'test> From<AssertBroadcastHandler<'test>>
    for BroadcastHandlerTerminalInterfaceAssertionMatrix<'test>
{
    fn from(assert: AssertBroadcastHandler<'test>) -> Self {
        match assert {
            AssertBroadcastHandler::Expected(matrix) => matrix,
            AssertBroadcastHandler::NotUsed {
                intercepted_broadcast_handler_term_interface_opt,
                stream_handles,
            } => BroadcastHandlerTerminalInterfaceAssertionMatrix::assert_terminal_not_used(
                intercepted_broadcast_handler_term_interface_opt,
                stream_handles,
            ),
            AssertBroadcastHandler::Nonexistent(terminal_opt) => {
                BroadcastHandlerTerminalInterfaceAssertionMatrix::assert_terminal_not_created(
                    terminal_opt,
                )
            }
        }
    }
}

pub struct BareStreamsFromStreamFactoryAssertionMatrix<'test> {
    stream_handles: &'test AsyncTestStreamHandles,
    write_streams: WriteStreamsAssertion<'test>,
    // Reading should be forbidden in these streams
}

impl<'test> BareStreamsFromStreamFactoryAssertionMatrix<'test> {
    pub fn new<AssertionDetails: Into<WriteStreamsAssertion<'test>>>(
        stream_handles: &'test AsyncTestStreamHandles,
        streams_assertion_details: AssertionDetails,
    ) -> Self {
        Self {
            stream_handles,
            write_streams: streams_assertion_details.into(),
        }
    }
}

impl<'test> AssertableAlsoAsNotUsed<'test> for BareStreamsFromStreamFactoryAssertionMatrix<'test> {
    fn compose_assertion_matrix_for_not_used(stream_handles: &'test AsyncTestStreamHandles) -> Self
    where
        Self: Sized,
    {
        Self {
            stream_handles,
            write_streams: WriteStreamsAssertion {
                one_piece_or_distinct_flushes: Either::Left(OnePieceWriteStreamsAssertion {
                    stdout_opt: None,
                    stderr_opt: None,
                }),
            },
        }
    }

    fn check_that_populated(expected_fully_defined: Self) -> Self {
        let is_populated = match &expected_fully_defined
            .write_streams
            .one_piece_or_distinct_flushes
        {
            Either::Left(one_piece_strings) => {
                one_piece_strings.stdout_opt.is_some() || one_piece_strings.stderr_opt.is_some()
            }
            Either::Right(flushed_strings) => {
                !flushed_strings.stdout.is_empty() || !flushed_strings.stderr.is_empty()
            }
        };

        if !is_populated {
            panic!("This assertion can be set up more simply by using the structure 'NotUsed' instead of 'Expected'")
        }

        expected_fully_defined
    }
}

pub struct TerminalInterfaceAssertion<'test> {
    term_interface_stream_handles: &'test AsyncTestStreamHandles,
    expected_writes: WriteStreamsAssertion<'test>,
    // None ... non-interactive mode,
    // Some ... interactive mode
    read_attempts_opt: Option<usize>,
}

impl<'test> TerminalInterfaceAssertion<'test> {
    pub fn new<AssertionDetails: Into<WriteStreamsAssertion<'test>>>(
        term_interface_stream_handles: &'test AsyncTestStreamHandles,
        assertion_details: AssertionDetails,
    ) -> TerminalInterfaceAssertion<'test> {
        Self {
            term_interface_stream_handles,
            expected_writes: assertion_details.into(),
            read_attempts_opt: None,
        }
    }

    pub fn expected_read_attempts(mut self, read_attempts: usize) -> Self {
        self.read_attempts_opt = Some(read_attempts);
        self
    }
}

pub struct ProcessorTerminalInterfaceAssertion<'test> {
    standard_assertions: TerminalInterfaceAssertion<'test>,
}

impl<'test> ProcessorTerminalInterfaceAssertion<'test> {
    pub fn new(standard_assertions: TerminalInterfaceAssertion<'test>) -> Self {
        Self {
            standard_assertions,
        }
    }
}

impl<'test> AssertableAlsoAsNotUsed<'test> for ProcessorTerminalInterfaceAssertion<'test> {
    fn compose_assertion_matrix_for_not_used(stream_handles: &'test AsyncTestStreamHandles) -> Self
    where
        Self: Sized,
    {
        Self {
            standard_assertions: TerminalInterfaceAssertion {
                term_interface_stream_handles: stream_handles,
                expected_writes: WriteStreamsAssertion {
                    one_piece_or_distinct_flushes: Either::Left(OnePieceWriteStreamsAssertion {
                        stdout_opt: None,
                        stderr_opt: None,
                    }),
                },
                read_attempts_opt: None,
            },
        }
    }

    fn check_that_populated(expected_fully_defined: Self) -> Self {
        let is_populated = match &expected_fully_defined
            .standard_assertions
            .expected_writes
            .one_piece_or_distinct_flushes
        {
            Either::Left(in_one_piece) => {
                in_one_piece.stdout_opt.is_some() || in_one_piece.stderr_opt.is_some()
            }
            Either::Right(flushed_strings) => {
                !flushed_strings.stdout.is_empty() || !flushed_strings.stderr.is_empty()
            }
        };

        if !is_populated {
            panic!("This assertion can be set up more simply by using the structure 'NotUsed' instead of 'Expected'")
        }

        expected_fully_defined
    }
}

pub struct BroadcastHandlerTerminalInterfaceAssertionMatrix<'test> {
    pub w_term_interface_opt: Option<&'test Box<dyn WTermInterfaceDupAndSend>>,
    // None means the terminal is not even considered as existing, we therefore suspect
    // the non-interactive mode
    pub expected_std_streams_usage_opt: Option<TerminalInterfaceAssertion<'test>>,
}

impl<'test> BroadcastHandlerTerminalInterfaceAssertionMatrix<'test> {
    fn assert_terminal_not_created(
        w_term_interface_opt: Option<&'test Box<dyn WTermInterfaceDupAndSend>>,
    ) -> Self {
        Self {
            w_term_interface_opt,
            expected_std_streams_usage_opt: None,
        }
    }

    fn assert_terminal_not_used(
        w_term_interface_opt: Option<&'test Box<dyn WTermInterfaceDupAndSend>>,
        stream_handles: &'test AsyncTestStreamHandles,
    ) -> Self {
        Self {
            w_term_interface_opt,
            expected_std_streams_usage_opt: Some(TerminalInterfaceAssertion {
                term_interface_stream_handles: stream_handles,
                expected_writes: WriteStreamsAssertion {
                    one_piece_or_distinct_flushes: Either::Left(OnePieceWriteStreamsAssertion {
                        stdout_opt: None,
                        stderr_opt: None,
                    }),
                },
                read_attempts_opt: None,
            }),
        }
    }
}

#[derive(Debug)]
pub enum StreamType {
    Stdout,
    Stderr,
}

pub trait AssertionValuesWithTestableExpectedStreamOutputEmptiness {
    fn is_empty_stdout_output_expected(&self) -> bool;
    fn is_empty_stderr_output_expected(&self) -> bool;
}

#[derive(Default)]
pub struct OnePieceWriteStreamsAssertion<'test> {
    stdout_opt: Option<&'test str>,
    stderr_opt: Option<&'test str>,
}

impl<'test> OnePieceWriteStreamsAssertion<'test> {
    pub fn stdout(mut self, expected: &'test str) -> Self {
        self.stdout_opt = Some(expected);
        self
    }
    pub fn stderr(mut self, expected: &'test str) -> Self {
        self.stderr_opt = Some(expected);
        self
    }
}

impl AssertionValuesWithTestableExpectedStreamOutputEmptiness
    for OnePieceWriteStreamsAssertion<'_>
{
    fn is_empty_stdout_output_expected(&self) -> bool {
        self.stdout_opt.is_none()
    }

    fn is_empty_stderr_output_expected(&self) -> bool {
        self.stderr_opt.is_none()
    }
}

#[derive(Default)]
pub struct FlushesWriteStreamsAssertion<'test> {
    stdout: Vec<&'test str>,
    stderr: Vec<&'test str>,
}

impl<'test> FlushesWriteStreamsAssertion<'test> {
    pub fn stdout(mut self, expected: Vec<&'test str>) -> Self {
        self.stdout = expected;
        self
    }
    pub fn stderr(mut self, expected: Vec<&'test str>) -> Self {
        self.stderr = expected;
        self
    }
}

impl AssertionValuesWithTestableExpectedStreamOutputEmptiness for FlushesWriteStreamsAssertion<'_> {
    fn is_empty_stdout_output_expected(&self) -> bool {
        self.stdout.is_empty()
    }

    fn is_empty_stderr_output_expected(&self) -> bool {
        self.stderr.is_empty()
    }
}

pub struct WriteStreamsAssertion<'test> {
    pub one_piece_or_distinct_flushes:
        Either<OnePieceWriteStreamsAssertion<'test>, FlushesWriteStreamsAssertion<'test>>,
}

impl<'test> From<OnePieceWriteStreamsAssertion<'test>> for WriteStreamsAssertion<'test> {
    fn from(assertions: OnePieceWriteStreamsAssertion<'test>) -> Self {
        WriteStreamsAssertion {
            one_piece_or_distinct_flushes: Either::Left(assertions),
        }
    }
}

impl<'test> From<FlushesWriteStreamsAssertion<'test>> for WriteStreamsAssertion<'test> {
    fn from(assertions: FlushesWriteStreamsAssertion<'test>) -> Self {
        WriteStreamsAssertion {
            one_piece_or_distinct_flushes: Either::Right(assertions),
        }
    }
}

impl<'test> StdStreamsAssertion<'test> {
    pub async fn assert(self) {
        let incidental_streams = self
            .incidental_std_streams_opt
            .expect("incidental std streams assertions not configured");
        assert_stream_writes(
            incidental_streams.stream_handles,
            incidental_streams.write_streams,
        )
        .await;
        assert_stream_reads(&incidental_streams.stream_handles, Some(0));

        let processor_aspiring_streams = self
            .processor_std_streams_opt
            .expect("processor-aspiring std streams assertions not configured");
        assert_stream_writes(
            processor_aspiring_streams.stream_handles,
            processor_aspiring_streams.write_streams,
        )
        .await;
        assert_stream_reads(&processor_aspiring_streams.stream_handles, Some(0));

        let processor_term_interface = self
            .processor_term_interface_opt
            .expect("processor terminal interface assertions not configured");
        let processor_term_interface_stream_handles = processor_term_interface
            .standard_assertions
            .term_interface_stream_handles;
        let processor_term_interface_expected_writes =
            processor_term_interface.standard_assertions.expected_writes;
        let processor_term_interface_expected_read_attempts_opt = processor_term_interface
            .standard_assertions
            .read_attempts_opt;

        assert_stream_writes(
            processor_term_interface_stream_handles,
            processor_term_interface_expected_writes,
        )
        .await;
        assert_stream_reads(
            &processor_term_interface_stream_handles,
            processor_term_interface_expected_read_attempts_opt,
        );

        match self.broadcast_handler_term_interface_opt {
            Some(broadcast_term_interface) => {
                assert_broadcast_term_interface_outputs(
                    broadcast_term_interface.w_term_interface_opt,
                    broadcast_term_interface.expected_std_streams_usage_opt,
                )
                .await
            }
            None => (),
        }
    }
}

async fn assert_broadcast_term_interface_outputs<'test>(
    term_interface_opt: Option<&'test Box<dyn WTermInterfaceDupAndSend>>,
    expected_std_streams_usage_opt: Option<TerminalInterfaceAssertion<'test>>,
) {
    macro_rules! assert_terminal_output_stream_and_its_stream_handle_are_connected {
        ($fetch_write_utils: expr, $await_non_empty_output: expr, $fetch_written_data_all_in_one: expr, $literals_to_test_it_with: literal) => {
            let (std_stream_writer, flush_handle) = $fetch_write_utils;
            std_stream_writer.write($literals_to_test_it_with).await;
            drop(flush_handle);
            $await_non_empty_output.await;
            assert_eq!($fetch_written_data_all_in_one, $literals_to_test_it_with)
        };
    }

    match (term_interface_opt, expected_std_streams_usage_opt) {
        (Some(w_terminal), Some(expected_usage)) => {
            assert_stream_writes(expected_usage.term_interface_stream_handles, expected_usage.expected_writes).await;
            assert_terminal_output_stream_and_its_stream_handle_are_connected!(
                    w_terminal.stdout(),
                    expected_usage.term_interface_stream_handles.await_stdout_is_not_empty(),
                    expected_usage.term_interface_stream_handles.stdout_all_in_one(),
                    "AbCdEfG"
                );
            assert_terminal_output_stream_and_its_stream_handle_are_connected!(
                    w_terminal.stderr(),
                    expected_usage.term_interface_stream_handles.await_stderr_is_not_empty(),
                    expected_usage.term_interface_stream_handles.stderr_all_in_one(),
                    "1a2b3c4"
                );
            let reads_opt = expected_usage.term_interface_stream_handles.reads_opt();
            assert_eq!(reads_opt, None)
        }
        (None, None)  => (),
        (actual_opt, expected_opt) => panic!("Interactive mode was expected: {}. But broadcast terminal interface was created and supplied: {}. (Non-interactive mode is not supposed to have one)", expected_opt.is_some(), actual_opt.is_some())
    }
}

async fn assert_stream_writes<'test>(
    original_stream_handles: &AsyncTestStreamHandles,
    expected_writes: WriteStreamsAssertion<'test>,
) {
    fn optional_into_empty_or_populated_string(string_opt: Option<&str>) -> String {
        string_opt.map(|s| s.to_string()).unwrap_or_default()
    }
    fn owned_strings(strings: &[&str]) -> Vec<String> {
        strings.into_iter().map(|s| s.to_string()).collect()
    }

    match expected_writes.one_piece_or_distinct_flushes {
        Either::Left(one_piece) => {
            assert_single_write_stream(
                StreamType::Stdout,
                original_stream_handles,
                &one_piece,
                |original_stream_handles| original_stream_handles.stdout_all_in_one(),
                |one_piece| optional_into_empty_or_populated_string(one_piece.stdout_opt),
            )
            .await;
            assert_single_write_stream(
                StreamType::Stderr,
                original_stream_handles,
                &one_piece,
                |original_stream_handles| original_stream_handles.stderr_all_in_one(),
                |one_piece| optional_into_empty_or_populated_string(one_piece.stderr_opt),
            )
            .await
        }
        Either::Right(flushes) => {
            assert_single_write_stream(
                StreamType::Stdout,
                original_stream_handles,
                &flushes,
                |original_stream_handles| original_stream_handles.stdout_flushed_strings(),
                |flushes| owned_strings(&flushes.stdout),
            )
            .await;
            assert_single_write_stream(
                StreamType::Stderr,
                original_stream_handles,
                &flushes,
                |original_stream_handles| original_stream_handles.stderr_flushed_strings(),
                |flushes| owned_strings(&flushes.stderr),
            )
            .await
        }
    }
}

async fn assert_single_write_stream<ExpectedValue, Fn1, Fn2, AssertionValues>(
    std_stream: StreamType,
    original_stream_handles: &AsyncTestStreamHandles,
    preliminarily_examinable_assertion: &AssertionValues,
    actual_value_fetcher: Fn1,
    expected_value_extractor: Fn2,
) where
    ExpectedValue: Debug + PartialEq,
    Fn1: Fn(&AsyncTestStreamHandles) -> ExpectedValue,
    Fn2: Fn(&AssertionValues) -> ExpectedValue,
    AssertionValues: AssertionValuesWithTestableExpectedStreamOutputEmptiness,
{
    let is_emptiness_expected = match std_stream {
        StreamType::Stdout => preliminarily_examinable_assertion.is_empty_stdout_output_expected(),
        StreamType::Stderr => preliminarily_examinable_assertion.is_empty_stderr_output_expected(),
    };

    match is_emptiness_expected {
        true => (),
        false => {
            let expected_value_debug = || {
                format!(
                    "{:?}",
                    expected_value_extractor(preliminarily_examinable_assertion)
                )
            };

            match std_stream {
                StreamType::Stdout => {
                    original_stream_handles
                        .await_stdout_is_not_empty_or_panic_with_expected(&expected_value_debug())
                        .await
                }
                StreamType::Stderr => {
                    original_stream_handles
                        .await_stderr_is_not_empty_or_panic_with_expected(&expected_value_debug())
                        .await
                }
            }
        }
    }

    let actual_output = actual_value_fetcher(original_stream_handles);
    let expected_output = expected_value_extractor(preliminarily_examinable_assertion);

    assert_eq!(
        actual_output, expected_output,
        "We expected this printed by {:?} {:?} but was {:?}",
        std_stream, expected_output, actual_output
    );
}

fn assert_stream_reads(
    std_stream_handles: &AsyncTestStreamHandles,
    // None means that the stdin was not provided (as in the write-only terminal interface)
    expected_read_attempts_opt: Option<usize>,
) {
    let actual_reads_opt = std_stream_handles.reads_opt();
    match (actual_reads_opt, expected_read_attempts_opt) {
        (Some(actual), Some(expected)) => assert_eq!(
            actual, expected,
            "Expected read attempts {} don't match the actual {}",
            expected, actual
        ),
        (None, None) | (Some(0), None) => (),
        (actual_opt, expected_opt) => panic!(
            "Expected {:?} doesn't match the actual {:?}",
            expected_opt, actual_opt
        ),
    }
}
