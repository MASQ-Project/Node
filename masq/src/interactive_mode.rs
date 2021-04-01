use crate::command_factory::CommandFactory;
use crate::command_processor::CommandProcessor;
use crate::line_reader::TerminalEvent::{
    Break, CommandLine, Continue, Error as TerminalEventError,
};
use masq_lib::command::StdStreams;
use masq_lib::short_writeln;
use std::io::Write;

fn split_quoted_line(input: String) -> Vec<String> {
    let mut active_single = false;
    let mut active_double = false;
    let mut pieces: Vec<String> = vec![];
    let mut current_piece = String::new();
    input.chars().for_each(|c| {
        if c.is_whitespace() && !active_double && !active_single {
            if !current_piece.is_empty() {
                pieces.push(current_piece.clone());
                current_piece.clear();
            }
        } else if c == '"' && !active_single {
            active_double = !active_double;
        } else if c == '\'' && !active_double {
            active_single = !active_single;
        } else {
            current_piece.push(c);
        }
    });
    if !current_piece.is_empty() {
        pieces.push(current_piece)
    }
    pieces
}

pub fn go_interactive<A, B, FN>(
    handle_command: Box<FN>,
    command_factory: &A,
    processor: &mut B,
    streams: &mut StdStreams<'_>,
) -> u8
where
    FN: Fn(&A, &mut B, Vec<String>, &mut (dyn Write + Send)) -> Result<(), ()>,
    A: CommandFactory + ?Sized + 'static,
    B: CommandProcessor + ?Sized + 'static,
{
    loop {
        let args = match processor.clone_terminal_interface().read_line() {
            CommandLine(line) => split_quoted_line(line),
            Break => unimplemented!(),    //Break
            Continue => unimplemented!(), //Continue
            TerminalEventError(msg) => {
                short_writeln!(streams.stderr, "{}", msg);
                return 1;
            }
        };
        if args.is_empty() {
            continue;
        }
        if args[0] == "exit" {
            break;
        }
        match handle_command(command_factory, processor, args, streams.stderr) {
            Ok(_) => (),
            Err(_) => continue,
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use crate::interactive_mode::split_quoted_line;

    #[test]
    fn accept_subcommand_handles_balanced_double_quotes() {
        let command_line =
            "  first \"second\" third  \"fourth'fifth\" \t sixth \"seventh eighth\tninth\" "
                .to_string();

        let result = split_quoted_line(command_line);

        assert_eq!(
            result,
            vec![
                "first".to_string(),
                "second".to_string(),
                "third".to_string(),
                "fourth'fifth".to_string(),
                "sixth".to_string(),
                "seventh eighth\tninth".to_string(),
            ]
        )
    }

    #[test]
    fn accept_subcommand_handles_unbalanced_double_quotes() {
        let command_line =
            "  first \"second\" third  \"fourth'fifth\" \t sixth \"seventh eighth\tninth  "
                .to_string();

        let result = split_quoted_line(command_line);

        assert_eq!(
            result,
            vec![
                "first".to_string(),
                "second".to_string(),
                "third".to_string(),
                "fourth'fifth".to_string(),
                "sixth".to_string(),
                "seventh eighth\tninth  ".to_string(),
            ]
        )
    }

    #[test]
    fn accept_subcommand_handles_balanced_single_quotes() {
        let command_line =
            "  first \n 'second' \n third \n 'fourth\"fifth' \t sixth 'seventh eighth\tninth' "
                .to_string();

        let result = split_quoted_line(command_line);

        assert_eq!(
            result,
            vec![
                "first".to_string(),
                "second".to_string(),
                "third".to_string(),
                "fourth\"fifth".to_string(),
                "sixth".to_string(),
                "seventh eighth\tninth".to_string(),
            ]
        )
    }

    #[test]
    fn accept_subcommand_handles_unbalanced_single_quotes() {
        let command_line =
            "  first 'second' third  'fourth\"fifth' \t sixth 'seventh eighth\tninth  ".to_string();
        let result = split_quoted_line(command_line);

        assert_eq!(
            result,
            vec![
                "first".to_string(),
                "second".to_string(),
                "third".to_string(),
                "fourth\"fifth".to_string(),
                "sixth".to_string(),
                "seventh eighth\tninth  ".to_string(),
            ]
        )
    }
}
