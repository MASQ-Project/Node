// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::bit_queue::BitQueue;
use crate::country_block_serde::{CountryBlockSerializer, FinalBitQueue};
use crate::country_block_stream::CountryBlock;
use std::io;

const COUNTRY_BLOCK_BIT_SIZE: usize = 64;

pub fn ip_country(
    _args: Vec<String>,
    stdin: &mut dyn io::Read,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> i32 {
    let mut serializer = CountryBlockSerializer::new();
    let mut csv_rdr = csv::Reader::from_reader(stdin);
    let mut errors = csv_rdr
        .records()
        .map(|string_record_result| match string_record_result {
            Ok(string_record) => CountryBlock::try_from(string_record),
            Err(e) => Err(format!("CSV format error: {:?}", e)),
        })
        .enumerate()
        .flat_map(|(idx, country_block_result)| match country_block_result {
            Ok(country_block) => {
                serializer.add(country_block);
                None
            }
            Err(e) => Some(format!("Line {}: {}", idx + 1, e)),
        })
        .collect::<Vec<String>>();
    let (final_ipv4, final_ipv6) = serializer.finish();
    if let Err(error) = generate_rust_code(final_ipv4, final_ipv6, stdout) {
        errors.push(format!("Error generating Rust code: {:?}", error))
    }
    if errors.is_empty() {
        0
    } else {
        let error_list = errors.join("\n");
        write!(
            stdout,
            r#"
            *** DO NOT USE THIS CODE ***
            It will produce incorrect results.
            The process that generated it found these errors:

{}

            Fix the errors and regenerate the code.
            *** DO NOT USE THIS CODE ***
"#,
            error_list
        )
        .expect("expected WANRNING output");
        write!(stderr, "{}", error_list).expect("expected error list output");
        1
    }
}

fn generate_rust_code(
    final_ipv4: FinalBitQueue,
    final_ipv6: FinalBitQueue,
    output: &mut dyn io::Write,
) -> Result<(), io::Error> {
    write!(output, "\n// GENERATED CODE: REGENERATE, DO NOT MODIFY!\n")?;
    generate_country_data(
        "ipv4_country",
        final_ipv4.bit_queue,
        output,
        final_ipv4.block_count,
    )?;
    generate_country_data(
        "ipv6_country",
        final_ipv6.bit_queue,
        output,
        final_ipv6.block_count,
    )?;
    Ok(())
}

fn generate_country_data(
    name: &str,
    mut bit_queue: BitQueue,
    output: &mut dyn io::Write,
    block_count: usize,
) -> Result<(), io::Error> {
    let bit_queue_len = bit_queue.len();
    writeln!(output)?;
    writeln!(output, "pub fn {}_data() -> (Vec<u64>, usize) {{", name)?;
    writeln!(output, "    (")?;
    write!(output, "        vec![")?;
    let mut values_written = 0usize;
    while bit_queue.len() >= COUNTRY_BLOCK_BIT_SIZE {
        write_value(
            &mut bit_queue,
            COUNTRY_BLOCK_BIT_SIZE,
            &mut values_written,
            output,
        )?;
    }
    if !bit_queue.is_empty() {
        let bit_count = bit_queue.len();
        write_value(&mut bit_queue, bit_count, &mut values_written, output)?;
    }
    write!(output, "\n        ],\n")?;
    writeln!(output, "        {}", bit_queue_len)?;
    writeln!(output, "    )")?;
    writeln!(output, "}}")?;
    writeln!(output, "\npub fn {}_block_count() -> usize {{", name)?;
    writeln!(output, "        {}", block_count)?;
    writeln!(output, "}}")?;
    Ok(())
}

fn write_value(
    bit_queue: &mut BitQueue,
    bit_count: usize,
    values_written: &mut usize,
    output: &mut dyn io::Write,
) -> Result<(), io::Error> {
    if (*values_written & 0b11) == 0 {
        write!(output, "\n            ")?;
    } else {
        write!(output, " ")?;
    }
    let value = bit_queue
        .take_bits(bit_count)
        .expect("There should be bits left!");
    write!(output, "0x{:016X},", value)?;
    *values_written += 1;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};
    use test_utilities::byte_array_reader_writer::{ByteArrayReader, ByteArrayWriter};

    static PROPER_TEST_DATA: &str = "0.0.0.0,0.255.255.255,ZZ
1.0.0.0,1.0.0.255,AU
1.0.1.0,1.0.3.255,CN
1.0.4.0,1.0.7.255,AU
1.0.8.0,1.0.15.255,CN
1.0.16.0,1.0.31.255,JP
1.0.32.0,1.0.63.255,CN
1.0.64.0,1.0.127.255,JP
1.0.128.0,1.0.255.255,TH
1.1.0.0,1.1.0.255,CN
0:0:0:0:0:0:0:0,0:255:255:255:0:0:0:0,ZZ
1:0:0:0:0:0:0:0,1:0:0:255:0:0:0:0,AU
1:0:1:0:0:0:0:0,1:0:3:255:0:0:0:0,CN
1:0:4:0:0:0:0:0,1:0:7:255:0:0:0:0,AU
1:0:8:0:0:0:0:0,1:0:15:255:0:0:0:0,CN
1:0:16:0:0:0:0:0,1:0:31:255:0:0:0:0,JP
1:0:32:0:0:0:0:0,1:0:63:255:0:0:0:0,CN
1:0:64:0:0:0:0:0,1:0:127:255:0:0:0:0,JP
1:0:128:0:0:0:0:0,1:0:255:255:0:0:0:0,TH
1:1:0:0:0:0:0:0,1:1:0:255:0:0:0:0,CN
";

    static BAD_TEST_DATA: &str = "0.0.0.0,0.255.255.255,ZZ
1.0.0.0,1.0.0.255,AU
1.0.1.0,1.0.3.255,CN
1.0.7.255,AU
1.0.8.0,1.0.15.255
1.0.16.0,1.0.31.255,JP,
BOOGA,BOOGA,BOOGA
1.0.63.255,1.0.32.0,CN
1.0.64.0,1.0.64.0,JP
1.0.128.0,1.0.255.255,TH
1.1.0.0,1.1.0.255,CN
0:0:0:0:0:0:0:0,0:255:255:255:0:0:0:0,ZZ
1:0:0:0:0:0:0:0,1:0:0:255:0:0:0:0,AU
1:0:1:0:0:0:0:0,1:0:3:255:0:0:0:0,CN
1:0:4:0:0:0:0:0,1:0:7:255:0:0:0:0,AU
1:0:8:0:0:0:0:0,1:0:15:255:0:0:0:0,CN
1:0:16:0:0:0:0:0,1:0:31:255:0:0:0:0,JP
BOOGA,BOOGA,BOOGA
1:0:32:0:0:0:0:0,1:0:63:255:0:0:0:0,CN
1:0:64:0:0:0:0:0,1:0:127:255:0:0:0:0,JP
1:0:128:0:0:0:0:0,1:0:255:255:0:0:0:0,TH
1:1:0:0:0:0:0:0,1:1:0:255:0:0:0:0,CN
";

    #[test]
    fn happy_path_test() {
        let mut stdin = ByteArrayReader::new(PROPER_TEST_DATA.as_bytes());
        let mut stdout = ByteArrayWriter::new();
        let mut stderr = ByteArrayWriter::new();

        let result = ip_country(vec![], &mut stdin, &mut stdout, &mut stderr);

        assert_eq!(result, 0);
        let stdout_string = String::from_utf8(stdout.get_bytes()).unwrap();
        let stderr_string = String::from_utf8(stderr.get_bytes()).unwrap();
        assert_eq!(
            stdout_string,
            r#"
// GENERATED CODE: REGENERATE, DO NOT MODIFY!

pub fn ipv4_country_data() -> (Vec<u64>, usize) {
    (
        vec![
            0x0080000300801003, 0x82201C0902E01807, 0x28102E208388840B, 0x605C0100AB76020E,
            0x0000000000000000,
        ],
        271
    )
}

pub fn ipv4_country_block_count() -> usize {
        11
}

pub fn ipv6_country_data() -> (Vec<u64>, usize) {
    (
        vec![
            0x3000040000400007, 0x00C0001400020000, 0xA80954B000000700, 0x4000000F0255604A,
            0x0300004000040004, 0xE04AAC8380003800, 0x00018000A4000001, 0x2AB0003485C0001C,
            0x0600089000000781, 0xC001D20700007000, 0x00424000001E04AA, 0x15485C0001C00018,
            0xC90000007812AB00, 0x2388000700006002, 0x000001E04AAC00C5, 0xC0001C0001801924,
            0x0007812AB0063485, 0x0070000600C89000, 0x1E04AAC049D23880, 0xC000180942400000,
            0x12AB025549BA0001, 0x0040002580000078, 0xAC8B800038000300, 0x000000000001E04A,
        ],
        1513
    )
}

pub fn ipv6_country_block_count() -> usize {
        20
}
"#
            .to_string()
        );
        assert_eq!(stderr_string, "".to_string());
    }

    #[test]
    fn sad_path_test() {
        let mut stdin = ByteArrayReader::new(BAD_TEST_DATA.as_bytes());
        let mut stdout = ByteArrayWriter::new();
        let mut stderr = ByteArrayWriter::new();

        let result = ip_country(vec![], &mut stdin, &mut stdout, &mut stderr);

        assert_eq!(result, 1);
        let stdout_string = String::from_utf8(stdout.get_bytes()).unwrap();
        let stderr_string = String::from_utf8(stderr.get_bytes()).unwrap();
        assert_eq!(
            stdout_string,
            r#"
// GENERATED CODE: REGENERATE, DO NOT MODIFY!

pub fn ipv4_country_data() -> (Vec<u64>, usize) {
    (
        vec![
            0x0080000300801003, 0x5020000902E01807, 0xAB74038090000E1C, 0x00000000605C0100,
        ],
        239
    )
}

pub fn ipv4_country_block_count() -> usize {
        9
}

pub fn ipv6_country_data() -> (Vec<u64>, usize) {
    (
        vec![
            0x3000040000400007, 0x00C0001400020000, 0xA80954B000000700, 0x4000000F0255604A,
            0x0300004000040004, 0xE04AAC8380003800, 0x00018000A4000001, 0x2AB0003485C0001C,
            0x0600089000000781, 0xC001D20700007000, 0x00424000001E04AA, 0x15485C0001C00018,
            0xC90000007812AB00, 0x2388000700006002, 0x000001E04AAC00C5, 0xC0001C0001801924,
            0x0007812AB0063485, 0x0070000600C89000, 0x1E04AAC049D23880, 0xC000180942400000,
            0x12AB025549BA0001, 0x0040002580000078, 0xAC8B800038000300, 0x000000000001E04A,
        ],
        1513
    )
}

pub fn ipv6_country_block_count() -> usize {
        20
}

            *** DO NOT USE THIS CODE ***
            It will produce incorrect results.
            The process that generated it found these errors:

Line 3: CSV format error: Error(UnequalLengths { pos: Some(Position { byte: 67, line: 4, record: 3 }), expected_len: 3, len: 2 })
Line 4: CSV format error: Error(UnequalLengths { pos: Some(Position { byte: 80, line: 5, record: 4 }), expected_len: 3, len: 2 })
Line 5: CSV format error: Error(UnequalLengths { pos: Some(Position { byte: 99, line: 6, record: 5 }), expected_len: 3, len: 4 })
Line 6: Invalid (AddrParseError(Ip)) IP address in CSV record: 'BOOGA'
Line 7: Ending address 1.0.32.0 is less than starting address 1.0.63.255
Line 17: Invalid (AddrParseError(Ip)) IP address in CSV record: 'BOOGA'

            Fix the errors and regenerate the code.
            *** DO NOT USE THIS CODE ***
"#
        );
        assert_eq!(stderr_string,
r#"Line 3: CSV format error: Error(UnequalLengths { pos: Some(Position { byte: 67, line: 4, record: 3 }), expected_len: 3, len: 2 })
Line 4: CSV format error: Error(UnequalLengths { pos: Some(Position { byte: 80, line: 5, record: 4 }), expected_len: 3, len: 2 })
Line 5: CSV format error: Error(UnequalLengths { pos: Some(Position { byte: 99, line: 6, record: 5 }), expected_len: 3, len: 4 })
Line 6: Invalid (AddrParseError(Ip)) IP address in CSV record: 'BOOGA'
Line 7: Ending address 1.0.32.0 is less than starting address 1.0.63.255
Line 17: Invalid (AddrParseError(Ip)) IP address in CSV record: 'BOOGA'"#
.to_string()
        );
    }

    #[test]
    fn write_error_from_ip_country() {
        let stdin = &mut ByteArrayReader::new(PROPER_TEST_DATA.as_bytes());
        let stdout = &mut ByteArrayWriter::new();
        let stderr = &mut ByteArrayWriter::new();
        stdout.reject_next_write(Error::new(ErrorKind::WriteZero, "Bad file Descriptor"));

        let result = ip_country(vec![], stdin, stdout, stderr);

        assert_eq!(result, 1);
        let stdout_string = String::from_utf8(stdout.get_bytes()).unwrap();
        let stderr_string = String::from_utf8(stderr.get_bytes()).unwrap();
        assert_eq!(stderr_string, "Error generating Rust code: Custom { kind: WriteZero, error: \"Bad file Descriptor\" }");
        assert_eq!(stdout_string, "\n            *** DO NOT USE THIS CODE ***\n            It will produce incorrect results.\n            The process that generated it found these errors:\n\nError generating Rust code: Custom { kind: WriteZero, error: \"Bad file Descriptor\" }\n\n            Fix the errors and regenerate the code.\n            *** DO NOT USE THIS CODE ***\n");
    }
}
