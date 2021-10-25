// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;

#[derive(Debug, PartialEq, Clone)]
pub struct DataHunk {
    pub from: SocketAddr,
    pub to: SocketAddr,
    pub data: Vec<u8>,
}

impl From<Vec<u8>> for DataHunk {
    fn from(binary: Vec<u8>) -> Self {
        from(&binary[..], "Vec<u8>")
    }
}

impl<'a> From<&'a [u8]> for DataHunk {
    fn from(binary: &[u8]) -> Self {
        from(binary, "&[u8]")
    }
}

fn from(binary: &[u8], type_name: &str) -> DataHunk {
    if binary.len() < 16 {
        panic!(
            "A {} must be at least 16 bytes long to parse into a DataHunk, not {}",
            type_name,
            binary.len()
        )
    }
    let from = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(binary[0], binary[1], binary[2], binary[3])),
        (u16::from(binary[4]) << 8) + u16::from(binary[5]),
    );
    let to = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(binary[6], binary[7], binary[8], binary[9])),
        (u16::from(binary[10]) << 8) + u16::from(binary[11]),
    );
    let length = (u32::from(binary[12]) << 24)
        + (u32::from(binary[13]) << 16)
        + (u32::from(binary[14]) << 8)
        + u32::from(binary[15]);
    if binary.len() != (16 + (length as usize)) {
        panic!("Binary data suggested that a DataHunk payload should be {} bytes long, but {} bytes were provided",
                length, binary.len () - 16)
    }
    let data = Vec::from(&binary[16..]);
    DataHunk::new(from, to, data)
}

impl From<DataHunk> for Vec<u8> {
    fn from(data_hunk: DataHunk) -> Self {
        let from_ip = match data_hunk.from.ip() {
            IpAddr::V4(x) => x,
            IpAddr::V6(_) => unimplemented!(),
        };
        let to_ip = match data_hunk.to.ip() {
            IpAddr::V4(x) => x,
            IpAddr::V6(_) => unimplemented!(),
        };
        let mut binary = vec![];
        binary.extend(from_ip.octets().iter());
        binary.push((data_hunk.from.port() >> 8) as u8);
        binary.push((data_hunk.from.port() & 0x00FF) as u8);
        binary.extend(to_ip.octets().iter());
        binary.push((data_hunk.to.port() >> 8) as u8);
        binary.push((data_hunk.to.port() & 0x00FF) as u8);
        binary.push((data_hunk.data.len() >> 24 & 0x0000_00FF) as u8);
        binary.push((data_hunk.data.len() >> 16 & 0x0000_00FF) as u8);
        binary.push((data_hunk.data.len() >> 8 & 0x0000_00FF) as u8);
        binary.push((data_hunk.data.len() & 0x0000_00FF) as u8);
        binary.extend(data_hunk.data);
        binary
    }
}

impl DataHunk {
    pub fn new(from: SocketAddr, to: SocketAddr, data: Vec<u8>) -> DataHunk {
        DataHunk { from, to, data }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    #[should_panic(
        expected = "A Vec<u8> must be at least 16 bytes long to parse into a DataHunk, not 15"
    )]
    fn short_vecs_dont_become_data_hunks() {
        let input = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let _data_hunk: DataHunk = input.into();
    }

    #[test]
    #[should_panic(
        expected = "Binary data suggested that a DataHunk payload should be 0 bytes long, but 1 bytes were provided"
    )]
    fn vecs_with_bad_length_fields_dont_become_data_hunks() {
        let input = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        let _data_hunk: DataHunk = input.into();
    }

    #[test]
    fn vecs_become_data_hunks() {
        let input = vec![1, 2, 3, 4, 5, 6, 2, 3, 4, 5, 6, 7, 0, 0, 0, 4, 4, 3, 2, 1];

        let result: DataHunk = input.into();

        assert_eq!(
            result,
            DataHunk::new(
                SocketAddr::from_str("1.2.3.4:1286").unwrap(),
                SocketAddr::from_str("2.3.4.5:1543").unwrap(),
                vec!(4, 3, 2, 1)
            )
        )
    }

    #[test]
    fn data_hunks_become_vecs() {
        let input = DataHunk::new(
            SocketAddr::from_str("1.2.3.4:1286").unwrap(),
            SocketAddr::from_str("2.3.4.5:1543").unwrap(),
            vec![4, 3, 2, 1],
        );

        let result: Vec<u8> = input.into();

        assert_eq!(
            result,
            vec!(1, 2, 3, 4, 5, 6, 2, 3, 4, 5, 6, 7, 0, 0, 0, 4, 4, 3, 2, 1)
        );
    }
}
