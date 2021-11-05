// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::sub_lib::framer::FramedChunk;
use crate::sub_lib::framer::Framer;

#[derive(Clone, Default)]
pub struct DataHunkFramer {
    data_so_far: Vec<u8>,
}

impl Framer for DataHunkFramer {
    fn add_data(&mut self, data: &[u8]) {
        self.data_so_far.extend(data);
    }

    fn take_frame(&mut self) -> Option<FramedChunk> {
        match self.length_of_oldest_frame() {
            None => None,
            Some(frame_len) => {
                if self.oldest_frame_is_complete() {
                    let mut frame_data = self.data_so_far.clone();
                    self.data_so_far = frame_data.split_off(frame_len);
                    Some(FramedChunk {
                        chunk: frame_data,
                        last_chunk: false,
                    })
                } else {
                    None
                }
            }
        }
    }
}

impl DataHunkFramer {
    pub fn new() -> Self {
        Self::default()
    }

    fn length_of_oldest_frame(&self) -> Option<usize> {
        if self.data_so_far.len() < 16 {
            return None;
        }
        let b1 = (u32::from(self.data_so_far[12])) << 24;
        let b2 = (u32::from(self.data_so_far[13])) << 16;
        let b3 = (u32::from(self.data_so_far[14])) << 8;
        let b4 = u32::from(self.data_so_far[15]);
        let body_len = b1 + b2 + b3 + b4;
        let total_len = 16 + body_len;
        Some(total_len as usize)
    }

    fn oldest_frame_is_complete(&self) -> bool {
        match self.length_of_oldest_frame() {
            None => false,
            Some(frame_len) => self.data_so_far.len() >= frame_len,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::data_hunk::DataHunk;
    use std::net::SocketAddr;
    use std::str::FromStr;

    #[test]
    fn data_hunk_framer_frames_single_data_hunk() {
        let data_hunk = DataHunk::new(
            SocketAddr::from_str("1.2.3.4:1025").unwrap(),
            SocketAddr::from_str("2.3.4.5:2050").unwrap(),
            vec![3, 4, 5, 6],
        );
        let serialized_data_hunk: Vec<u8> = data_hunk.clone().into();
        let mut subject = DataHunkFramer::new();

        let first_frame = subject.take_frame();
        subject.add_data(&serialized_data_hunk[..]);
        let second_frame = subject.take_frame().unwrap();
        let third_frame = subject.take_frame();

        assert_eq!(first_frame, None);
        let deserialized_data_hunk = DataHunk::from(second_frame.chunk);
        assert_eq!(deserialized_data_hunk, data_hunk);
        assert_eq!(second_frame.last_chunk, false);
        assert_eq!(third_frame, None);
    }

    #[test]
    fn data_hunk_framer_handles_single_hunk_split_in_header() {
        let data_hunk = DataHunk::new(
            SocketAddr::from_str("1.2.3.4:1025").unwrap(),
            SocketAddr::from_str("2.3.4.5:2050").unwrap(),
            vec![3, 4, 5, 6],
        );
        let serialized_data_hunk: Vec<u8> = data_hunk.clone().into();
        let mut subject = DataHunkFramer::new();

        subject.add_data(&serialized_data_hunk[..15]);
        let first_frame = subject.take_frame();
        subject.add_data(&serialized_data_hunk[15..]);
        let second_frame = subject.take_frame().unwrap();
        let third_frame = subject.take_frame();

        assert_eq!(first_frame, None);
        let deserialized_data_hunk = DataHunk::from(second_frame.chunk);
        assert_eq!(deserialized_data_hunk, data_hunk);
        assert_eq!(second_frame.last_chunk, false);
        assert_eq!(third_frame, None);
    }

    #[test]
    fn data_hunk_framer_handles_single_hunk_split_in_body() {
        let data_hunk = DataHunk::new(
            SocketAddr::from_str("1.2.3.4:1025").unwrap(),
            SocketAddr::from_str("2.3.4.5:2050").unwrap(),
            vec![3, 4, 5, 6],
        );
        let serialized_data_hunk: Vec<u8> = data_hunk.clone().into();
        let mut subject = DataHunkFramer::new();

        subject.add_data(&serialized_data_hunk[..19]);
        let first_frame = subject.take_frame();
        subject.add_data(&serialized_data_hunk[19..]);
        let second_frame = subject.take_frame().unwrap();
        let third_frame = subject.take_frame();

        assert_eq!(first_frame, None);
        let deserialized_data_hunk = DataHunk::from(second_frame.chunk);
        assert_eq!(deserialized_data_hunk, data_hunk);
        assert_eq!(second_frame.last_chunk, false);
        assert_eq!(third_frame, None);
    }

    #[test]
    fn data_hunk_framer_handles_hunk_and_a_half_followed_by_a_half() {
        let first_hunk = DataHunk::new(
            SocketAddr::from_str("1.2.3.4:1025").unwrap(),
            SocketAddr::from_str("2.3.4.5:2050").unwrap(),
            vec![3, 4, 5, 6],
        );
        let second_hunk = DataHunk::new(
            SocketAddr::from_str("4.5.6.7:1025").unwrap(),
            SocketAddr::from_str("5.6.7.8:2050").unwrap(),
            vec![6, 7, 8, 9],
        );
        let serialized_first_hunk: Vec<u8> = first_hunk.clone().into();
        let serialized_second_hunk: Vec<u8> = second_hunk.clone().into();
        let mut subject = DataHunkFramer::new();

        subject.add_data(&serialized_first_hunk[..]);
        subject.add_data(&serialized_second_hunk[..10]);
        let first_frame = subject.take_frame().unwrap();
        subject.add_data(&serialized_second_hunk[10..]);
        let second_frame = subject.take_frame().unwrap();
        let third_frame = subject.take_frame();

        let deserialized_first_hunk = DataHunk::from(first_frame.chunk);
        assert_eq!(deserialized_first_hunk, first_hunk);
        assert_eq!(first_frame.last_chunk, false);
        let deserialized_second_hunk = DataHunk::from(second_frame.chunk);
        assert_eq!(deserialized_second_hunk, second_hunk);
        assert_eq!(second_frame.last_chunk, false);
        assert_eq!(third_frame, None);
    }
}
