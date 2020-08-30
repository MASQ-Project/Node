// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::cmp::max;
use std::ops::Add;
use std::str::from_utf8;

macro_rules! try_opt {
    ($e:expr) => {
        match $e {
            Some(x) => x,
            None => return None,
        }
    };
}

macro_rules! try_flg {
    ($e:expr) => {
        match $e {
            Some(x) => x,
            None => return false,
        }
    };
}

#[derive(Debug)]
pub struct Query {
    name: String,
    qtype: u16,
    qclass: u16,
    length: usize,
}

impl Query {
    fn new(buf: &[u8], offset: usize, length: usize) -> Option<Query> {
        let (name, name_end) = try_opt!(PacketFacade::extract_string_seq(buf, offset, length));
        let qtype = try_opt!(PacketFacade::u16_from(buf, name_end, length));
        let qclass = try_opt!(PacketFacade::u16_from(buf, name_end + 2, length));
        Some(Query {
            name,
            qtype,
            qclass,
            length: name_end + 4 - offset,
        })
    }

    #[cfg(test)]
    pub fn new_for_test(name: String, qtype: u16, qclass: u16, length: usize) -> Query {
        Query {
            name,
            qtype,
            qclass,
            length,
        }
    }

    fn find_end(buf: &[u8], offset: usize, length: usize) -> Option<usize> {
        let query_end = try_opt!(PacketFacade::find_string_seq_end(buf, offset, length)) + 4;
        if query_end > length {
            None
        } else {
            Some(query_end)
        }
    }

    pub fn get_query_name(&self) -> &str {
        &self.name
    }

    pub fn get_query_type(&self) -> u16 {
        self.qtype
    }

    pub fn get_query_class(&self) -> u16 {
        self.qclass
    }

    fn get_length(&self) -> usize {
        self.length
    }
}

#[derive(Debug)]
pub struct ResourceRecord {
    name: String,
    rtype: u16,
    rclass: u16,
    time_to_live: u32,
    rdata: Vec<u8>,
    length: usize,
}

impl ResourceRecord {
    fn new(buf: &[u8], offset: usize, buflen: usize) -> Option<ResourceRecord> {
        let (name, name_end) = try_opt!(PacketFacade::extract_string_seq(buf, offset, buflen));
        let rtype = try_opt!(PacketFacade::u16_from(buf, name_end, buflen));
        let rclass = try_opt!(PacketFacade::u16_from(buf, name_end + 2, buflen));
        let time_to_live = try_opt!(PacketFacade::u32_from(buf, name_end + 4, buflen));
        let rdata_length = try_opt!(PacketFacade::u16_from(buf, name_end + 8, buflen)) as usize;
        let rdata_begin = name_end + 10;
        let rdata_end = rdata_begin + rdata_length;
        let length = rdata_end - offset;
        if offset + length > buflen {
            return None;
        }
        let rdata = Vec::from(&buf[(rdata_begin)..(rdata_end)]);
        Some(ResourceRecord {
            name,
            rtype,
            rclass,
            time_to_live,
            rdata,
            length,
        })
    }

    pub fn new_for_test(
        name: String,
        rtype: u16,
        rclass: u16,
        time_to_live: u32,
        rdata: Vec<u8>,
        length: usize,
    ) -> ResourceRecord {
        ResourceRecord {
            name,
            rtype,
            rclass,
            time_to_live,
            rdata,
            length,
        }
    }

    fn find_end(buf: &[u8], offset: usize, length: usize) -> Option<usize> {
        let name_end = try_opt!(PacketFacade::find_string_seq_end(buf, offset, length));
        let rdata_length = try_opt!(PacketFacade::u16_from(buf, name_end + 8, length)) as usize;
        let record_end = name_end + 10 + rdata_length;
        if record_end > length {
            None
        } else {
            Some(record_end)
        }
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn get_resource_type(&self) -> u16 {
        self.rtype
    }

    pub fn get_resource_class(&self) -> u16 {
        self.rclass
    }

    pub fn get_time_to_live(&self) -> u32 {
        self.time_to_live
    }

    pub fn get_rdata(&self) -> &[u8] {
        &self.rdata
    }

    fn get_length(&self) -> usize {
        self.length
    }
}

#[derive(Debug)]
pub struct PacketFacade<'a> {
    buf: &'a mut [u8],
    length: usize,
}

impl<'a> PacketFacade<'a> {
    pub fn new(buf: &mut [u8], length: usize) -> PacketFacade<'_> {
        PacketFacade { buf, length }
    }

    pub fn get_transaction_id(&self) -> Option<u16> {
        PacketFacade::u16_from(self.buf, 0, self.length)
    }

    pub fn set_transaction_id(&mut self, v: u16) -> bool {
        PacketFacade::u16_to(v, self.buf, 0)
    }

    pub fn is_query(&self) -> Option<bool> {
        self.req_len_opt(3, || (self.buf[2] & 0x80) == 0)
    }

    pub fn set_query(&mut self, v: bool) -> bool {
        if self.buf.len() < 3 {
            return false;
        }
        self.buf[2] = (self.buf[2] & 0x7F) | if v { 0x00 } else { 0x80 };
        true
    }

    pub fn get_opcode(&self) -> Option<u8> {
        self.req_len_opt(3, || (self.buf[2] & 0x78) >> 3)
    }

    pub fn set_opcode(&mut self, v: u8) -> bool {
        if self.buf.len() < 3 {
            return false;
        }
        self.buf[2] = (self.buf[2] & 0x87) | (v << 3);
        true
    }

    pub fn is_authoritative_answer(&self) -> Option<bool> {
        self.req_len_opt(3, || (self.buf[2] & 0x04) > 0)
    }

    pub fn set_authoritative_answer(&mut self, v: bool) -> bool {
        if self.buf.len() < 3 {
            return false;
        }
        self.buf[2] = (self.buf[2] & 0xFB) | if v { 0x04 } else { 0x00 };
        true
    }

    pub fn is_truncated(&self) -> Option<bool> {
        self.req_len_opt(3, || (self.buf[2] & 0x02) > 0)
    }

    pub fn set_truncated(&mut self, v: bool) -> bool {
        if self.buf.len() < 3 {
            return false;
        }
        self.buf[2] = (self.buf[2] & 0xFD) | if v { 0x02 } else { 0x00 };
        true
    }

    pub fn is_recursion_desired(&self) -> Option<bool> {
        self.req_len_opt(3, || (self.buf[2] & 0x01) > 0)
    }

    pub fn set_recursion_desired(&mut self, v: bool) -> bool {
        if self.buf.len() < 3 {
            return false;
        }
        self.buf[2] = (self.buf[2] & 0xFE) | if v { 0x01 } else { 0x00 };
        true
    }

    pub fn is_recursion_available(&self) -> Option<bool> {
        self.req_len_opt(4, || (self.buf[3] & 0x80) > 0)
    }

    pub fn set_recursion_available(&mut self, v: bool) -> bool {
        if self.buf.len() < 4 {
            return false;
        }
        self.buf[3] = (self.buf[3] & 0x7F) | if v { 0x80 } else { 0x00 };
        true
    }

    pub fn get_z(&self) -> Option<bool> {
        self.req_len_opt(4, || (self.buf[3] & 0x40) > 0)
    }

    pub fn set_z(&mut self, v: bool) -> bool {
        if self.buf.len() < 4 {
            return false;
        }
        self.buf[3] = (self.buf[3] & 0xBF) | if v { 0x40 } else { 0x00 };
        true
    }

    pub fn is_authenticated_data(&self) -> Option<bool> {
        self.req_len_opt(4, || (self.buf[3] & 0x20) > 0)
    }

    pub fn set_authenticated_data(&mut self, v: bool) -> bool {
        if self.buf.len() < 4 {
            return false;
        }
        self.buf[3] = (self.buf[3] & 0xDF) | if v { 0x20 } else { 0x00 };
        true
    }

    pub fn is_checking_disabled(&self) -> Option<bool> {
        self.req_len_opt(4, || (self.buf[3] & 0x10) > 0)
    }

    pub fn set_checking_disabled(&mut self, v: bool) -> bool {
        if self.buf.len() < 4 {
            return false;
        }
        self.buf[3] = (self.buf[3] & 0xEF) | if v { 0x10 } else { 0x00 };
        true
    }

    pub fn get_rcode(&self) -> Option<u8> {
        self.req_len_opt(4, || (self.buf[3] & 0x0F))
    }

    pub fn set_rcode(&mut self, v: u8) -> bool {
        if self.buf.len() < 4 {
            return false;
        }
        self.buf[3] = (self.buf[3] & 0xF0) | (v & 0x0F);
        true
    }

    pub fn get_queries(&self) -> Option<Vec<Query>> {
        let count = try_opt!(PacketFacade::u16_from(self.buf, 4, self.length));
        let mut offset = 12;
        let mut result: Vec<Query> = vec![];
        for _i in 0..count {
            let query = try_opt!(Query::new(self.buf, offset, self.length));
            offset += query.get_length();
            result.push(query);
        }
        Some(result)
    }

    fn find_queries_end(&self) -> Option<usize> {
        let count = try_opt!(PacketFacade::u16_from(self.buf, 4, self.length));
        let mut offset = 12;
        for _i in 0..count {
            offset = try_opt!(Query::find_end(self.buf, offset, self.length));
        }
        Some(offset)
    }

    pub fn add_query(&mut self, name: &str, query_type: u16, query_class: u16) -> bool {
        let mut offset = try_flg!(self.find_queries_end());
        offset = try_flg!(PacketFacade::add_string_seq(self.buf, offset, name));
        if !PacketFacade::u16_to(query_type, self.buf, offset) {
            return false;
        };
        if !PacketFacade::u16_to(query_class, self.buf, offset + 2) {
            return false;
        };
        self.establish_high_water(offset + 4);
        let count = try_flg!(PacketFacade::u16_from(self.buf, 4, self.length)) + 1;
        PacketFacade::u16_to(count, self.buf, 4);
        true
    }

    pub fn get_answers(&self) -> Option<Vec<ResourceRecord>> {
        let mut offset = try_opt!(self.find_queries_end());
        let mut result: Vec<ResourceRecord> = vec![];
        let count = try_opt!(PacketFacade::u16_from(self.buf, 6, self.length));
        for _i in 0..count {
            let record: ResourceRecord =
                try_opt!(ResourceRecord::new(self.buf, offset, self.length));
            offset += record.get_length();
            result.push(record);
        }
        Some(result)
    }

    fn find_answers_end(&self) -> Option<usize> {
        let count = try_opt!(PacketFacade::u16_from(self.buf, 6, self.length));
        let mut offset = try_opt!(self.find_queries_end());

        for _i in 0..count {
            offset = try_opt!(ResourceRecord::find_end(self.buf, offset, self.length));
        }
        Some(offset)
    }

    pub fn add_answer(
        &mut self,
        name: &str,
        resource_type: u16,
        resource_class: u16,
        time_to_live: u32,
        rdata: &[u8],
    ) -> bool {
        let begin = try_flg!(self.find_answers_end());
        try_flg!(self.write_resource_record(
            begin,
            name,
            resource_type,
            resource_class,
            time_to_live,
            rdata
        ));
        let count = try_flg!(PacketFacade::u16_from(self.buf, 6, self.length)) + 1;
        PacketFacade::u16_to(count, self.buf, 6);
        true
    }

    pub fn get_authorities(&self) -> Option<Vec<ResourceRecord>> {
        let mut offset = try_opt!(self.find_answers_end());
        let mut result: Vec<ResourceRecord> = vec![];
        let count = try_opt!(PacketFacade::u16_from(self.buf, 8, self.length));
        for _i in 0..count {
            let record = try_opt!(ResourceRecord::new(self.buf, offset, self.length));
            offset += record.get_length();
            result.push(record);
        }
        Some(result)
    }

    fn find_authorities_end(&self) -> Option<usize> {
        let count = try_opt!(PacketFacade::u16_from(self.buf, 8, self.length));
        let mut offset = try_opt!(self.find_answers_end());
        for _i in 0..count {
            offset = try_opt!(ResourceRecord::find_end(self.buf, offset, self.length));
        }
        Some(offset)
    }

    pub fn add_authority(
        &mut self,
        name: &str,
        resource_type: u16,
        resource_class: u16,
        time_to_live: u32,
        rdata: &[u8],
    ) -> bool {
        let begin = try_flg!(self.find_authorities_end());
        try_flg!(self.write_resource_record(
            begin,
            name,
            resource_type,
            resource_class,
            time_to_live,
            rdata
        ));
        let count = try_flg!(PacketFacade::u16_from(self.buf, 8, self.length)) + 1;
        PacketFacade::u16_to(count, self.buf, 8);
        true
    }

    pub fn get_additionals(&self) -> Option<Vec<ResourceRecord>> {
        let mut offset = try_opt!(self.find_authorities_end());
        let mut result: Vec<ResourceRecord> = vec![];
        let count = try_opt!(PacketFacade::u16_from(self.buf, 10, self.length));
        for _i in 0..count {
            let record = try_opt!(ResourceRecord::new(self.buf, offset, self.length));
            offset += record.get_length();
            result.push(record);
        }
        Some(result)
    }

    fn find_additionals_end(&self) -> Option<usize> {
        let count = try_opt!(PacketFacade::u16_from(self.buf, 10, self.length));
        let mut offset = try_opt!(self.find_authorities_end());
        for _i in 0..count {
            offset = try_opt!(ResourceRecord::find_end(self.buf, offset, self.length));
        }
        Some(offset)
    }

    pub fn add_additional(
        &mut self,
        name: &str,
        resource_type: u16,
        resource_class: u16,
        time_to_live: u32,
        rdata: &[u8],
    ) -> bool {
        let begin = try_flg!(self.find_additionals_end());
        try_flg!(self.write_resource_record(
            begin,
            name,
            resource_type,
            resource_class,
            time_to_live,
            rdata
        ));
        let count = try_flg!(PacketFacade::u16_from(self.buf, 10, self.length)) + 1;
        PacketFacade::u16_to(count, self.buf, 10);
        true
    }

    pub fn get_length(&self) -> usize {
        self.length
    }

    pub fn clear(&mut self) {
        PacketFacade::u16_to(0x0000, &mut self.buf, 4);
        PacketFacade::u16_to(0x0000, &mut self.buf, 6);
        PacketFacade::u16_to(0x0000, &mut self.buf, 8);
        PacketFacade::u16_to(0x0000, &mut self.buf, 10);
        self.length = 12
    }

    fn establish_high_water(&mut self, candidate: usize) {
        self.length = max(self.length, candidate);
    }

    fn req_len_opt<T, F>(&self, length: usize, closure: F) -> Option<T>
    where
        T: Sized,
        F: Fn() -> T,
    {
        if (self.length < length) || (self.buf.len() < length) {
            None
        } else {
            Some(closure())
        }
    }

    fn u16_from(buf: &[u8], start: usize, buflen: usize) -> Option<u16> {
        if buflen < start + 2 {
            return None;
        }
        Some((u16::from(buf[start]) << 8) + u16::from(buf[start + 1]))
    }

    fn u16_to(value: u16, buf: &mut [u8], start: usize) -> bool {
        if start + 2 > buf.len() {
            return false;
        }
        buf[start] = (value >> 8) as u8;
        buf[start + 1] = (value & 0xFF) as u8;
        true
    }

    fn u32_from(buf: &[u8], start: usize, buflen: usize) -> Option<u32> {
        let high_word = u32::from(PacketFacade::u16_from(buf, start, buflen)?);
        let low_word = u32::from(PacketFacade::u16_from(buf, start + 2, buflen)?);
        Some((high_word << 16) | low_word)
    }

    fn u32_to(value: u32, buf: &mut [u8], start: usize) -> bool {
        PacketFacade::u16_to((value >> 16) as u16, buf, start);
        PacketFacade::u16_to((value & 0xFFFF) as u16, buf, start + 2);
        true
    }

    fn write_resource_record(
        &mut self,
        start: usize,
        name: &str,
        resource_type: u16,
        resource_class: u16,
        time_to_live: u32,
        rdata: &[u8],
    ) -> Option<usize> {
        let string_end = try_opt!(PacketFacade::add_string_seq(self.buf, start, name));
        if !PacketFacade::u16_to(resource_type, self.buf, string_end) {
            return None;
        }
        if !PacketFacade::u16_to(resource_class, self.buf, string_end + 2) {
            return None;
        }
        if !PacketFacade::u32_to(time_to_live, self.buf, string_end + 4) {
            return None;
        }
        if !PacketFacade::u16_to(rdata.len() as u16, self.buf, string_end + 8) {
            return None;
        }
        let rdata_begin = string_end + 10;
        let rdata_end = rdata_begin + rdata.len();
        if rdata_end > self.buf.len() {
            return None;
        };
        self.buf[rdata_begin..(rdata.len() + rdata_begin)].clone_from_slice(&rdata[..]);
        self.establish_high_water(rdata_end);
        Some(rdata_end - start)
    }

    fn find_string_seq_end(buf: &[u8], offset: usize, buflen: usize) -> Option<usize> {
        let mut local_offset = offset;
        loop {
            if local_offset > buflen {
                return None;
            }
            let length = buf[local_offset] as usize;
            if length == 0x00 {
                return Some(local_offset + 1);
            }
            local_offset += length + 1;
        }
    }

    fn extract_string_seq(buf: &[u8], offset: usize, buflen: usize) -> Option<(String, usize)> {
        let mut local_offset = offset;
        let mut result = String::from("");
        loop {
            if local_offset >= buflen {
                return None;
            }
            let length = buf[local_offset] as usize;
            if length == 0x00 {
                return Some((result, local_offset + 1));
            }
            if !result.is_empty() {
                result = result.add(".");
            }
            let end = local_offset + 1 + length;
            if end > buflen {
                return None;
            }
            result = result.add(match from_utf8(&buf[(local_offset + 1)..end]) {
                Ok(s) => s,
                Err(_) => return None,
            });
            local_offset = end;
        }
    }

    fn add_string_seq(buf: &mut [u8], offset: usize, string: &str) -> Option<usize> {
        let mut local_offset = offset;
        if !string.is_empty() {
            for part in string.split('.') {
                let bytes = part.as_bytes();
                if (local_offset + bytes.len() + 1) > buf.len() {
                    return None;
                }
                buf[local_offset] = bytes.len() as u8;
                for i in 0..bytes.len() {
                    buf[local_offset + 1 + i] = bytes[i] as u8
                }
                local_offset += 1 + bytes.len()
            }
        }
        if local_offset >= buf.len() {
            return None;
        };
        buf[local_offset] = 0x00;
        Some(local_offset + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_complains_when_name_length_busts_length_limit() {
        let mut buf: [u8; 100] = [0; 100];
        let length = {
            let mut adder = ByteHandle::new(&mut buf, 4);
            adder.add_bytes(&[0x00, 0x01]); // one query
            adder.skip_bytes(6);
            adder.get_offset()
        };

        let new_result = Query::new(&buf, 12, length);
        let find_result = Query::find_end(&buf, 12, length);

        assert_eq!(new_result.is_none(), true);
        assert_eq!(find_result.is_none(), true);
    }

    #[test]
    fn query_complains_when_name_busts_length_limit() {
        let mut buf: [u8; 100] = [0; 100];
        let length = {
            let mut adder = ByteHandle::new(&mut buf, 4);
            adder.add_bytes(&[0x00, 0x01]); // one query
            adder.skip_bytes(6);
            adder.add_bytes(&[0x01]); // length of first name part
            adder.get_offset()
        };

        let new_result = Query::new(&buf, 12, length);
        let find_result = Query::find_end(&buf, 12, length);

        assert_eq!(new_result.is_none(), true);
        assert_eq!(find_result.is_none(), true);
    }

    #[test]
    fn query_complains_when_qtype_busts_length_limit() {
        let mut buf: [u8; 100] = [0; 100];
        let length = {
            let mut adder = ByteHandle::new(&mut buf, 4);
            adder.add_bytes(&[0x00, 0x01]); // one query
            adder.skip_bytes(6);
            adder.add_bytes(&[0x00]); // no name
            adder.add_bytes(&[0x12]); // first byte of type
            adder.get_offset()
        };

        let new_result = Query::new(&buf, 12, length);
        let find_result = Query::find_end(&buf, 12, length);

        assert_eq!(new_result.is_none(), true);
        assert_eq!(find_result.is_none(), true);
    }

    #[test]
    fn query_complains_when_qclass_busts_length_limit() {
        let mut buf: [u8; 100] = [0; 100];
        let length = {
            let mut adder = ByteHandle::new(&mut buf, 4);
            adder.add_bytes(&[0x00, 0x01]); // one query
            adder.skip_bytes(6);
            adder.add_bytes(&[0x00]); // no name
            adder.add_bytes(&[0x12, 0x34]); // type
            adder.add_bytes(&[0x45]); // first byte of class
            adder.get_offset()
        };

        let new_result = Query::new(&buf, 12, length);
        let find_result = Query::find_end(&buf, 12, length);

        assert_eq!(new_result.is_none(), true);
        assert_eq!(find_result.is_none(), true);
    }

    #[test]
    fn resource_record_complains_when_name_length_busts_length_limit() {
        let mut buf: [u8; 100] = [0; 100];
        let length = {
            let mut adder = ByteHandle::new(&mut buf, 6);
            adder.add_bytes(&[0x00, 0x01]); // one resource record
            adder.skip_bytes(4);
            adder.get_offset()
        };

        let new_result = ResourceRecord::new(&buf, 12, length);
        let find_result = ResourceRecord::find_end(&buf, 12, length);

        assert_eq!(new_result.is_none(), true);
        assert_eq!(find_result.is_none(), true);
    }

    #[test]
    fn resource_record_complains_when_name_busts_length_limit() {
        let mut buf: [u8; 100] = [0; 100];
        let length = {
            let mut adder = ByteHandle::new(&mut buf, 6);
            adder.add_bytes(&[0x00, 0x01]); // one resource record
            adder.skip_bytes(4);
            adder.add_bytes(&[0x01]); // length of first name part
            adder.get_offset()
        };

        let new_result = ResourceRecord::new(&buf, 12, length);
        let find_result = ResourceRecord::find_end(&buf, 12, length);

        assert_eq!(new_result.is_none(), true);
        assert_eq!(find_result.is_none(), true);
    }

    #[test]
    fn resource_record_complains_when_name_is_not_utf8() {
        let mut buf: [u8; 100] = [0; 100];
        let length = {
            let mut adder = ByteHandle::new(&mut buf, 6);
            adder.add_bytes(&[0x00, 0x01]); // one resource record
            adder.skip_bytes(4);
            adder.add_bytes(&[0x02]); // length of first name part
            adder.add_bytes(&[192, 193]); // illegal UTF-8
            adder.get_offset()
        };

        let new_result = ResourceRecord::new(&buf, 12, length);
        let find_result = ResourceRecord::find_end(&buf, 12, length);

        assert_eq!(new_result.is_none(), true);
        assert_eq!(find_result.is_none(), true);
    }

    #[test]
    fn resource_record_complains_when_rtype_busts_length_limit() {
        let mut buf: [u8; 100] = [0; 100];
        let length = {
            let mut adder = ByteHandle::new(&mut buf, 6);
            adder.add_bytes(&[0x00, 0x01]); // one resource record
            adder.skip_bytes(4);
            adder.add_bytes(&[0x00]); // no name
            adder.add_bytes(&[0x12]); // first byte of type
            adder.get_offset()
        };

        let new_result = ResourceRecord::new(&buf, 12, length);
        let find_result = ResourceRecord::find_end(&buf, 12, length);

        assert_eq!(new_result.is_none(), true);
        assert_eq!(find_result.is_none(), true);
    }

    #[test]
    fn resource_record_complains_when_rclass_busts_length_limit() {
        let mut buf: [u8; 100] = [0; 100];
        let length = {
            let mut adder = ByteHandle::new(&mut buf, 6);
            adder.add_bytes(&[0x00, 0x01]); // one resource record
            adder.skip_bytes(4);
            adder.add_bytes(&[0x00]); // no name
            adder.add_bytes(&[0x12, 0x34]); // type
            adder.add_bytes(&[0x45]); // first byte of class
            adder.get_offset()
        };

        let new_result = ResourceRecord::new(&buf, 12, length);
        let find_result = ResourceRecord::find_end(&buf, 12, length);

        assert_eq!(new_result.is_none(), true);
        assert_eq!(find_result.is_none(), true);
    }

    #[test]
    fn resource_record_complains_when_time_to_live_busts_length_limit() {
        let mut buf: [u8; 100] = [0; 100];
        let length = {
            let mut adder = ByteHandle::new(&mut buf, 6);
            adder.add_bytes(&[0x00, 0x01]); // one resource record
            adder.skip_bytes(4);
            adder.add_bytes(&[0x00]); // no name
            adder.add_bytes(&[0x12, 0x34]); // type
            adder.add_bytes(&[0x45, 0x67]); // class
            adder.add_bytes(&[0x89, 0xAB, 0xCD]); // first three bytes of time to live
            adder.get_offset()
        };

        let new_result = ResourceRecord::new(&buf, 12, length);
        let find_result = ResourceRecord::find_end(&buf, 12, length);

        assert_eq!(new_result.is_none(), true);
        assert_eq!(find_result.is_none(), true);
    }

    #[test]
    fn resource_record_complains_when_rdata_length_busts_length_limit() {
        let mut buf: [u8; 100] = [0; 100];
        let length = {
            let mut adder = ByteHandle::new(&mut buf, 6);
            adder.add_bytes(&[0x00, 0x01]); // one resource record
            adder.skip_bytes(4);
            adder.add_bytes(&[0x00]); // no name
            adder.add_bytes(&[0x12, 0x34]); // type
            adder.add_bytes(&[0x45, 0x67]); // class
            adder.add_bytes(&[0x89, 0xAB, 0xCD, 0xEF]); // time to live
            adder.add_bytes(&[0x00]); // first byte of rdata length
            adder.get_offset()
        };

        let new_result = ResourceRecord::new(&buf, 12, length);
        let find_result = ResourceRecord::find_end(&buf, 12, length);

        assert_eq!(new_result.is_none(), true);
        assert_eq!(find_result.is_none(), true);
    }

    #[test]
    fn resource_record_complains_when_rdata_busts_length_limit() {
        let mut buf: [u8; 100] = [0; 100];
        let length = {
            let mut adder = ByteHandle::new(&mut buf, 6);
            adder.add_bytes(&[0x00, 0x01]); // one resource record
            adder.skip_bytes(4);
            adder.add_bytes(&[0x00]); // no name
            adder.add_bytes(&[0x12, 0x34]); // type
            adder.add_bytes(&[0x45, 0x67]); // class
            adder.add_bytes(&[0x89, 0xAB, 0xCD, 0xEF]); // time to live
            adder.add_bytes(&[0x00, 0x01]); // rdata length
            adder.get_offset()
        };

        let new_result = ResourceRecord::new(&buf, 12, length);
        let find_result = ResourceRecord::find_end(&buf, 12, length);

        assert_eq!(new_result.is_none(), true);
        assert_eq!(find_result.is_none(), true);
    }

    #[test]
    fn can_access_transaction_id() {
        let mut buf: [u8; 500] = [0; 500];
        buf[0] = 0x12;
        buf[1] = 0x34;
        let subject = PacketFacade::new(&mut buf, 12);

        let result = subject.get_transaction_id().unwrap();

        assert_eq!(result, 0x1234);
        assert_eq!(subject.get_length(), 12)
    }

    #[test]
    fn can_access_flags_zeros_then_ones() {
        let mut buf: [u8; 500] = [0; 500];
        buf[2] = 0x7A;
        buf[3] = 0xAF;
        let subject = PacketFacade::new(&mut buf, 12);

        assert_eq!(subject.is_query(), Some(true));
        assert_eq!(subject.get_opcode(), Some(0xF));
        assert_eq!(subject.is_authoritative_answer(), Some(false));
        assert_eq!(subject.is_truncated(), Some(true));
        assert_eq!(subject.is_recursion_desired(), Some(false));
        assert_eq!(subject.is_recursion_available(), Some(true));
        assert_eq!(subject.get_z(), Some(false));
        assert_eq!(subject.is_authenticated_data(), Some(true));
        assert_eq!(subject.is_checking_disabled(), Some(false));
        assert_eq!(subject.get_rcode(), Some(0xF));
        assert_eq!(subject.get_length(), 12)
    }

    #[test]
    fn can_access_flags_ones_then_zeros() {
        let mut buf: [u8; 500] = [0; 500];
        buf[2] = 0x85;
        buf[3] = 0x50;
        let subject = PacketFacade::new(&mut buf, 12);

        assert_eq!(subject.is_query(), Some(false));
        assert_eq!(subject.get_opcode(), Some(0x0));
        assert_eq!(subject.is_authoritative_answer(), Some(true));
        assert_eq!(subject.is_truncated(), Some(false));
        assert_eq!(subject.is_recursion_desired(), Some(true));
        assert_eq!(subject.is_recursion_available(), Some(false));
        assert_eq!(subject.get_z(), Some(true));
        assert_eq!(subject.is_authenticated_data(), Some(false));
        assert_eq!(subject.is_checking_disabled(), Some(true));
        assert_eq!(subject.get_rcode(), Some(0x0));
        assert_eq!(subject.get_length(), 12)
    }

    #[test]
    fn can_access_queries() {
        let mut buf: [u8; 500] = [0; 500];
        let length = {
            let mut adder = ByteHandle::new(&mut buf, 4);
            adder.add_bytes(&[0x00, 0x02]); // 2 queries
            adder.skip_bytes(6);

            adder.add_bytes(&[0x03, 0x77, 0x77, 0x77]); // www
            adder.add_bytes(&[0x06, 0x64, 0x6F, 0x6D, 0x61, 0x69, 0x6E]); // domain
            adder.add_bytes(&[0x03, 0x63, 0x6F, 0x6D, 0x00]); // com [end]
            adder.add_bytes(&[0x00, 0x01]); // type A (host address)
            adder.add_bytes(&[0x00, 0x01]); // class IN

            adder.add_bytes(&[0x03, 0x78, 0x79, 0x7A]); // xyz
            adder.add_bytes(&[0x07, 0x66, 0x69, 0x64, 0x64, 0x6C, 0x65, 0x73]); // fiddles
            adder.add_bytes(&[0x03, 0x6F, 0x72, 0x67, 0x00]); // org [end]
            adder.add_bytes(&[0x12, 0x34]); // invalid type
            adder.add_bytes(&[0x23, 0x45]); // invalid class

            adder.get_offset()
        };

        let subject = PacketFacade::new(&mut buf, length);

        let queries = subject.get_queries().unwrap();
        assert_eq!(queries.len(), 2);
        let first_query = &queries[0];
        assert_eq!(first_query.get_query_name(), "www.domain.com");
        assert_eq!(first_query.get_query_type(), 0x0001);
        assert_eq!(first_query.get_query_class(), 0x0001);
        let second_query = &queries[1];
        assert_eq!(second_query.get_query_name(), "xyz.fiddles.org");
        assert_eq!(second_query.get_query_type(), 0x1234);
        assert_eq!(second_query.get_query_class(), 0x2345);

        assert_eq!(subject.get_length(), length);
    }

    #[test]
    fn can_access_answers() {
        let mut buf: [u8; 500] = [0; 500];
        let length = {
            let mut adder = ByteHandle::new(&mut buf, 4);
            adder.add_bytes(&[0x00, 0x01]); // 1 query
            adder.add_bytes(&[0x00, 0x02]); // 2 answers
            adder.skip_bytes(4);

            adder.add_bytes(&[0x00, 0x12, 0x34, 0x43, 0x21]); // null query

            adder.add_bytes(&[0x03, 0x77, 0x77, 0x77]); // www
            adder.add_bytes(&[0x06, 0x64, 0x6F, 0x6D, 0x61, 0x69, 0x6E]); // domain
            adder.add_bytes(&[0x03, 0x63, 0x6F, 0x6D, 0x00]); // com [end]
            adder.add_bytes(&[0x00, 0x01]); // type A (host address)
            adder.add_bytes(&[0x00, 0x01]); // class IN
            adder.add_bytes(&[0x45, 0x67, 0x89, 0xAB]); // time to live
            adder.add_bytes(&[0x00, 0x04]); // rdata length
            adder.add_bytes(&[0xCD, 0xEF, 0x01, 0x23]); // rdata

            adder.add_bytes(&[0x03, 0x78, 0x79, 0x7A]); // xyz
            adder.add_bytes(&[0x07, 0x66, 0x69, 0x64, 0x64, 0x6C, 0x65, 0x73]); // fiddles
            adder.add_bytes(&[0x03, 0x6F, 0x72, 0x67, 0x00]); // org [end]
            adder.add_bytes(&[0x23, 0x45]); // type
            adder.add_bytes(&[0x34, 0x56]); // class
            adder.add_bytes(&[0xFE, 0xDC, 0xBA, 0x98]); // time to live
            adder.add_bytes(&[0x00, 0x04]); // rdata length
            adder.add_bytes(&[0x56, 0x78, 0x9A, 0xBC]); // rdata

            adder.get_offset()
        };

        let subject = PacketFacade::new(&mut buf, length);

        let records = subject.get_answers().unwrap();
        assert_eq!(records.len(), 2);
        let first_record = &records[0];
        assert_eq!(first_record.get_name(), "www.domain.com");
        assert_eq!(first_record.get_resource_type(), 0x0001);
        assert_eq!(first_record.get_resource_class(), 0x0001);
        assert_eq!(first_record.get_time_to_live(), 0x456789AB);
        assert_eq!(first_record.get_rdata(), u8vec(&[0xCD, 0xEF, 0x01, 0x23]));
        let second_record = &records[1];
        assert_eq!(second_record.get_name(), "xyz.fiddles.org");
        assert_eq!(second_record.get_resource_type(), 0x2345);
        assert_eq!(second_record.get_resource_class(), 0x3456);
        assert_eq!(second_record.get_time_to_live(), 0xFEDCBA98);
        assert_eq!(second_record.get_rdata(), u8vec(&[0x56, 0x78, 0x9A, 0xBC]));

        assert_eq!(subject.get_length(), length);
    }

    #[test]
    fn can_access_authorities() {
        let mut buf: [u8; 500] = [0; 500];
        let length = {
            let mut adder = ByteHandle::new(&mut buf, 4);
            adder.add_bytes(&[0x00, 0x01]); // 1 query
            adder.add_bytes(&[0x00, 0x01]); // 1 answer
            adder.add_bytes(&[0x00, 0x02]); // 2 authorities
            adder.skip_bytes(2);

            adder.add_bytes(&[0x00, 0x12, 0x34, 0x43, 0x21]); // null query
            adder.add_bytes(&[
                0x00, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x00, 0x00,
            ]); // null answer

            adder.add_bytes(&[0x03, 0x77, 0x77, 0x77]); // www
            adder.add_bytes(&[0x06, 0x64, 0x6F, 0x6D, 0x61, 0x69, 0x6E]); // domain
            adder.add_bytes(&[0x03, 0x63, 0x6F, 0x6D, 0x00]); // com [end]
            adder.add_bytes(&[0x00, 0x01]); // type A (host address)
            adder.add_bytes(&[0x00, 0x01]); // class IN
            adder.add_bytes(&[0x45, 0x67, 0x89, 0xAB]); // time to live
            adder.add_bytes(&[0x00, 0x04]); // rdata length
            adder.add_bytes(&[0xCD, 0xEF, 0x01, 0x23]); // rdata

            adder.add_bytes(&[0x03, 0x78, 0x79, 0x7A]); // xyz
            adder.add_bytes(&[0x07, 0x66, 0x69, 0x64, 0x64, 0x6C, 0x65, 0x73]); // fiddles
            adder.add_bytes(&[0x03, 0x6F, 0x72, 0x67, 0x00]); // org [end]
            adder.add_bytes(&[0x23, 0x45]); // type
            adder.add_bytes(&[0x34, 0x56]); // class
            adder.add_bytes(&[0xFE, 0xDC, 0xBA, 0x98]); // time to live
            adder.add_bytes(&[0x00, 0x04]); // rdata length
            adder.add_bytes(&[0x56, 0x78, 0x9A, 0xBC]); // rdata

            adder.get_offset()
        };

        let subject = PacketFacade::new(&mut buf, length);

        let records = subject.get_authorities().unwrap();
        assert_eq!(records.len(), 2);
        let first_record = &records[0];
        assert_eq!(first_record.get_name(), "www.domain.com");
        assert_eq!(first_record.get_resource_type(), 0x0001);
        assert_eq!(first_record.get_resource_class(), 0x0001);
        assert_eq!(first_record.get_time_to_live(), 0x456789AB);
        assert_eq!(first_record.get_rdata(), u8vec(&[0xCD, 0xEF, 0x01, 0x23]));
        let second_record = &records[1];
        assert_eq!(second_record.get_name(), "xyz.fiddles.org");
        assert_eq!(second_record.get_resource_type(), 0x2345);
        assert_eq!(second_record.get_resource_class(), 0x3456);
        assert_eq!(second_record.get_time_to_live(), 0xFEDCBA98);
        assert_eq!(second_record.get_rdata(), u8vec(&[0x56, 0x78, 0x9A, 0xBC]));

        assert_eq!(subject.get_length(), length);
    }

    #[test]
    fn can_access_additionals() {
        let mut buf: [u8; 500] = [0; 500];
        let length = {
            let mut adder = ByteHandle::new(&mut buf, 4);
            adder.add_bytes(&[0x00, 0x01]); // 1 query
            adder.add_bytes(&[0x00, 0x01]); // 1 answer
            adder.add_bytes(&[0x00, 0x01]); // 1 authority
            adder.add_bytes(&[0x00, 0x02]); // 2 additionals

            adder.add_bytes(&[0x00, 0x12, 0x34, 0x43, 0x21]); // null query
            adder.add_bytes(&[
                0x00, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x00, 0x00,
            ]); // null answer
            adder.add_bytes(&[
                0x00, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x00, 0x00,
            ]); // null authority

            adder.add_bytes(&[0x03, 0x77, 0x77, 0x77]); // www
            adder.add_bytes(&[0x06, 0x64, 0x6F, 0x6D, 0x61, 0x69, 0x6E]); // domain
            adder.add_bytes(&[0x03, 0x63, 0x6F, 0x6D, 0x00]); // com [end]
            adder.add_bytes(&[0x00, 0x01]); // type A (host address)
            adder.add_bytes(&[0x00, 0x01]); // class IN
            adder.add_bytes(&[0x45, 0x67, 0x89, 0xAB]); // time to live
            adder.add_bytes(&[0x00, 0x04]); // rdata length
            adder.add_bytes(&[0xCD, 0xEF, 0x01, 0x23]); // rdata

            adder.add_bytes(&[0x03, 0x78, 0x79, 0x7A]); // xyz
            adder.add_bytes(&[0x07, 0x66, 0x69, 0x64, 0x64, 0x6C, 0x65, 0x73]); // fiddles
            adder.add_bytes(&[0x03, 0x6F, 0x72, 0x67, 0x00]); // org [end]
            adder.add_bytes(&[0x23, 0x45]); // type
            adder.add_bytes(&[0x34, 0x56]); // class
            adder.add_bytes(&[0xFE, 0xDC, 0xBA, 0x98]); // time to live
            adder.add_bytes(&[0x00, 0x04]); // rdata length
            adder.add_bytes(&[0x56, 0x78, 0x9A, 0xBC]); // rdata

            adder.get_offset()
        };

        let subject = PacketFacade::new(&mut buf, length);

        let records = subject.get_additionals().unwrap();
        assert_eq!(records.len(), 2);
        let first_record = &records[0];
        assert_eq!(first_record.get_name(), "www.domain.com");
        assert_eq!(first_record.get_resource_type(), 0x0001);
        assert_eq!(first_record.get_resource_class(), 0x0001);
        assert_eq!(first_record.get_time_to_live(), 0x456789AB);
        assert_eq!(first_record.get_rdata(), u8vec(&[0xCD, 0xEF, 0x01, 0x23]));
        let second_record = &records[1];
        assert_eq!(second_record.get_name(), "xyz.fiddles.org");
        assert_eq!(second_record.get_resource_type(), 0x2345);
        assert_eq!(second_record.get_resource_class(), 0x3456);
        assert_eq!(second_record.get_time_to_live(), 0xFEDCBA98);
        assert_eq!(second_record.get_rdata(), u8vec(&[0x56, 0x78, 0x9A, 0xBC]));

        assert_eq!(subject.get_length(), length);
    }

    #[test]
    fn can_set_transaction_id() {
        let mut buf: [u8; 500] = [0; 500];
        let length = {
            let mut subject = PacketFacade::new(&mut buf, 12);

            assert_eq!(subject.set_transaction_id(0x1234), true);

            subject.get_length()
        };

        assert_eq!(PacketFacade::u16_from(&buf, 0, length), Some(0x1234));
        assert_eq!(length, 12);
    }

    #[test]
    fn can_set_flags_to_zeros_then_ones() {
        let mut buf: [u8; 500] = [0; 500];
        let length = {
            let mut subject = PacketFacade::new(&mut buf, 12);

            assert_eq!(subject.set_query(true), true);
            assert_eq!(subject.set_opcode(0xF), true);
            assert_eq!(subject.set_authoritative_answer(false), true);
            assert_eq!(subject.set_truncated(true), true);
            assert_eq!(subject.set_recursion_desired(false), true);
            assert_eq!(subject.set_recursion_available(true), true);
            assert_eq!(subject.set_z(false), true);
            assert_eq!(subject.set_authenticated_data(true), true);
            assert_eq!(subject.set_checking_disabled(false), true);
            assert_eq!(subject.set_rcode(0xF), true);
            subject.get_length()
        };

        assert_eq!(buf[2], 0x7A);
        assert_eq!(buf[3], 0xAF);
        assert_eq!(length, 12);
    }

    #[test]
    fn can_set_flags_to_ones_then_zeros() {
        let mut buf: [u8; 500] = [0; 500];
        let length = {
            let mut subject = PacketFacade::new(&mut buf, 12);

            assert_eq!(subject.set_query(false), true);
            assert_eq!(subject.set_opcode(0x0), true);
            assert_eq!(subject.set_authoritative_answer(true), true);
            assert_eq!(subject.set_truncated(false), true);
            assert_eq!(subject.set_recursion_desired(true), true);
            assert_eq!(subject.set_recursion_available(false), true);
            assert_eq!(subject.set_z(true), true);
            assert_eq!(subject.set_authenticated_data(false), true);
            assert_eq!(subject.set_checking_disabled(true), true);
            assert_eq!(subject.set_rcode(0x0), true);
            subject.get_length()
        };

        assert_eq!(buf[2], 0x85);
        assert_eq!(buf[3], 0x50);
        assert_eq!(length, 12);
    }

    #[test]
    fn can_add_queries() {
        let mut buf: [u8; 500] = [0; 500];
        let get_length = {
            let mut subject = PacketFacade::new(&mut buf, 12);

            assert_eq!(subject.add_query("www.domain.com", 0x0001, 0x0001), true);
            assert_eq!(subject.add_query("xyz.fiddles.org", 0x1234, 0x2345), true);

            subject.get_length()
        };

        let mut checker = ByteHandle::new(&mut buf, 4);
        checker.check_bytes(&[0x00, 0x02]); // 2 queries
        checker.skip_bytes(6);

        checker.check_bytes(&[0x03, 0x77, 0x77, 0x77]); // www
        checker.check_bytes(&[0x06, 0x64, 0x6F, 0x6D, 0x61, 0x69, 0x6E]); // domain
        checker.check_bytes(&[0x03, 0x63, 0x6F, 0x6D, 0x00]); // com [end]
        checker.check_bytes(&[0x00, 0x01]); // type A (host address)
        checker.check_bytes(&[0x00, 0x01]); // class IN

        checker.check_bytes(&[0x03, 0x78, 0x79, 0x7A]); // xyz
        checker.check_bytes(&[0x07, 0x66, 0x69, 0x64, 0x64, 0x6C, 0x65, 0x73]); // fiddles
        checker.check_bytes(&[0x03, 0x6F, 0x72, 0x67, 0x00]); // org [end]
        checker.check_bytes(&[0x12, 0x34]); // invalid type
        checker.check_bytes(&[0x23, 0x45]); // invalid class

        assert_eq!(get_length, checker.get_offset());
    }

    #[test]
    fn can_add_answers() {
        let mut buf: [u8; 500] = [0; 500];
        let get_length = {
            let mut subject = PacketFacade::new(&mut buf, 12);

            assert_eq!(subject.add_query("", 0xFEDC, 0xBA98), true);
            assert_eq!(
                subject.add_answer(
                    "www.domain.com",
                    0x1234,
                    0x2345,
                    0x12345678,
                    &[0x00, 0x05, 0x10, 0x15],
                ),
                true
            );
            assert_eq!(
                subject.add_answer(
                    "xyz.fiddles.org",
                    0x3456,
                    0x4567,
                    0x87654321,
                    &[0x20, 0x25, 0x30, 0x35],
                ),
                true
            );

            subject.get_length()
        };

        let mut checker = ByteHandle::new(&mut buf, 4);
        checker.check_bytes(&[0x00, 0x01]); // 1 query
        checker.check_bytes(&[0x00, 0x02]); // 2 answers
        checker.skip_bytes(4);

        checker.check_bytes(&[0x00, 0xFE, 0xDC, 0xBA, 0x98]); // query for spacing

        checker.check_bytes(&[0x03, 0x77, 0x77, 0x77]); // www
        checker.check_bytes(&[0x06, 0x64, 0x6F, 0x6D, 0x61, 0x69, 0x6E]); // domain
        checker.check_bytes(&[0x03, 0x63, 0x6F, 0x6D, 0x00]); // com [end]
        checker.check_bytes(&[0x12, 0x34]); // resource_type
        checker.check_bytes(&[0x23, 0x45]); // resource_class
        checker.check_bytes(&[0x12, 0x34, 0x56, 0x78]); // time to live
        checker.check_bytes(&[0x00, 0x04]); // resource data length
        checker.check_bytes(&[0x00, 0x05, 0x10, 0x15]); // data

        checker.check_bytes(&[0x03, 0x78, 0x79, 0x7A]); // xyz
        checker.check_bytes(&[0x07, 0x66, 0x69, 0x64, 0x64, 0x6C, 0x65, 0x73]); // fiddles
        checker.check_bytes(&[0x03, 0x6F, 0x72, 0x67, 0x00]); // org [end]
        checker.check_bytes(&[0x34, 0x56]); // resource type
        checker.check_bytes(&[0x45, 0x67]); // resource class
        checker.check_bytes(&[0x87, 0x65, 0x43, 0x21]); // time to live
        checker.check_bytes(&[0x00, 0x04]); // resource data length
        checker.check_bytes(&[0x20, 0x25, 0x30, 0x35]); // data

        assert_eq!(get_length, checker.get_offset());
    }

    #[test]
    fn can_add_authorities() {
        let mut buf: [u8; 500] = [0; 500];
        let get_length = {
            let mut subject = PacketFacade::new(&mut buf, 12);

            assert_eq!(subject.add_query("", 0xFEDC, 0xBA98), true);
            assert_eq!(
                subject.add_answer("", 0xFEDC, 0xBA98, 0x76543210, &[]),
                true
            );
            assert_eq!(
                subject.add_authority(
                    "www.domain.com",
                    0x1234,
                    0x2345,
                    0x12345678,
                    &[0x00, 0x05, 0x10, 0x15],
                ),
                true
            );
            assert_eq!(
                subject.add_authority(
                    "xyz.fiddles.org",
                    0x3456,
                    0x4567,
                    0x87654321,
                    &[0x20, 0x25, 0x30, 0x35],
                ),
                true
            );

            subject.get_length()
        };

        let mut checker = ByteHandle::new(&mut buf, 4);
        checker.check_bytes(&[0x00, 0x01]); // 1 query
        checker.check_bytes(&[0x00, 0x01]); // 1 answer
        checker.check_bytes(&[0x00, 0x02]); // 2 authorities
        checker.skip_bytes(2);

        checker.check_bytes(&[0x00, 0xFE, 0xDC, 0xBA, 0x98]); // query for spacing
        checker.check_bytes(&[
            0x00, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x00, 0x00,
        ]); // answer for spacing

        checker.check_bytes(&[0x03, 0x77, 0x77, 0x77]); // www
        checker.check_bytes(&[0x06, 0x64, 0x6F, 0x6D, 0x61, 0x69, 0x6E]); // domain
        checker.check_bytes(&[0x03, 0x63, 0x6F, 0x6D, 0x00]); // com [end]
        checker.check_bytes(&[0x12, 0x34]); // resource_type
        checker.check_bytes(&[0x23, 0x45]); // resource_class
        checker.check_bytes(&[0x12, 0x34, 0x56, 0x78]); // time to live
        checker.check_bytes(&[0x00, 0x04]); // resource data length
        checker.check_bytes(&[0x00, 0x05, 0x10, 0x15]); // data

        checker.check_bytes(&[0x03, 0x78, 0x79, 0x7A]); // xyz
        checker.check_bytes(&[0x07, 0x66, 0x69, 0x64, 0x64, 0x6C, 0x65, 0x73]); // fiddles
        checker.check_bytes(&[0x03, 0x6F, 0x72, 0x67, 0x00]); // org [end]
        checker.check_bytes(&[0x34, 0x56]); // resource type
        checker.check_bytes(&[0x45, 0x67]); // resource class
        checker.check_bytes(&[0x87, 0x65, 0x43, 0x21]); // time to live
        checker.check_bytes(&[0x00, 0x04]); // resource data length
        checker.check_bytes(&[0x20, 0x25, 0x30, 0x35]); // data

        assert_eq!(get_length, checker.get_offset());
    }

    #[test]
    fn can_add_additionals() {
        let mut buf: [u8; 500] = [0; 500];
        let get_length = {
            let mut subject = PacketFacade::new(&mut buf, 12);

            assert_eq!(subject.add_query("", 0xFEDC, 0xBA98), true);
            assert_eq!(
                subject.add_answer("", 0xFEDC, 0xBA98, 0x76543210, &[]),
                true
            );
            assert_eq!(
                subject.add_authority("", 0xFEDC, 0xBA98, 0x76543210, &[]),
                true
            );
            assert_eq!(
                subject.add_additional(
                    "www.domain.com",
                    0x1234,
                    0x2345,
                    0x12345678,
                    &[0x00, 0x05, 0x10, 0x15],
                ),
                true
            );
            assert_eq!(
                subject.add_additional(
                    "xyz.fiddles.org",
                    0x3456,
                    0x4567,
                    0x87654321,
                    &[0x20, 0x25, 0x30, 0x35],
                ),
                true
            );

            subject.get_length()
        };

        let mut checker = ByteHandle::new(&mut buf, 4);
        checker.check_bytes(&[0x00, 0x01]); // 1 query
        checker.check_bytes(&[0x00, 0x01]); // 1 answer
        checker.check_bytes(&[0x00, 0x01]); // 1 authority
        checker.check_bytes(&[0x00, 0x02]); // 2 additionals

        checker.check_bytes(&[0x00, 0xFE, 0xDC, 0xBA, 0x98]); // query for spacing
        checker.check_bytes(&[
            0x00, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x00, 0x00,
        ]); // answer for spacing
        checker.check_bytes(&[
            0x00, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x00, 0x00,
        ]); // authority for spacing

        checker.check_bytes(&[0x03, 0x77, 0x77, 0x77]); // www
        checker.check_bytes(&[0x06, 0x64, 0x6F, 0x6D, 0x61, 0x69, 0x6E]); // domain
        checker.check_bytes(&[0x03, 0x63, 0x6F, 0x6D, 0x00]); // com [end]
        checker.check_bytes(&[0x12, 0x34]); // resource_type
        checker.check_bytes(&[0x23, 0x45]); // resource_class
        checker.check_bytes(&[0x12, 0x34, 0x56, 0x78]); // time to live
        checker.check_bytes(&[0x00, 0x04]); // resource data length
        checker.check_bytes(&[0x00, 0x05, 0x10, 0x15]); // data

        checker.check_bytes(&[0x03, 0x78, 0x79, 0x7A]); // xyz
        checker.check_bytes(&[0x07, 0x66, 0x69, 0x64, 0x64, 0x6C, 0x65, 0x73]); // fiddles
        checker.check_bytes(&[0x03, 0x6F, 0x72, 0x67, 0x00]); // org [end]
        checker.check_bytes(&[0x34, 0x56]); // resource type
        checker.check_bytes(&[0x45, 0x67]); // resource class
        checker.check_bytes(&[0x87, 0x65, 0x43, 0x21]); // time to live
        checker.check_bytes(&[0x00, 0x04]); // resource data length
        checker.check_bytes(&[0x20, 0x25, 0x30, 0x35]); // data

        assert_eq!(get_length, checker.get_offset());
    }

    #[test]
    fn clears_existing_queries_and_resource_records() {
        let mut buf: [u8; 100] = [0; 100];
        {
            let mut adder = ByteHandle::new(&mut buf, 0);
            adder.add_bytes(&[0x12, 0x34]); // transaction id
            adder.add_bytes(&[0x56, 0x78]); // flags
            adder.add_bytes(&[0x01, 0x01]); // query count
            adder.add_bytes(&[0x01, 0x01]); // answer count
            adder.add_bytes(&[0x01, 0x01]); // authority count
            adder.add_bytes(&[0x01, 0x01]); // additional count
        }
        {
            let mut subject = PacketFacade::new(&mut buf, 100);

            subject.clear();
        }
        {
            let mut checker = ByteHandle::new(&mut buf, 0);
            checker.check_bytes(&[0x12, 0x34]); // transaction id unmolested
            checker.check_bytes(&[0x56, 0x78]); // flags unmolested
            checker.check_bytes(&[0x00, 0x00]); // queries cleared
            checker.check_bytes(&[0x00, 0x00]); // answers cleared
            checker.check_bytes(&[0x00, 0x00]); // authorities cleared
            checker.check_bytes(&[0x00, 0x00]); // additionals cleared
        }
    }

    #[test]
    fn returns_none_if_getting_transaction_id_busts_length() {
        let mut buf: [u8; 100] = [0; 100];
        let subject = PacketFacade::new(&mut buf, 1);

        assert_eq!(subject.get_transaction_id(), None);
    }

    #[test]
    fn returns_false_if_setting_transaction_id_busts_length() {
        let mut buf: [u8; 1] = [0; 1];
        let mut subject = PacketFacade::new(&mut buf, 100);

        assert_eq!(subject.set_transaction_id(0x1234), false);
    }

    #[test]
    fn returns_none_if_getting_first_flag_byte_busts_length() {
        let mut buf: [u8; 100] = [0; 100];
        let subject = PacketFacade::new(&mut buf, 2);

        assert_eq!(subject.is_query(), None);
        assert_eq!(subject.get_opcode(), None);
        assert_eq!(subject.is_authoritative_answer(), None);
        assert_eq!(subject.is_truncated(), None);
        assert_eq!(subject.is_recursion_desired(), None);
    }

    #[test]
    fn returns_false_if_setting_first_flag_byte_busts_length() {
        let mut buf: [u8; 2] = [0; 2];
        let mut subject = PacketFacade::new(&mut buf, 100);

        assert_eq!(subject.set_query(false), false);
        assert_eq!(subject.set_opcode(0x5), false);
        assert_eq!(subject.set_authoritative_answer(false), false);
        assert_eq!(subject.set_truncated(false), false);
        assert_eq!(subject.set_recursion_desired(false), false);
    }

    #[test]
    fn returns_none_if_getting_second_flag_byte_busts_length() {
        let mut buf: [u8; 100] = [0; 100];
        let subject = PacketFacade::new(&mut buf, 3);

        assert_eq!(subject.is_recursion_available(), None);
        assert_eq!(subject.get_z(), None);
        assert_eq!(subject.is_authenticated_data(), None);
        assert_eq!(subject.is_checking_disabled(), None);
        assert_eq!(subject.get_rcode(), None);
    }

    #[test]
    fn returns_false_if_setting_second_flag_byte_busts_length() {
        let mut buf: [u8; 3] = [0; 3];
        let mut subject = PacketFacade::new(&mut buf, 100);

        assert_eq!(subject.set_recursion_available(false), false);
        assert_eq!(subject.set_z(false), false);
        assert_eq!(subject.set_authenticated_data(false), false);
        assert_eq!(subject.set_checking_disabled(false), false);
        assert_eq!(subject.set_rcode(0x3), false);
    }

    #[test]
    fn returns_none_if_getting_query_count_busts_length() {
        let mut buf: [u8; 100] = [0xAA; 100];
        let subject = PacketFacade::new(&mut buf, 5);

        assert_eq!(subject.get_queries().is_none(), true);
        assert_eq!(subject.find_queries_end().is_none(), true);
    }

    #[test]
    fn returns_none_if_getting_answer_count_busts_length() {
        let mut buf: [u8; 100] = [0xAA; 100];
        let subject = PacketFacade::new(&mut buf, 7);

        assert_eq!(subject.get_answers().is_none(), true);
        assert_eq!(subject.find_answers_end().is_none(), true);
    }

    #[test]
    fn returns_none_if_getting_authority_count_busts_length() {
        let mut buf: [u8; 100] = [0xAA; 100];
        let subject = PacketFacade::new(&mut buf, 9);

        assert_eq!(subject.get_authorities().is_none(), true);
        assert_eq!(subject.find_authorities_end().is_none(), true);
    }

    #[test]
    fn returns_none_if_getting_additional_count_busts_length() {
        let mut buf: [u8; 100] = [0xAA; 100];
        let subject = PacketFacade::new(&mut buf, 11);

        assert_eq!(subject.get_additionals().is_none(), true);
        assert_eq!(subject.find_additionals_end().is_none(), true);
    }

    #[test]
    fn returns_none_if_getting_query_busts_length() {
        let mut buf: [u8; 100] = [0; 100];
        let length = {
            let mut adder = ByteHandle::new(&mut buf, 0);
            adder.skip_bytes(4); // id and flags
            adder.add_bytes(&[0x00, 0x01]); // one query
            adder.skip_bytes(6); // answer, authority, additional counts
            adder.add_bytes(&[0x01]); // 1-byte part
            adder.get_offset()
        };
        let subject = PacketFacade::new(&mut buf, length);

        assert_eq!(subject.get_queries().is_none(), true);
        assert_eq!(subject.find_queries_end().is_none(), true);
    }

    #[test]
    fn returns_false_if_adding_query_busts_length() {
        let mut buf: [u8; 12] = [0; 12];
        let mut subject = PacketFacade::new(&mut buf, 100);

        let result = subject.add_query("booga", 0x0101, 0x0202);

        assert_eq!(result, false);
    }

    #[test]
    fn returns_none_if_getting_answer_busts_length() {
        let mut buf: [u8; 100] = [0; 100];
        let length = {
            let mut adder = ByteHandle::new(&mut buf, 0);
            adder.skip_bytes(6); // id, flags, and query count
            adder.add_bytes(&[0x00, 0x01]); // one answer
            adder.skip_bytes(4); // authority, additional count
            adder.add_bytes(&[0x01]); // 1-byte part
            adder.get_offset()
        };
        let subject = PacketFacade::new(&mut buf, length);

        assert_eq!(subject.get_answers().is_none(), true);
        assert_eq!(subject.find_answers_end().is_none(), true);
    }

    #[test]
    fn returns_false_if_adding_answer_busts_length() {
        let mut buf: [u8; 12] = [0; 12];
        let mut subject = PacketFacade::new(&mut buf, 100);

        let result = subject.add_answer("booga", 0x0101, 0x0202, 0x03030303, &[0x04]);

        assert_eq!(result, false);
    }

    #[test]
    fn returns_none_if_getting_authority_busts_length() {
        let mut buf: [u8; 100] = [0; 100];
        let length = {
            let mut adder = ByteHandle::new(&mut buf, 0);
            adder.skip_bytes(8); // id, flags, and query, answer count
            adder.add_bytes(&[0x00, 0x01]); // one authority
            adder.skip_bytes(2); // additional count
            adder.add_bytes(&[0x01]); // 1-byte part
            adder.get_offset()
        };
        let subject = PacketFacade::new(&mut buf, length);

        assert_eq!(subject.get_authorities().is_none(), true);
        assert_eq!(subject.find_authorities_end().is_none(), true);
    }

    #[test]
    fn returns_false_if_adding_authority_busts_length() {
        let mut buf: [u8; 12] = [0; 12];
        let mut subject = PacketFacade::new(&mut buf, 100);

        let result = subject.add_authority("booga", 0x0101, 0x0202, 0x03030303, &[0x04]);

        assert_eq!(result, false);
    }

    #[test]
    fn returns_none_if_getting_additional_busts_length() {
        let mut buf: [u8; 100] = [0; 100];
        let length = {
            let mut adder = ByteHandle::new(&mut buf, 0);
            adder.skip_bytes(10); // id, flags, and query, answer, authority count
            adder.add_bytes(&[0x00, 0x01]); // one additional
            adder.add_bytes(&[0x01]); // 1-byte part
            adder.get_offset()
        };
        let subject = PacketFacade::new(&mut buf, length);

        assert_eq!(subject.get_additionals().is_none(), true);
        assert_eq!(subject.find_additionals_end().is_none(), true);
    }

    #[test]
    fn returns_false_if_adding_additional_busts_length() {
        let mut buf: [u8; 12] = [0; 12];
        let mut subject = PacketFacade::new(&mut buf, 100);

        let result = subject.add_authority("booga", 0x0101, 0x0202, 0x03030303, &[0x04]);

        assert_eq!(result, false);
    }

    #[test]
    fn writing_query_adjusts_subject_length() {
        let mut buf: [u8; 100] = [0; 100];
        let mut subject = PacketFacade::new(&mut buf, 12);

        let result = subject.add_query("booga", 0x0000, 0x0000);

        assert_eq!(result, true);
        assert_eq!(subject.length, 23)
    }

    #[test]
    fn writing_resource_record_adjusts_subject_length() {
        let mut buf: [u8; 100] = [0; 100];
        let mut subject = PacketFacade::new(&mut buf, 12);

        let result =
            subject.write_resource_record(12, "booga", 0x1234, 0x5678, 0x9ABCDEF0, &[0x24, 0x36]);

        assert_eq!(result, Some(19));
        assert_eq!(subject.length, 31);
    }

    #[test]
    fn writing_resource_record_returns_none_if_name_end_indicator_busts_length() {
        let mut buf: [u8; 14] = [0; 14];
        let mut subject = PacketFacade::new(&mut buf, 100);

        let result = subject.write_resource_record(12, "x", 0x1234, 0x5678, 0x9ABCDEF0, &[0x48]);

        assert_eq!(result, None);
    }

    #[test]
    fn writing_resource_record_returns_none_if_rdata_busts_length() {
        let mut buf: [u8; 23] = [0; 23];
        let mut subject = PacketFacade::new(&mut buf, 100);

        let result = subject.write_resource_record(12, "", 0x1234, 0x5678, 0x9ABCDEF0, &[0x48]);

        assert_eq!(result, None);
    }

    #[test]
    fn reverse_integration() {
        let mut buf: [u8; 500] = [0; 500];
        let mut subject = PacketFacade::new(&mut buf, 500);

        subject.set_transaction_id(1022);
        subject.set_query(false);
        subject.set_opcode(0xA);
        subject.set_authoritative_answer(true);
        subject.set_truncated(false);
        subject.set_recursion_desired(true);
        subject.set_recursion_available(false);
        subject.set_z(true);
        subject.set_authenticated_data(false);
        subject.set_checking_disabled(true);
        subject.set_rcode(0x5);
        subject.add_query("a.b.c", 1000, 1001);
        subject.add_query("b.c.d", 1002, 1003);
        subject.add_answer("c.d.e", 1004, 1005, 1006, &[0x01, 0x02]);
        subject.add_answer("d.e.f", 1007, 1008, 1009, &[0x03, 0x04]);
        subject.add_authority("e.f.g", 1010, 1011, 1012, &[0x05, 0x06]);
        subject.add_authority("f.g.h", 1013, 1014, 1015, &[0x07, 0x08]);
        subject.add_additional("g.h.i", 1016, 1017, 1018, &[0x09, 0x0A]);
        subject.add_additional("h.i.j", 1019, 1020, 1021, &[0x0B, 0x0C]);

        assert_eq!(subject.get_transaction_id(), Some(1022));
        assert_eq!(subject.is_query(), Some(false));
        assert_eq!(subject.get_opcode(), Some(0xA));
        assert_eq!(subject.is_authoritative_answer(), Some(true));
        assert_eq!(subject.is_truncated(), Some(false));
        assert_eq!(subject.is_recursion_desired(), Some(true));
        assert_eq!(subject.is_recursion_available(), Some(false));
        assert_eq!(subject.get_z(), Some(true));
        assert_eq!(subject.is_authenticated_data(), Some(false));
        assert_eq!(subject.is_checking_disabled(), Some(true));
        assert_eq!(subject.get_rcode(), Some(0x5));

        let queries = subject.get_queries().unwrap();
        assert_eq!(queries[0].get_query_name(), "a.b.c");
        assert_eq!(queries[0].get_query_type(), 1000);
        assert_eq!(queries[0].get_query_class(), 1001);
        assert_eq!(queries[1].get_query_name(), "b.c.d");
        assert_eq!(queries[1].get_query_type(), 1002);
        assert_eq!(queries[1].get_query_class(), 1003);
        assert_eq!(queries.len(), 2);

        let answers = subject.get_answers().unwrap();
        assert_eq!(answers[0].get_name(), "c.d.e");
        assert_eq!(answers[0].get_resource_type(), 1004);
        assert_eq!(answers[0].get_resource_class(), 1005);
        assert_eq!(answers[0].get_time_to_live(), 1006);
        assert_eq!(answers[0].get_rdata(), u8vec(&[0x01, 0x02]));
        assert_eq!(answers[1].get_name(), "d.e.f");
        assert_eq!(answers[1].get_resource_type(), 1007);
        assert_eq!(answers[1].get_resource_class(), 1008);
        assert_eq!(answers[1].get_time_to_live(), 1009);
        assert_eq!(answers[1].get_rdata(), u8vec(&[0x03, 0x04]));
        assert_eq!(answers.len(), 2);

        let authorities = subject.get_authorities().unwrap();
        assert_eq!(authorities[0].get_name(), "e.f.g");
        assert_eq!(authorities[0].get_resource_type(), 1010);
        assert_eq!(authorities[0].get_resource_class(), 1011);
        assert_eq!(authorities[0].get_time_to_live(), 1012);
        assert_eq!(authorities[0].get_rdata(), u8vec(&[0x05, 0x06]));
        assert_eq!(authorities[1].get_name(), "f.g.h");
        assert_eq!(authorities[1].get_resource_type(), 1013);
        assert_eq!(authorities[1].get_resource_class(), 1014);
        assert_eq!(authorities[1].get_time_to_live(), 1015);
        assert_eq!(authorities[1].get_rdata(), u8vec(&[0x07, 0x08]));
        assert_eq!(authorities.len(), 2);

        let additionals = subject.get_additionals().unwrap();
        assert_eq!(additionals[0].get_name(), "g.h.i");
        assert_eq!(additionals[0].get_resource_type(), 1016);
        assert_eq!(additionals[0].get_resource_class(), 1017);
        assert_eq!(additionals[0].get_time_to_live(), 1018);
        assert_eq!(additionals[0].get_rdata(), u8vec(&[0x09, 0x0A]));
        assert_eq!(additionals[1].get_name(), "h.i.j");
        assert_eq!(additionals[1].get_resource_type(), 1019);
        assert_eq!(additionals[1].get_resource_class(), 1020);
        assert_eq!(additionals[1].get_time_to_live(), 1021);
        assert_eq!(additionals[1].get_rdata(), u8vec(&[0x0B, 0x0C]));
        assert_eq!(additionals.len(), 2);
    }

    fn u8vec(buf: &[u8]) -> &[u8] {
        buf
    }

    struct ByteHandle<'a> {
        buf: &'a mut [u8],
        offset: usize,
    }

    impl<'a> ByteHandle<'a> {
        pub fn new(buf: &'a mut [u8], offset: usize) -> ByteHandle<'a> {
            ByteHandle { buf, offset }
        }

        pub fn add_bytes(&mut self, bytes: &[u8]) -> usize {
            for i in 0..bytes.len() {
                self.buf[self.offset + i] = bytes[i]
            }
            self.offset += bytes.len();
            self.offset
        }

        pub fn check_bytes(&mut self, bytes: &[u8]) -> usize {
            let actual_bytes = &self.buf[self.offset..(self.offset + bytes.len())];
            assert_eq!(actual_bytes, bytes, "At offset {}", self.offset);
            self.offset += bytes.len();
            self.offset
        }

        pub fn skip_bytes(&mut self, count: usize) -> usize {
            self.offset += count;
            self.offset
        }

        pub fn get_offset(&self) -> usize {
            self.offset
        }
    }
}
