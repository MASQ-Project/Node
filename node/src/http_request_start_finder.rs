// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use sub_lib::utils::index_of;
use sub_lib::dispatcher::Component;
use sub_lib::http_packet_framer::State;
use sub_lib::http_packet_framer::HttpPacketStartFinder;
use sub_lib::http_packet_framer::HttpFramerState;
use sub_lib::http_packet_framer::HttpPacketFramer;
use discriminator::Discriminator;
use discriminator::DiscriminatorFactory;
use null_masquerader::NullMasquerader;

const METHODS: &[&[u8]] = &[b"GET", b"HEAD", b"POST", b"PUT", b"DELETE", b"CONNECT", b"OPTIONS", b"TRACE", b"PATCH"];
const LONGEST_METHOD_LEN: usize = 7;

pub struct HttpRequestStartFinder {}

impl HttpPacketStartFinder for HttpRequestStartFinder {
    fn handle_seeking_request_start(&self, framer_state: &mut HttpFramerState) {
        if framer_state.state == State::SeekingRequestStart {
            match METHODS.iter().flat_map(|method| {
                index_of(&framer_state.data_so_far[..], *method)
            }).min() {
                Some(first_method_offset) => {
                    let clean_start_data = framer_state.data_so_far.split_off(first_method_offset);
                    framer_state.data_so_far = clean_start_data;
                    framer_state.state = State::SeekingBodyStart;
                    framer_state.content_length = 0;
                    framer_state.lines.clear ();
                },
                None => {
                    let index = if framer_state.data_so_far.len () > LONGEST_METHOD_LEN
                        {framer_state.data_so_far.len () - LONGEST_METHOD_LEN} else {0};
                    let remainder = framer_state.data_so_far.split_off (index);
                    framer_state.data_so_far = remainder;
                }
            };
        }
    }
}

pub struct HttpRequestDiscriminatorFactory {}

impl DiscriminatorFactory for HttpRequestDiscriminatorFactory {
    fn make(&self) -> Box<Discriminator> {
        Box::new (Discriminator::new (Box::new (HttpPacketFramer::new (Box::new (HttpRequestStartFinder {}))),
                                      vec! (Box::new (NullMasquerader::new (Component::ProxyServer)))))
    }

    fn clone(&self) -> Box<DiscriminatorFactory> {
        unimplemented!()
    }
}

impl HttpRequestDiscriminatorFactory {
    pub fn new () -> HttpRequestDiscriminatorFactory {
        HttpRequestDiscriminatorFactory {

        }
    }
}

#[cfg (test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_to_operate_in_state_other_than_seeking_request_start () {
        let mut framer_state = HttpFramerState {
            data_so_far: Vec::from("GET http://nowhere.com/index.html HTTP/1.1\r\n".as_bytes()),
            state: State::SeekingBodyStart,
            content_length: 100,
            lines: vec! (vec! (), vec! ()),
        };
        let subject = HttpRequestStartFinder {};

        subject.handle_seeking_request_start(&mut framer_state);

        assert_eq!(framer_state, HttpFramerState {
            data_so_far: Vec::from("GET http://nowhere.com/index.html HTTP/1.1\r\n".as_bytes()),
            state: State::SeekingBodyStart,
            content_length: 100,
            lines: vec! (vec! (), vec! ()),
        });
    }

    #[test]
    fn throws_away_leading_garbage_except_for_last_seven_characters () {
        let mut framer_state = HttpFramerState {
            data_so_far: Vec::from("this is garbage".as_bytes()),
            state: State::SeekingRequestStart,
            content_length: 100,
            lines: vec! (vec! (), vec! ()),
        };
        let subject = HttpRequestStartFinder {};

        subject.handle_seeking_request_start(&mut framer_state);

        assert_eq!(framer_state, HttpFramerState {
            data_so_far: Vec::from("garbage".as_bytes()),
            state: State::SeekingRequestStart,
            content_length: 100,
            lines: vec! (vec! (), vec! ()),
        });
    }

    #[test]
    fn frames_properly_in_the_presence_of_garbage () {
        let mut framer_state = HttpFramerState {
            data_so_far: Vec::from("this is garbageGET http://nowhere.com/index.html HTTP/1.1\r\n\
One-Header: value\r\n\
Another-Header: val".as_bytes()),
            state: State::SeekingRequestStart,
            content_length: 100,
            lines: vec! (vec! (), vec! ()),
        };
        let subject = HttpRequestStartFinder {};

        subject.handle_seeking_request_start(&mut framer_state);

        assert_eq!(framer_state, HttpFramerState {
            data_so_far: Vec::from("GET http://nowhere.com/index.html HTTP/1.1\r\n\
One-Header: value\r\n\
Another-Header: val".as_bytes()),
            state: State::SeekingBodyStart,
            content_length: 0,
            lines: vec! (),
        });
    }

    #[test]
    fn recognizes_all_methods() {
        METHODS.iter().for_each(|method| { check_method(method) })
    }

    fn check_method(method: &[u8]) {
        let mut request = Vec::from(method);
        request.extend (" http://nowhere.com/index.html HTTP/1.1\r\n\r\n".as_bytes());
        let saved_request = request.clone();
        let mut data = Vec::from("garbage".as_bytes());
        data.extend (request);
        let mut framer_state = HttpFramerState {
            data_so_far: data,
            state: State::SeekingRequestStart,
            content_length: 0,
            lines: vec! (),
        };
        let subject = HttpRequestStartFinder {};

        subject.handle_seeking_request_start(&mut framer_state);

        assert_eq!(framer_state, HttpFramerState {
            data_so_far: saved_request,
            state: State::SeekingBodyStart,
            content_length: 0,
            lines: vec! (),
        });
    }

    #[test]
    fn factory_makes_discriminator () {
        let subject = HttpRequestDiscriminatorFactory::new ();

        let mut http_discriminator = subject.make ();

        http_discriminator.add_data ("GET http://url.com HTTP/1.1\r\n\r\n".as_bytes ());
        let http_chunk = http_discriminator.take_chunk ().unwrap ();
        assert_eq! (http_chunk, (Component::ProxyServer, Vec::from ("GET http://url.com HTTP/1.1\r\n\r\n".as_bytes ())));
    }
}
