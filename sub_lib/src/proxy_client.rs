// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use actix::Recipient;
use actix::Syn;
use cryptde::PlainData;
use hopper::ExpiredCoresPackage;
use peer_actors::BindMessage;
use stream_key::StreamKey;

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct ClientResponsePayload {
    pub stream_key: StreamKey,
    pub last_response: bool,
    pub sequence_number: u64,
    pub data: PlainData
}

#[derive(Clone)]
pub struct ProxyClientSubs {
    pub bind: Recipient<Syn, BindMessage>,
    pub from_hopper: Recipient<Syn, ExpiredCoresPackage>,
}

impl ClientResponsePayload {
    pub fn make_terminating_payload(stream_key: StreamKey) -> ClientResponsePayload {
        ClientResponsePayload {
            stream_key,
            last_response: true,
            sequence_number: 0,
            data: PlainData::new(&[]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::str::FromStr;

    #[test]
    fn make_terminating_payload_makes_terminating_payload() {
        let stream_key = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let payload = ClientResponsePayload::make_terminating_payload(stream_key);

        assert_eq!(payload, ClientResponsePayload {
            stream_key,
            last_response: true,
            sequence_number: 0,
            data: PlainData::new(&[])
        })
    }
}