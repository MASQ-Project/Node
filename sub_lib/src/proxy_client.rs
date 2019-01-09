// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use actix::Recipient;
use actix::Syn;
use hopper::ExpiredCoresPackage;
use peer_actors::BindMessage;
use sequence_buffer::SequencedPacket;
use stream_key::StreamKey;

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct ClientResponsePayload {
    pub stream_key: StreamKey,
    pub sequenced_packet: SequencedPacket,
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
            sequenced_packet: SequencedPacket {
                data: vec![],
                sequence_number: 0,
                last_data: true,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use utils::tests::make_meaningless_stream_key;

    #[test]
    fn make_terminating_payload_makes_terminating_payload() {
        let stream_key: StreamKey = make_meaningless_stream_key();

        let payload = ClientResponsePayload::make_terminating_payload(stream_key);

        assert_eq!(
            payload,
            ClientResponsePayload {
                stream_key,
                sequenced_packet: SequencedPacket {
                    data: vec!(),
                    sequence_number: 0,
                    last_data: true
                },
            }
        )
    }
}
