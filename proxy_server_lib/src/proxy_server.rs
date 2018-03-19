// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::marker::Send;
use sub_lib::dispatcher::Endpoint;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::hopper::ExpiredCoresPackage;
use sub_lib::logger::Logger;
use sub_lib::route::Route;
use sub_lib::proxy_client::ClientResponsePayload;
use sub_lib::proxy_server::ClientRequestPayload;
use sub_lib::cryptde_null::CryptDENull;
use sub_lib::cryptde::CryptDE;
use sub_lib::cryptde::PlainData;
use sub_lib::actor_messages::ResponseMessage;
use sub_lib::actor_messages::RequestMessage;
use sub_lib::actor_messages::IncipientCoresPackageMessage;
use sub_lib::actor_messages::ExpiredCoresPackageMessage;
use sub_lib::actor_messages::BindMessage;
use sub_lib::proxy_server::ProxyServerSubs;

use actix::Actor;
use actix::Context;
use actix::SyncAddress;
use actix::Handler;
use actix::Subscriber;

use host_name_finder;

pub struct ProxyServer {
    dispatcher: Option<Box<Subscriber<ResponseMessage> + Send>>,
    hopper: Option<Box<Subscriber<IncipientCoresPackageMessage> + Send>>,
    logger: Logger
}

impl Actor for ProxyServer {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for ProxyServer {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.dispatcher = Some(msg.peer_actors.dispatcher.from_proxy_server);
        self.hopper = Some(msg.peer_actors.hopper.from_hopper_client);
        ()
    }
}

impl Handler<RequestMessage> for ProxyServer {
    type Result = ();

    fn handle(&mut self, msg: RequestMessage, _ctx: &mut Self::Context) -> Self::Result {
        let cryptde = CryptDENull::new();
        let route = Route::rel2_from_proxy_server(&cryptde.public_key(), &cryptde).expect("Couldn't create route");
        if let (Endpoint::Socket(socket_addr), _component, data) = msg.data {
            let data = PlainData::new(&data[..]);
            if let Some (hostname) = host_name_finder::find_http_host_name (&data) {
                let payload = ClientRequestPayload {
                    stream_key: socket_addr,
                    data,
                    target_hostname: hostname,
                    target_port: 80, // TODO: This is a biiig assumption.
                    originator_public_key: cryptde.public_key (),
                };
                let pkg = IncipientCoresPackage::new(route, payload, &cryptde.public_key());
                let _ = self.hopper.as_ref().expect("Hopper unbound in ProxyServer").send(IncipientCoresPackageMessage { pkg });
            } else {
                // TODO: Add direct test of handle to drive out this unimplemented! ()
                unimplemented!()
            }
        } else {
            panic!("Not Endpoint::Socket(socket_addr)")
        }
        ()
    }
}

impl Handler<ExpiredCoresPackageMessage> for ProxyServer {
    type Result = ();

    fn handle(&mut self, msg: ExpiredCoresPackageMessage, _ctx: &mut Self::Context) -> Self::Result {
        let package: ExpiredCoresPackage = msg.pkg;
        match package.payload::<ClientResponsePayload>() {
            Ok(payload) => {
                self.logger.debug (format! ("Relaying {}-byte payload from Hopper to Dispatcher", payload.data.data.len ()));
                self.dispatcher.as_ref().expect("Dispatcher unbound in ProxyServer")
                    .send(ResponseMessage {
                        socket_addr: payload.stream_key,
                        data: payload.data.data.clone()
                    }).expect ("Proxy Client actor is dead");
                ()
            },
            Err(_) => panic!("ClientRequestPayload is not ok"),
        }
        ()
    }
}

impl ProxyServer {
    pub fn new() -> ProxyServer {
        ProxyServer {
            dispatcher: None,
            hopper: None,
            logger: Logger::new ("Proxy Server"),
        }
    }

    pub fn make_subs_from(addr: &SyncAddress<ProxyServer>) -> ProxyServerSubs {
        ProxyServerSubs {
            bind: addr.subscriber::<BindMessage>(),
            from_dispatcher: addr.subscriber::<RequestMessage>(),
            from_hopper: addr.subscriber::<ExpiredCoresPackageMessage>(),
            // from_neighborhood: addr.subscriber::<RouteResponseMessage>(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix::msgs;
    use actix::Arbiter;
    use std::str::FromStr;
    use sub_lib::hopper::IncipientCoresPackage;
    use sub_lib::hopper::ExpiredCoresPackage;
    use sub_lib::proxy_client::ClientResponsePayload;
    use sub_lib::test_utils::make_peer_actors_from;
    use sub_lib::test_utils::Recorder;

    #[test]
    fn proxy_server_receives_request_from_dispatcher_then_sends_cores_package_to_hopper() {
        let system = System::new("proxy_server_receives_request_from_dispatcher_then_sends_cores_package_to_hopper");
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let hopper_mock = Recorder::new();
        let hopper_log_arc = hopper_mock.get_recording();
        let hopper_awaiter = hopper_mock.get_awaiter();
        let subject = ProxyServer::new();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let expected_endpoint = Endpoint::Socket(socket_addr.clone());
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = RequestMessage { data: (expected_endpoint.clone(), Component::ProxyServer, expected_data.clone()) };
        let expected_http_request = PlainData::new(http_request);
        let cryptde = CryptDENull::new();
        let key = cryptde.public_key();
        let route = Route::rel2_from_proxy_server(&key, &cryptde).unwrap();
        let payload = ClientRequestPayload {
            stream_key: socket_addr.clone(),
            data: expected_http_request.clone(),
            target_hostname: String::from("nowhere.com"),
            target_port: 80,
            originator_public_key: key.clone()
        };
        let expected_pkg = IncipientCoresPackage::new(route.clone(), payload, &key);
        let subject_addr: SyncAddress<_> = subject.start();
        let mut peer_actors = make_peer_actors_from(None, None, Some(hopper_mock), None, None);
        peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
        subject_addr.send(BindMessage { peer_actors });

        subject_addr.send(msg_from_dispatcher);

        Arbiter::system().send(msgs::SystemExit(0));
        system.run();

        hopper_awaiter.await_message_count(1);
        let recording = hopper_log_arc.lock().unwrap();
        let record = recording.get_record::<IncipientCoresPackageMessage>(0);
        assert_eq!(record.pkg, expected_pkg);
    }

    #[test]
    fn proxy_server_receives_response_from_hopper() {
        let system = System::new("proxy_server_receives_response_from_hopper");
        let dispatcher_mock = Recorder::new();
        let dispatcher_log_arc = dispatcher_mock.get_recording();
        let dispatcher_awaiter = dispatcher_mock.get_awaiter();
        let subject = ProxyServer::new();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let cryptde = CryptDENull::new();
        let key = cryptde.public_key();
        let subject_addr: SyncAddress<_> = subject.start();
        let remaining_route = Route::rel2_to_proxy_server(&key, &cryptde).unwrap();
        let client_response_payload = ClientResponsePayload {
            stream_key: socket_addr.clone(),
            last_response: true,
            data: PlainData::new(b"data")
        };
        let incipient_cores_package = IncipientCoresPackage::new(remaining_route.clone(), client_response_payload, &key);
        let expired_cores_package_message = ExpiredCoresPackageMessage { pkg: ExpiredCoresPackage::new(remaining_route, incipient_cores_package.payload) };
        let mut peer_actors = make_peer_actors_from(None, Some(dispatcher_mock), None, None, None);
        peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
        subject_addr.send(BindMessage { peer_actors });

        subject_addr.send(expired_cores_package_message);

        Arbiter::system().send(msgs::SystemExit(0));
        system.run();

        dispatcher_awaiter.await_message_count(1);

        let recording = dispatcher_log_arc.lock().unwrap();
        let record = recording.get_record::<ResponseMessage>(0);
        assert_eq!(record.socket_addr, socket_addr);
        assert_eq!(record.data, b"data".to_vec());
    }
}
