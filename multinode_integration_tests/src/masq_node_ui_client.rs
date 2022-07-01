use std::cell::{RefCell, RefMut};
use std::io::ErrorKind;
use std::net::{SocketAddr, TcpStream};
use std::ops::Add;
use std::thread;
use std::time::{Duration, SystemTime};

use websocket::sync::Client;
use websocket::{ClientBuilder, OwnedMessage, WebSocketError};

use masq_lib::messages::NODE_UI_PROTOCOL;
use masq_lib::ui_gateway::{MessageBody, MessagePath};
use masq_lib::ui_traffic_converter::UiTrafficConverter;
use masq_lib::utils::plus;

pub struct MASQNodeUIClient {
    inner: RefCell<MASQNodeUIClientInner>,
}

struct MASQNodeUIClientInner {
    client: Client<TcpStream>,
    buffer: Vec<MessageBody>,
}

impl MASQNodeUIClient {
    pub fn new(addr: SocketAddr) -> Self {
        let url = format!("ws://{}", addr);
        let client = match ClientBuilder::new(url.as_str())
            .expect("Bad URL")
            .add_protocol(NODE_UI_PROTOCOL)
            .connect_insecure()
        {
            Ok(client) => client,
            Err(e) => {
                let msg = format!("Couldn't build client for {}: {:?}", url, e);
                panic!("{}", msg);
            }
        };
        Self {
            inner: RefCell::new(MASQNodeUIClientInner {
                client,
                buffer: vec![],
            }),
        }
    }

    pub fn send_request(&self, msg: MessageBody) {
        let mut inner = self.inner.borrow_mut();
        let json = UiTrafficConverter::new_marshal(msg);
        inner
            .client
            .send_message(&OwnedMessage::Text(json))
            .unwrap();
    }

    pub fn wait_for_response(&self, context_id: u64, timeout: Duration) -> MessageBody {
        self.buffered_or_incoming(MessagePath::Conversation(context_id), timeout)
    }

    pub fn wait_for_broadcast(&self, timeout: Duration) -> MessageBody {
        self.buffered_or_incoming(MessagePath::FireAndForget, timeout)
    }

    fn buffered_or_incoming(&self, path: MessagePath, timeout: Duration) -> MessageBody {
        if let Some(target) = self.check_for_buffered_message(path) {
            return target;
        }
        self.wait_for_message(path, timeout)
    }

    fn wait_for_message(&self, path: MessagePath, timeout: Duration) -> MessageBody {
        let mut inner = self.inner.borrow_mut();
        let mut target_opt = None;
        let deadline = SystemTime::now().add(timeout);
        loop {
            match self.check_for_waiting_message(&mut inner) {
                Some(message) => {
                    if message.path == path {
                        target_opt = Some(message)
                    } else {
                        inner.buffer.push(message)
                    }
                }
                None => {
                    if let Some(target) = target_opt {
                        return target;
                    } else {
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            }
            if SystemTime::now().ge(&deadline) {
                panic!("Timeout waiting for UI message from Node: {:?}", path);
            }
        }
    }

    fn check_for_buffered_message(&self, path: MessagePath) -> Option<MessageBody> {
        let mut inner = self.inner.borrow_mut();
        let (target_opt, new_buffer) =
            inner.buffer.drain(..).fold((None, vec![]), |so_far, msg| {
                if msg.path == path {
                    (Some(msg), so_far.1)
                } else {
                    (so_far.0, plus(so_far.1, msg))
                }
            });
        inner.buffer = new_buffer;
        target_opt
    }

    fn check_for_waiting_message(
        &self,
        inner: &mut RefMut<MASQNodeUIClientInner>,
    ) -> Option<MessageBody> {
        inner.client.set_nonblocking(true).unwrap();
        match inner.client.recv_message() {
            Ok(message) => match message {
                OwnedMessage::Text(string) => {
                    Some(UiTrafficConverter::new_unmarshal(&string).unwrap())
                }
                OwnedMessage::Close(_) => {
                    panic!("Close message unexpected");
                }
                unexpected => {
                    panic!("Unexpected message: {:?}", unexpected);
                }
            },
            Err(WebSocketError::NoDataAvailable) => None,
            Err(WebSocketError::IoError(e)) if e.kind() == ErrorKind::WouldBlock => None,
            Err(WebSocketError::IoError(e)) if e.kind() == ErrorKind::TimedOut => None,
            Err(e) => {
                panic!("{:?}", e)
            }
        }
    }
}
