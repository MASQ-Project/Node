use sub_lib::proxy_server::ProxyProtocol;
use sub_lib::cryptde::PlainData;

pub trait ProtocolPack {
    fn proxy_protocol (&self) -> ProxyProtocol;
    fn find_host_name (&self, data: &PlainData) -> Option<String>;
}
