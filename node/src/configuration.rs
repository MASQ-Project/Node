// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::collections::HashMap;
use discriminator::DiscriminatorFactory;
use http_request_start_finder::HttpRequestDiscriminatorFactory;
use tls_discriminator_factory::TlsDiscriminatorFactory;
use std::net::UdpSocket;
use std::net::SocketAddr;
use std::net::Ipv4Addr;
use std::net::IpAddr;
use json_discriminator_factory::JsonDiscriminatorFactory;
use sub_lib::parameter_finder::ParameterFinder;

pub struct Configuration {
    port_discriminator_factories: HashMap<u16, Vec<Box<DiscriminatorFactory>>>
}

impl Configuration {
    pub fn new () -> Configuration {
        Configuration {
            port_discriminator_factories: HashMap::new ()
        }
    }

    pub fn establish (&mut self, args: &Vec<String>) {
        self.port_discriminator_factories.insert (80,
            vec! (Box::new (HttpRequestDiscriminatorFactory::new ())));
        self.port_discriminator_factories.insert (443,
            vec! (Box::new (TlsDiscriminatorFactory::new ())));
        let port_count = Configuration::parse_port_count (&ParameterFinder::new (args.clone ()));
        for _i in 0..port_count {
            let port = Configuration::find_free_port ();
            self.port_discriminator_factories.insert (port,
                vec! (Box::new (JsonDiscriminatorFactory::new ())));
        }
    }

    pub fn all_ports(&self) -> Vec<u16> {
        self.port_discriminator_factories.keys ().map (|port_ref| {*port_ref}).collect ()
    }

    pub fn clandestine_ports (&self) -> Vec<u16> {
        self.all_ports ().into_iter ().filter (|port| (*port != 80) && (*port != 443)).collect ()
    }

    pub fn take_discriminator_factories_for (&mut self, port: u16) -> Vec<Box<DiscriminatorFactory>> {
        match self.port_discriminator_factories.remove (&port) {
            Some (factories) => factories,
            None => vec! ()
        }
    }

    fn find_free_port () -> u16 {
        let socket = UdpSocket::bind (SocketAddr::new (IpAddr::V4 (Ipv4Addr::new (127, 0, 0, 1)), 0)).expect ("Not enough free ports");
        socket.local_addr ().expect ("Bind failed").port ()
    }

    fn parse_port_count (finder: &ParameterFinder) -> usize {
        let usage = "--port_count <number of clandestine ports to open, default = 1>";
        match finder.find_value_for ("--port_count", usage) {
            None => 1, // TODO: This should be 0, not 1
            Some (ref port_count_str) => match port_count_str.parse::<usize> () {
                Ok (port_count) => port_count,
                Err (_) => panic! ("--port_count <clandestine port count> needs a number, not '{}'", port_count_str)
            }
        }
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use discriminator::UnmaskedChunk;
    use node_test_utils::NullDiscriminatorFactory;

    #[test]
    fn find_free_port_works_ten_times () {
        let ports: Vec<u16> = (0u16..10u16).map (|_| Configuration::find_free_port ()).collect ();
        for i in 0..10 {
            for j in (i + 1)..10 {
                assert_ne! (ports[i], ports[j], "Port #{} is the same as port #{}: {}!", i, j, ports[i]);
            }
        }
    }

    #[test]
    fn no_parameters_produces_configuration_for_80 () {
        let args = vec! (String::from ("command"));
        let mut subject = Configuration::new ();

        subject.establish (&args);

        let mut port_80_factories = subject.port_discriminator_factories.remove (&80).unwrap ();
        assert_eq! (port_80_factories.len (), 1);
        let http_factory = port_80_factories.remove (0);
        let mut http_discriminator = http_factory.make ();
        http_discriminator.add_data ("GET http://url.com HTTP/1.1\r\n\r\n".as_bytes ());
        let http_chunk = http_discriminator.take_chunk ().unwrap ();
        assert_eq! (http_chunk, UnmaskedChunk::new (Vec::from ("GET http://url.com HTTP/1.1\r\n\r\n".as_bytes ()), true));
    }

    #[test]
    fn no_parameters_produces_configuration_for_443 () {
        let args = vec! (String::from ("command"));
        let mut subject = Configuration::new ();

        subject.establish (&args);

        let mut port_443_factories = subject.port_discriminator_factories.remove (&443).unwrap ();
        assert_eq! (port_443_factories.len (), 1);
        let tls_factory = port_443_factories.remove (0);
        let mut tls_discriminator = tls_factory.make ();
        tls_discriminator.add_data (&vec! (0x16, 0x03, 0x01, 0x00, 0x03, 0x01, 0x02, 0x03)[..]);
        let tls_chunk = tls_discriminator.take_chunk ().unwrap ();
        assert_eq! (tls_chunk, UnmaskedChunk::new (vec! (0x16, 0x03, 0x01, 0x00, 0x03, 0x01, 0x02, 0x03), true));
    }

    #[test]
    fn no_parameters_produces_configuration_with_one_high_port () {
        let args = vec! (String::from ("command"));
        let mut subject = Configuration::new ();

        subject.establish (&args);

        assert_eq! (subject.clandestine_ports().len (), 1);
        let high_port = subject.clandestine_ports ()[0];
        let mut high_port_factories = subject.port_discriminator_factories.remove (&high_port).unwrap ();
        assert_eq! (high_port_factories.len (), 1);
        let json_factory = high_port_factories.remove (0);
        let mut json_discriminator = json_factory.make ();
        json_discriminator.add_data (&b"{\"component\": \"NBHD\", \"bodyText\": \"booga\"}"[..]);
        let json_chunk = json_discriminator.take_chunk ().unwrap ();
        assert_eq! (json_chunk, UnmaskedChunk::new (b"booga".to_vec (), true));
    }

    #[test]
    fn port_count_produces_configuration_with_proper_number_of_high_ports () {
        let args = vec! (String::from ("command"), String::from ("--port_count"), String::from ("5"));
        let mut subject = Configuration::new ();

        subject.establish (&args);

        subject.port_discriminator_factories.remove (&80);
        subject.port_discriminator_factories.remove (&443);
        assert_eq! (subject.all_ports().len (), 5);
        subject.all_ports().into_iter ().for_each (|high_port| {
            let mut high_port_factories = subject.port_discriminator_factories.remove (&high_port).unwrap ();
            assert_eq! (high_port_factories.len (), 1);
            let json_factory = high_port_factories.remove (0);
            let mut json_discriminator = json_factory.make ();
            json_discriminator.add_data (&b"{\"component\": \"NBHD\", \"bodyText\": \"booga\"}"[..]);
            let json_chunk = json_discriminator.take_chunk ().unwrap ();
            assert_eq! (json_chunk, UnmaskedChunk::new (b"booga".to_vec (), true));
        });
    }

    #[test]
    #[should_panic (expected = "--port_count <clandestine port count> needs a number, not 'booga'")]
    fn parse_port_count_rejects_badly_formatted_port_count () {
        let args = vec! (String::from ("command"), String::from ("--port_count"), String::from ("booga"));
        let finder = ParameterFinder::new (args);

        Configuration::parse_port_count (&finder);
    }

    #[test]
    fn all_ports_returns_list_of_all_ports () {
        let mut subject = Configuration::new ();
        let factory1 = NullDiscriminatorFactory::new ();
        let factory2 = NullDiscriminatorFactory::new ();
        let factory3 = NullDiscriminatorFactory::new ();
        subject.port_discriminator_factories.insert (80, vec! (
            Box::new (factory1), Box::new (factory2)
        ));
        subject.port_discriminator_factories.insert (443, vec! (
            Box::new (factory3)
        ));
        subject.port_discriminator_factories.insert (3456, vec! ());

        let ports = subject.all_ports();

        assert_eq! (ports.contains (&80), true);
        assert_eq! (ports.contains (&443), true);
        assert_eq! (ports.contains (&3456), true);
        assert_eq! (ports.len (), 3);
    }

    #[test]
    fn clandestine_ports_returns_only_clandestine_ports () {
        let mut subject = Configuration::new ();
        let factory1 = NullDiscriminatorFactory::new ();
        let factory2 = NullDiscriminatorFactory::new ();
        let factory3 = NullDiscriminatorFactory::new ();
        subject.port_discriminator_factories.insert (80, vec! (
            Box::new (factory1), Box::new (factory2)
        ));
        subject.port_discriminator_factories.insert (443, vec! (
            Box::new (factory3)
        ));
        subject.port_discriminator_factories.insert (3456, vec! ());

        let ports = subject.clandestine_ports();

        assert_eq! (ports.contains (&3456), true);
        assert_eq! (ports.len (), 1);
    }

    #[test]
    fn take_discriminator_factories_for_removes_factories () {
        let mut subject = Configuration::new ();
        let factory1 = NullDiscriminatorFactory::new ();
        let factory2 = NullDiscriminatorFactory::new ();
        subject.port_discriminator_factories.insert (1234, vec! (
            Box::new (factory1), Box::new (factory2)
        ));

        let factories = subject.take_discriminator_factories_for (1234);

        assert_eq! (factories.len (), 2);

        let factories = subject.take_discriminator_factories_for (1234);

        assert_eq! (factories.len (), 0);
    }
}
