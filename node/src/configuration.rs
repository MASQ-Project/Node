// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::collections::HashMap;
use discriminator::DiscriminatorFactory;
use http_request_start_finder::HttpRequestDiscriminatorFactory;
use tls_discriminator::TlsDiscriminatorFactory;

pub struct Configuration {
    port_discriminator_factories: HashMap<u16, Vec<Box<DiscriminatorFactory>>>
}

impl Configuration {
    pub fn new () -> Configuration {
        Configuration {
            port_discriminator_factories: HashMap::new ()
        }
    }

    pub fn establish (&mut self, _args: &Vec<String>) {
        self.port_discriminator_factories.insert (80,
            vec! (Box::new (HttpRequestDiscriminatorFactory::new ())));
        self.port_discriminator_factories.insert (443,
            vec! (Box::new (TlsDiscriminatorFactory::new ())));
    }

    pub fn ports (&self) -> Vec<u16> {
        self.port_discriminator_factories.keys ().map (|port_ref| {*port_ref}).collect ()
    }

    pub fn take_discriminator_factories_for (&mut self, port: u16) -> Vec<Box<DiscriminatorFactory>> {
        match self.port_discriminator_factories.remove (&port) {
            Some (factories) => factories,
            None => vec! ()
        }
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use sub_lib::dispatcher::Component;
    use discriminator::UnmaskedChunk;
    use test_utils::NullDiscriminatorFactory;

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
        assert_eq! (http_chunk, UnmaskedChunk::new (Vec::from ("GET http://url.com HTTP/1.1\r\n\r\n".as_bytes ()),
                                                    Component::ProxyServer, true));
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
        assert_eq! (tls_chunk, UnmaskedChunk::new (vec! (0x16, 0x03, 0x01, 0x00, 0x03, 0x01, 0x02, 0x03),
                                                   Component::ProxyServer, true));
    }

    #[test]
    fn ports_returns_list_of_ports () {
        let mut subject = Configuration::new ();
        let factory1 = NullDiscriminatorFactory::new ();
        let factory2 = NullDiscriminatorFactory::new ();
        let factory3 = NullDiscriminatorFactory::new ();
        subject.port_discriminator_factories.insert (1234, vec! (
            Box::new (factory1), Box::new (factory2)
        ));
        subject.port_discriminator_factories.insert (2345, vec! (
            Box::new (factory3)
        ));
        subject.port_discriminator_factories.insert (3456, vec! ());

        let ports = subject.ports ();

        assert_eq! (ports.contains (&1234), true);
        assert_eq! (ports.contains (&2345), true);
        assert_eq! (ports.contains (&3456), true);
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
