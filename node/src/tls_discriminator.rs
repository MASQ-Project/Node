// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use sub_lib::dispatcher::Component;
use sub_lib::tls_framer::TlsFramer;
use discriminator::Discriminator;
use discriminator::DiscriminatorFactory;
use null_masquerader::NullMasquerader;

pub struct TlsDiscriminatorFactory {}

impl DiscriminatorFactory for TlsDiscriminatorFactory {
    fn make(&self) -> Box<Discriminator> {
        Box::new (Discriminator::new (
            Box::new (TlsFramer::new ()),
            vec! (Box::new (NullMasquerader::new (Component::ProxyServer)))
        ))
    }

    fn duplicate(&self) -> Box<DiscriminatorFactory> {
        Box::new (TlsDiscriminatorFactory{})
    }
}

impl TlsDiscriminatorFactory {
    pub fn new () -> TlsDiscriminatorFactory {
        TlsDiscriminatorFactory {}
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use discriminator::UnmaskedChunk;

    #[test]
    fn discriminator_factory_duplicate_works () {
        let subject = TlsDiscriminatorFactory::new ();

        subject.duplicate ();

        // no panic; test passes
    }

    #[test]
    fn factory_makes_discriminator_that_can_handle_null_masking_for_proxy_server () {
        let data: &[u8] = &[0x16, 0x03, 0x03, 0x00, 0x01, 0xCA];
        let subject = TlsDiscriminatorFactory::new ();

        let mut result = subject.make ();

        result.add_data (data);
        assert_eq! (result.take_chunk (), Some (UnmaskedChunk::new (Vec::from (data), Component::ProxyServer, true)));
    }
}
