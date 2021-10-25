// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::discriminator::Discriminator;
use crate::discriminator::DiscriminatorFactory;
use crate::null_masquerader::NullMasquerader;
use crate::sub_lib::tls_framer::TlsFramer;

#[derive(Debug, Default)]
pub struct TlsDiscriminatorFactory {}

impl DiscriminatorFactory for TlsDiscriminatorFactory {
    fn make(&self) -> Discriminator {
        Discriminator::new(
            Box::new(TlsFramer::new()),
            vec![Box::new(NullMasquerader::new())],
        )
    }

    fn duplicate(&self) -> Box<dyn DiscriminatorFactory> {
        Box::new(TlsDiscriminatorFactory {})
    }
}

impl TlsDiscriminatorFactory {
    pub fn new() -> TlsDiscriminatorFactory {
        Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discriminator::UnmaskedChunk;

    #[test]
    fn discriminator_factory_duplicate_works() {
        let subject = TlsDiscriminatorFactory::new();

        subject.duplicate();

        // no panic; test passes
    }

    #[test]
    fn factory_makes_discriminator_that_can_handle_null_masking_for_proxy_server() {
        let data: &[u8] = &[0x16, 0x03, 0x03, 0x00, 0x01, 0xCA];
        let subject = TlsDiscriminatorFactory::new();

        let mut result = subject.make();

        result.add_data(data);
        assert_eq!(
            result.take_chunk(),
            Some(UnmaskedChunk::new(Vec::from(data), true, true))
        );
    }
}
