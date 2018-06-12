// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use masquerader::Masquerader;
use discriminator::UnmaskedChunk;
use masquerader::MasqueradeError;

pub struct NullMasquerader {
}

impl Masquerader for NullMasquerader {
    fn try_unmask(&self, item: &[u8]) -> Option<UnmaskedChunk> {
        Some (UnmaskedChunk::new (Vec::from (item), true))
    }

    fn mask(&self, _data: &[u8]) -> Result<Vec<u8>, MasqueradeError> {
        unimplemented!()
    }
}

impl NullMasquerader {
    pub fn new () -> NullMasquerader {
        NullMasquerader {
        }
    }
}

#[cfg (test)]
mod tests {
    use super::*;

    #[test]
    fn try_unmask_returns_input_data_with_specified_component () {
        let data = "booga".as_bytes ();
        let subject = NullMasquerader::new ();

        let result = subject.try_unmask (data).unwrap ();

        assert_eq! (result, UnmaskedChunk::new (Vec::from (data), true));
    }
}
