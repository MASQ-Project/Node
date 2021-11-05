// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::discriminator::UnmaskedChunk;
use crate::masquerader::MasqueradeError;
use crate::masquerader::Masquerader;

pub struct NullMasquerader {}

impl Masquerader for NullMasquerader {
    fn try_unmask(&self, item: &[u8]) -> Result<UnmaskedChunk, MasqueradeError> {
        Ok(UnmaskedChunk::new(Vec::from(item), true, true))
    }

    fn mask(&self, data: &[u8]) -> Result<Vec<u8>, MasqueradeError> {
        Ok(Vec::from(data))
    }
}

impl NullMasquerader {
    pub fn new() -> NullMasquerader {
        NullMasquerader {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_unmask_returns_input_data_with_specified_clandestine_flag() {
        let data = "booga".as_bytes();
        let subject = NullMasquerader::new();

        let result = subject.try_unmask(data).unwrap();

        assert_eq!(result, UnmaskedChunk::new(Vec::from(data), true, true));
    }

    #[test]
    fn try_unmask_marks_chunk_as_needing_sequencing() {
        let data = "booga".as_bytes();
        let subject = NullMasquerader::new();

        let result = subject.try_unmask(data).unwrap();

        assert!(result.sequenced);
    }

    #[test]
    fn mask_returns_input_data() {
        let data = "booga".as_bytes();
        let subject = NullMasquerader::new();

        let result = subject.mask(data).unwrap();

        assert_eq!(result, Vec::from(data));
    }
}
