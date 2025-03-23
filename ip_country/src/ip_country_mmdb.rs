use crate::ip_country::DBIPParser;
use std::io;
use std::any::Any;
use crate::country_block_serde::{CountryBlockSerializer, FinalBitQueue};

pub struct MMDBParser {}

impl DBIPParser for MMDBParser {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn parse(
        &self,
        stdin: &mut dyn io::Read,
        errors: &mut Vec<String>,
    ) -> (FinalBitQueue, FinalBitQueue, Option<Vec<(String, String)>>) {
        todo!()
    }
}

#[cfg(test)]
mod tests {


}