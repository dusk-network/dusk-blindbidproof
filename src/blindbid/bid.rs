use crate::Error;

use std::convert::TryFrom;
use std::io::Read;

use curve25519_dalek::scalar::Scalar;
use dusk_tlv::{Error as TlvError, TlvReader};
use serde::Deserialize;

#[derive(Debug, Clone, Default)]
pub struct Bid {
    pub x: Scalar,
    pub m: Scalar,
    pub end_height: u64,
}

impl Bid {
    pub fn try_list_from_reader<R: Read>(reader: R) -> Result<Vec<Bid>, Error> {
        Ok(TlvReader::new(reader).try_read_list()?)
    }
}

impl TryFrom<Vec<u8>> for Bid {
    type Error = TlvError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, TlvError> {
        let mut reader = TlvReader::new(bytes.as_slice());

        let x = Deserialize::deserialize(&mut reader)?;
        let m = Deserialize::deserialize(&mut reader)?;
        let end_height = Deserialize::deserialize(&mut reader)?;

        Ok(Bid { x, m, end_height })
    }
}
