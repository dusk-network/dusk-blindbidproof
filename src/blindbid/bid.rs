use crate::Error;

use std::cmp;
use std::io::Read;

use curve25519_dalek::scalar::Scalar;
use dusk_tlv::TlvReader;

#[derive(Debug, Clone, Default)]
pub struct Bid {
    pub x: Scalar,
}

impl Bid {
    pub fn try_list_from_reader<R: Read>(reader: R) -> Result<Vec<Bid>, Error> {
        Ok(TlvReader::new(reader).read_list()?)
    }
}

impl From<Vec<u8>> for Bid {
    fn from(bytes: Vec<u8>) -> Self {
        let mut s = [0x00u8; 32];

        s.copy_from_slice(&bytes.as_slice()[..cmp::max(bytes.len(), 32)]);

        Bid {
            x: Scalar::from_bits(s),
        }
    }
}
