use std::error::Error as StdError;
use std::fmt;

use bincode::Error as BincodeError;
use bulletproofs::r1cs::R1CSError;

macro_rules! from_error {
    ($t:ty, $id:ident) => {
        impl From<$t> for Error {
            fn from(e: $t) -> Self {
                Error::$id(e)
            }
        }
    };
}

#[derive(Debug)]
pub enum Error {
    Bincode(BincodeError),
    Other(String),
    R1CS(R1CSError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Bincode(e) => write!(f, "{}", e),
            Error::Other(s) => write!(f, "{}", s),
            Error::R1CS(e) => write!(f, "{}", e),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::Bincode(e) => Some(e),
            _ => None,
        }
    }
}

from_error!(BincodeError, Bincode);
from_error!(R1CSError, R1CS);
