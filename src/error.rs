use std::error::Error as StdError;
use std::fmt;
use std::io::{self, Error as IoError};

use bulletproofs::r1cs::R1CSError;
use dusk_tlv::Error as TlvError;

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
    Io(IoError),
    Other(String),
    R1CS(R1CSError),
    Tlv(TlvError),
    UnexpectedEof,
}

impl Error {
    pub fn io_unexpected_eof<S: ToString>(description: S) -> Self {
        let description = description.to_string();
        Error::Io(io::Error::new(io::ErrorKind::UnexpectedEof, description))
    }

    pub fn io_invalid_data<S: ToString>(description: S) -> Self {
        let description = description.to_string();
        Error::Io(io::Error::new(io::ErrorKind::InvalidData, description))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{}", e),
            Error::Other(s) => write!(f, "{}", s),
            Error::R1CS(e) => write!(f, "{}", e),
            Error::Tlv(e) => write!(f, "{}", e),
            Error::UnexpectedEof => write!(f, "Unexpected end of file"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Tlv(e) => Some(e),
            _ => None,
        }
    }
}

from_error!(IoError, Io);
from_error!(R1CSError, R1CS);
from_error!(TlvError, Tlv);
