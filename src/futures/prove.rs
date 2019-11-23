use crate::{Error, Proof};

use std::future::Future;
use std::io::Read;
use std::pin::Pin;
use std::task::{Context, Poll};

pub struct ProveFuture<R: Read> {
    reader: R,
}

impl<R: Read> ProveFuture<R> {
    pub fn new(reader: R) -> Self {
        ProveFuture { reader }
    }
}

impl<R: Read> Future for ProveFuture<R> {
    type Output = Result<Proof, Error>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Self::Output> {
        unsafe {
            let f = self.get_unchecked_mut();
            Poll::Ready(Proof::try_from_reader_variables(&mut f.reader))
        }
    }
}
