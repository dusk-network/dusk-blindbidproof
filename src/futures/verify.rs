use crate::{Error, Verify};

use std::future::Future;
use std::io::Read;
use std::pin::Pin;
use std::task::{Context, Poll};

pub struct VerifyFuture<R: Read> {
    reader: R,
}

impl<R: Read> VerifyFuture<R> {
    pub fn new(reader: R) -> Self {
        VerifyFuture { reader }
    }
}

impl<R: Read> Future for VerifyFuture<R> {
    type Output = Result<(), Error>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Self::Output> {
        unsafe {
            let f = self.get_unchecked_mut();
            Poll::Ready(Verify::try_from_reader_variables(&mut f.reader).and_then(|v| v.verify()))
        }
    }
}
