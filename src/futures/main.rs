use super::prove::ProveFuture;
use super::verify::VerifyFuture;
use crate::Error;

use std::convert::TryInto;
use std::future::Future;
use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::pin::Pin;
use std::task::{Context, Poll};

use dusk_tlv::{TlvReader, TlvWriter};
use dusk_uds::{Message, TaskProvider};

macro_rules! try_result_future {
    ($e:expr) => {
        match $e {
            Ok(a) => a,
            Err(e) => {
                error!("Error resolving the request: {}", e);
                return Poll::Ready(Message::Error);
            }
        }
    };
}

macro_rules! try_poll {
    ($e:expr, $c:expr) => {
        match Pin::new(&mut $e).poll($c) {
            Poll::Ready(a) => {
                trace!("Request resolved");
                a
            }
            Poll::Pending => {
                trace!("Pending request discarded");
                return Poll::Pending;
            }
        }
    };
}

pub struct MainFuture {
    socket: Option<UnixStream>,
}

impl Default for MainFuture {
    fn default() -> Self {
        MainFuture { socket: None }
    }
}

impl Clone for MainFuture {
    fn clone(&self) -> Self {
        MainFuture::default()
    }
}

impl TaskProvider for MainFuture {
    fn set_socket(&mut self, socket: UnixStream) {
        self.socket.replace(socket);
    }
}

impl Future for MainFuture {
    type Output = Message;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        match &mut self.socket {
            Some(s) => {
                let mut reader = TlvReader::new(s);
                // Fetch the full request
                let request = reader.next().transpose();
                let request = try_result_future!(request);
                let request = request.ok_or(Error::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "The request was not provided",
                )));
                let request = try_result_future!(request);
                let s = reader.into_inner();

                let opcode = request[0];

                // Proof
                if opcode == 1 {
                    let proof = try_poll!(ProveFuture::new(&request[1..]), cx);
                    let proof = try_result_future!(proof);
                    let proof: Vec<u8> = try_result_future!(proof.try_into());

                    let mut writer = TlvWriter::new(s);
                    try_result_future!(writer.write(proof.as_slice()));

                    Poll::Ready(Message::Success)
                // Verify
                } else if opcode == 2 {
                    let verify = try_poll!(VerifyFuture::new(&request[1..]), cx).is_ok();
                    let verify = if verify { 0x01u8 } else { 0x00u8 };

                    let mut writer = TlvWriter::new(s);
                    try_result_future!(writer.write(&[verify]));

                    Poll::Ready(Message::Success)
                // Undefined operation
                } else {
                    try_result_future!(Err(Error::Other("Undefined operation code".to_owned())))
                }
            }

            None => try_result_future!(Err(Error::Other("No socket provided".to_owned()))),
        }
    }
}
