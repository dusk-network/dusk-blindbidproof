#[macro_use]
extern crate lazy_static;

mod blindbid;
mod buffer;
mod gadgets;
mod pipe;

use buffer::BytesArray;
use curve25519_dalek::scalar::Scalar;
use pipe::NamedPipe;
use std::env;
use std::io::prelude::*;

fn main() -> std::io::Result<()> {
    let mut pipefile = env::temp_dir();
    pipefile.push("pipe-channel");

    println!("pipe: {:?}", pipefile);

    let mut pipe = NamedPipe::new(pipefile);

    println!("connecting...");
    pipe.connect();

    loop {
        let mut buf = Vec::new();
        println!("Waiting for content to read...");
        pipe.read_to_end(&mut buf)?;

        let buf_len = buf.len();
        println!("Read {} bytes.", &buf_len);

        let opcode = buf[0];

        println!("Opcode: {}", &opcode);

        if opcode == 1 {
            let ba: BytesArray = (&buf[1..buf_len - 1]).into();
            let mut bytes = ba.into_iter();
            let toggle = buf[buf_len - 1] as usize;

            println!("Calling PROVE");

            let result = prove(
                bytes.next().unwrap().into(), // d
                bytes.next().unwrap().into(), // k
                bytes.next().unwrap().into(), // y
                bytes.next().unwrap().into(), // y_inv
                bytes.next().unwrap().into(), // q
                bytes.next().unwrap().into(), // z_img
                bytes.next().unwrap().into(), // seed,
                bytes.next().unwrap().into(), // pub_list
                toggle,
            );

            let data: Vec<u8> = result.unwrap().into();

            println!("PROVE returned {} bytes", &data.len());

            pipe.write(&data)?;
        } else if opcode == 2 {
            let ba: BytesArray = (&buf[1..buf_len]).into();
            let mut bytes = ba.into_iter();

            println!("Calling VERIFY");

            let result = verify(
                bytes.next().unwrap().into(), // proof
                bytes.next().unwrap().into(), // seed
                bytes.next().unwrap().into(), // pub_list
                bytes.next().unwrap().into(), // q
                bytes.next().unwrap().into(), // z_img
            );

            pipe.write(&[result as u8])?;
        }
    }

    // Ok(())
}

fn prove(
    d: Scalar,
    k: Scalar,
    y: Scalar,
    y_inv: Scalar,
    q: Scalar,
    z_img: Scalar,
    seed: Scalar,
    pub_list: Vec<Scalar>,
    toggle: usize,
) -> Option<BytesArray> {
    match blindbid::prove(d, k, y, y_inv, q, z_img, seed, pub_list, toggle) {
        Ok((proof, commitments, t_c)) => {
            let mut bytes: BytesArray = BytesArray::new();

            bytes.push(proof.into());
            bytes.push(commitments.into());
            bytes.push(t_c.into());

            Some(bytes)
        }
        Err(_) => None,
    }
}

fn verify(
    bytes: BytesArray,
    seed: Scalar,
    pub_list: Vec<Scalar>,
    q: Scalar,
    z_img: Scalar,
) -> bool {
    let mut bytes = bytes.into_iter();

    let proof = bytes.next().unwrap();
    let commitments = bytes.next().unwrap();
    let t_c = bytes.next().unwrap();

    blindbid::verify(
        proof.into(),
        commitments.into(),
        t_c.into(),
        seed,
        pub_list,
        q,
        z_img,
    )
    .is_ok()
}
