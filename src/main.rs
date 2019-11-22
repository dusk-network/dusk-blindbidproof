#[macro_use]
extern crate log;

use blindbidproof::{blindbid, buffer, pipe};
use curve25519_dalek::scalar::Scalar;
use pipe::NamedPipe;
use std::env;
use std::io::prelude::*;

extern crate chrono;
extern crate env_logger;

use chrono::Local;
use env_logger::Builder;
use log::LevelFilter;
use std::io::Write;

fn get_log_level() -> LevelFilter {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        return LevelFilter::Info;
    }
    let flag: &str = &args[1];

    match flag {
        "-t" => LevelFilter::Trace,
        "-d" => LevelFilter::Debug,
        _ => LevelFilter::Info,
    }
}

fn main() -> std::io::Result<()> {
    Builder::new()
        .format(|buf, record| {
            writeln!(
                buf,
                "{} [{}] - {}",
                Local::now().format("%Y-%m-%dT%H:%M:%S"),
                record.level(),
                record.args()
            )
        })
        .filter(None, get_log_level())
        .init();

    let mut pipefile = env::temp_dir();
    pipefile.push("pipe-channel");

    let mut pipe = NamedPipe::new(pipefile);
    pipe.connect();

    loop {
        let mut buf = Vec::new();
        info!("\nWaiting for content to read...\n");
        pipe.read_to_end(&mut buf)?;

        let buf_len = buf.len();
        info!(">> Read {} bytes.", &buf_len);
        trace!("{:?}", &buf);

        let opcode = buf[0];

        debug!("Opcode: {}", &opcode);

        if opcode == 1 {
            let ba: buffer::BytesArray = (&buf[1..buf_len - 1]).into();
            let mut bytes = ba.into_iter();
            let toggle = buf[buf_len - 1] as usize;

            info!("Generating <proof>");

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

            debug!("<proof> is: {} bytes", &data.len());
            trace!("{:?}", &data);
            info!("<< Write <proof> to named pipe.");
            pipe.write(&data)?;
        } else if opcode == 2 {
            let ba: buffer::BytesArray = (&buf[1..buf_len]).into();

            info!("Verify <proof>");

            let mut bytes = ba.into_iter();

            let result = verify(
                bytes.next().unwrap().into(), // proof
                bytes.next().unwrap().into(), // seed
                bytes.next().unwrap().into(), // pub_list
                bytes.next().unwrap().into(), // q
                bytes.next().unwrap().into(), // z_img
            );

            if result {
                info!("Succeed.");
            } else {
                info!("Failed.");
            }
            info!("<< Write <result> to named pipe.");

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
) -> Option<buffer::BytesArray> {
    match blindbid::prove(d, k, y, y_inv, q, z_img, seed, pub_list, toggle) {
        Ok((proof, commitments, t_c)) => {
            let mut bytes: buffer::BytesArray = buffer::BytesArray::new();

            bytes.push(proof.into());
            bytes.push(commitments.into());
            bytes.push(t_c.into());

            Some(bytes)
        }
        Err(_) => None,
    }
}

fn verify(
    bytes: buffer::BytesArray,
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
