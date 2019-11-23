#[macro_use]
extern crate log;

use std::convert::TryInto;

use blindbidproof::{blindbid, buffer, pipe, Proof};

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

            let result: Option<Vec<u8>> = blindbid::Proof::prove(
                bytes.next().unwrap().into(), // d
                bytes.next().unwrap().into(), // k
                bytes.next().unwrap().into(), // y
                bytes.next().unwrap().into(), // y_inv
                bytes.next().unwrap().into(), // q
                bytes.next().unwrap().into(), // z_img
                bytes.next().unwrap().into(), // seed,
                bytes.next().unwrap().into(), // pub_list
                toggle,
            )
            .and_then(|p| p.try_into())
            .ok();

            let data: Vec<u8> = result.unwrap().into();

            debug!("<proof> is: {} bytes", &data.len());
            trace!("{:?}", &data);
            info!("<< Write <proof> to named pipe.");
            pipe.write(&data)?;
        } else if opcode == 2 {
            let ba: buffer::BytesArray = (&buf[1..buf_len]).into();

            info!("Verify <proof>");

            let mut bytes = ba.into_iter();
            let bytes: buffer::BytesArray = bytes.next().unwrap().into();
            let mut bytes = bytes.into_iter();

            let proof = bytes.next().unwrap();
            let commitments = bytes.next().unwrap();
            let t_c = bytes.next().unwrap();

            let proof = Proof::new(proof.into(), commitments.into(), t_c.into());
            let seed = bytes.next().unwrap().into();
            let pub_list = bytes.next().unwrap().into();
            let q = bytes.next().unwrap().into();
            let z_img = bytes.next().unwrap().into();
            let result = proof.verify(seed, pub_list, q, z_img).is_ok();

            if result {
                info!("Succeed.");
            } else {
                info!("Failed.");
            }
            info!("<< Write <result> to named pipe.");

            pipe.write(&[result as u8])?;
        }
    }
}
