use std::env;
use std::io::Write;

use dusk_blindbidproof::MainFuture;

use chrono::Local;
use dusk_uds::UnixDomainSocket;
use env_logger::Builder;
use log::LevelFilter;

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

fn main() {
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

    let mut uds = env::temp_dir();
    uds.push("dusk-uds-blindbid");

    UnixDomainSocket::new(uds, None, MainFuture::default())
        .bind()
        .unwrap();
}
