use std::env;
use std::path::PathBuf;

use dusk_blindbidproof::MainFuture;

use clap::{App, Arg};
use dusk_uds::UnixDomainSocket;

const NAME: Option<&'static str> = option_env!("CARGO_PKG_NAME");
const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");
const AUTHORS: Option<&'static str> = option_env!("CARGO_PKG_AUTHORS");

fn main() {
    let mut uds = env::temp_dir();
    uds.push("dusk-uds-blindbid");
    let uds_default = uds.to_str().unwrap();

    let matches = App::new(NAME.unwrap())
        .version(VERSION.unwrap())
        .author(AUTHORS.unwrap())
        .arg(
            Arg::with_name("bind-path")
                .short("b")
                .long("bind-path")
                .value_name("BIND")
                .help("Bind path")
                .default_value(uds_default)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("log-level")
                .short("l")
                .long("log-level")
                .value_name("LOG")
                .possible_values(&["error", "warn", "info", "debug", "trace"])
                .default_value("info")
                .help("Output log level")
                .takes_value(true),
        )
        .get_matches();

    let level = matches
        .value_of("log-level")
        .expect("Failed parsing log-level arg");
    if env::var_os("RUST_LOG").is_none() {
        env::set_var("RUST_LOG", level);
    }
    env_logger::init();

    let uds = matches
        .value_of("bind-path")
        .expect("Failed parsing bind-path arg");
    let uds = PathBuf::from(String::from(uds));

    UnixDomainSocket::new(uds, None, MainFuture::default())
        .bind()
        .expect("Failed binding socket");
}
