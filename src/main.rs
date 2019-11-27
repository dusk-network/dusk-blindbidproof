use std::env;

use dusk_blindbidproof::MainFuture;

use dusk_uds::UnixDomainSocket;

fn main() {
    if env::var_os("RUST_LOG").is_none() {
        env::set_var("RUST_LOG", "info");
    }
    env_logger::init();

    let mut uds = env::temp_dir();
    uds.push("dusk-uds-blindbid");

    UnixDomainSocket::new(uds, None, MainFuture::default())
        .bind()
        .unwrap();
}
