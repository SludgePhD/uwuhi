use std::io;

use log::LevelFilter;
use uwuhi::resolver::Resolver;

fn main() -> io::Result<()> {
    // This one requires passing the hostname to resolve as an argument (there's
    // no default we could use).
    let hostname = std::env::args()
        .skip(1)
        .next()
        .expect("expected hostname to resolve");

    env_logger::Builder::new()
        .filter_module("uwuhi", LevelFilter::Trace)
        .filter_module(env!("CARGO_CRATE_NAME"), LevelFilter::Trace)
        .init();
    let mut client = Resolver::new_multicast_v4()?;
    let ips = client.resolve(&hostname)?;
    for ip in ips {
        println!("Received IP: {}", ip);
    }
    Ok(())
}
