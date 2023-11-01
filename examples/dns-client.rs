use std::{env, io};

use log::LevelFilter;
use uwuhi::resolver::SyncResolver;

fn main() -> io::Result<()> {
    env_logger::Builder::new()
        .filter_module("uwuhi", LevelFilter::Trace)
        .filter_module(env!("CARGO_CRATE_NAME"), LevelFilter::Trace)
        .init();

    let domain = match env::args().skip(1).next() {
        Some(domain) => domain,
        None => "example.com".into(),
    };

    let mut client = SyncResolver::new("8.8.8.8:53".parse().unwrap())?;
    let ips = client.resolve(&domain)?;
    for ip in ips {
        println!("Received IP: {}", ip);
    }
    Ok(())
}
