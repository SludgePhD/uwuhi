//! Listens for mDNS packets and dumps them.

use std::io;

use log::LevelFilter;
use uwuhi::tap::SyncTap;

fn main() -> io::Result<()> {
    env_logger::Builder::new()
        .filter_module("uwuhi", LevelFilter::Trace)
        .filter_module(env!("CARGO_CRATE_NAME"), LevelFilter::Trace)
        .init();
    SyncTap::new()?.listen()?;
    Ok(())
}
