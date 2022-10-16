use std::{io, net::IpAddr};

use log::LevelFilter;
use uwuhi::service::{InstanceDetails, ServiceAdvertiser, ServiceInstance, ServiceTransport};

fn main() -> io::Result<()> {
    env_logger::Builder::new()
        .filter_module("uwuhi", LevelFilter::Trace)
        .filter_module(env!("CARGO_CRATE_NAME"), LevelFilter::Trace)
        .init();

    // FIXME: there doesn't seem to be a good way to find the default interface/IP address that 0.0.0.0 binds to
    let local_addrs = if_addrs::get_if_addrs()?
        .into_iter()
        .filter_map(|interface| match interface.ip() {
            IpAddr::V4(ip) if ip.is_private() => Some(ip),
            _ => None,
        })
        .collect::<Vec<_>>();

    let addr = match &*local_addrs {
        [ip] => *ip,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!(
                    "need exactly one local address, found {}: {:?}",
                    local_addrs.len(),
                    local_addrs
                ),
            ))
        }
    };

    let mut advertiser = ServiceAdvertiser::new("my_hostname".parse().unwrap(), addr)?;
    advertiser.add_instance(
        ServiceInstance::new(
            "My Service Instance".parse().unwrap(),
            "_servicename".parse().unwrap(),
            ServiceTransport::TCP,
        ),
        InstanceDetails::new("my_hostname.local".parse().unwrap(), 1234),
    );
    advertiser.listen_blocking()?;

    Ok(())
}
