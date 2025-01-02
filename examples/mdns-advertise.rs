use std::{env, process};
use std::{io, net::IpAddr};

use log::LevelFilter;
use uwuhi::name::Label;
use uwuhi::service::advertising::SyncAdvertiser;
use uwuhi::service::{InstanceDetails, ServiceInstance, ServiceTransport};

fn main() -> io::Result<()> {
    env_logger::Builder::new()
        .filter_module(env!("CARGO_PKG_NAME"), LevelFilter::Trace)
        .filter_module(env!("CARGO_CRATE_NAME"), LevelFilter::Trace)
        .init();

    let args = env::args().skip(1).collect::<Vec<_>>();
    let (service_name, transport) = match &*args {
        [] => ("_servicename".into(), ServiceTransport::TCP),
        [name] => {
            if let Some((service, transport)) = name.split_once('.') {
                if !service.starts_with('_') {
                    eprintln!("service name must start with `_`");
                    process::exit(1);
                }

                (service.to_string(), transport.parse()?)
            } else {
                let name = if name.starts_with('_') {
                    name.clone()
                } else {
                    format!("_{name}")
                };

                (name, ServiceTransport::TCP)
            }
        }
        _ => {
            eprintln!("usage: mdns-advertise [servicename]");
            process::exit(1);
        }
    };

    // FIXME: there doesn't seem to be a good way to find the default interface/IP address that 0.0.0.0 binds to
    let local_addrs = if_addrs::get_if_addrs()?
        .into_iter()
        .filter_map(|interface| match interface.ip() {
            IpAddr::V4(ip) if ip.is_private() => Some(ip),
            _ => None,
        })
        .collect::<Vec<_>>();

    let (&first_addr, more_addrs) = match &*local_addrs {
        [first, rest @ ..] => (first, rest),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "no local network interface with private IPv4 address found",
            ));
        }
    };

    let hostname: Label = "my_hostname".parse().unwrap();
    let mut advertiser = SyncAdvertiser::new(hostname.clone(), first_addr.into())?;
    for &addr in more_addrs {
        advertiser.add_name(hostname.clone(), addr.into());
    }
    advertiser.add_instance(
        ServiceInstance::new(
            "My Service Instance".parse().unwrap(),
            service_name.parse().unwrap(),
            transport,
        ),
        InstanceDetails::new("my_hostname.local".parse().unwrap(), 1234),
    );
    advertiser.listen_blocking()?;

    Ok(())
}
