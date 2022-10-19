//! Performs mDNS service discovery on the local network.

use std::{io, ops::ControlFlow};

use log::LevelFilter;
use uwuhi::service::discovery::SyncDiscoverer;

fn main() -> io::Result<()> {
    env_logger::Builder::new()
        .filter_module("uwuhi", LevelFilter::Trace)
        .filter_module(env!("CARGO_CRATE_NAME"), LevelFilter::Trace)
        .init();

    let mut service_types = Vec::new();
    let mut browser = SyncDiscoverer::new_multicast_v4()?;
    browser.discover_service_types(|service| {
        service_types.push(service.clone());
        ControlFlow::Continue(())
    })?;

    let mut instances = Vec::new();
    for service in &service_types {
        browser.discover_instances(service, |instance| {
            instances.push(instance.clone());
            ControlFlow::Continue(())
        })?;
    }

    let mut details = Vec::new();
    for instance in &instances {
        details.push(browser.load_instance_details(instance));
    }

    println!();
    println!("Discovered {} service instances", instances.len());
    for (instance, details) in instances.iter().zip(&details) {
        println!("- {}", instance);
        match details {
            Ok(details) => {
                println!("  {}:{}", details.host(), details.port());
                if !details.txt_records().is_empty() {
                    println!("  {}", details.txt_records());
                }
            }
            Err(e) => println!("  error: {}", e),
        }
    }

    Ok(())
}
