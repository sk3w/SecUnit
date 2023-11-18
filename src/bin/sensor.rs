use clap::Parser;
use ndisapi::{AsyncNdisapiAdapter, Ndisapi};
use secunit::monitor;
use std::sync::Arc;
use windows::core::Result;

/// A struct representing the command line arguments.
#[derive(Parser)]
struct Cli {
    /// Network interface index (please use listadapters example to determine the right one)
    #[arg(short, long, group = "interface")]
    interface_index: usize,
    // /// Network interface MAC address
    // #[arg(short = 'm', long, group = "interface")]
    // interface_mac: String,
}

// fn parse_mac(arg: &str) -> std::result::Result<MacAddress, _> {
//     let mut bytes = [0u8; 6];
//     for b in bytes.iter_mut() {
//         b = u8::try_from(arg[])
//     }
//     Ok(mac)
// }

// The main function of the program.
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let Cli {
        mut interface_index,
        // mut interface_mac,
    } = Cli::parse();

    // Decrement interface index to match zero-based index.
    interface_index -= 1;

    // Create a new Ndisapi driver instance.
    let driver = Arc::new(
        Ndisapi::new("NDISRD").expect("WinpkFilter driver is not installed or failed to load!"),
    );

    // Print the detected version of the Windows Packet Filter.
    println!(
        "Detected Windows Packet Filter version {}",
        driver.get_version()?
    );

    // Get a list of TCP/IP bound adapters in the system.
    let adapters = driver.get_tcpip_bound_adapters_info()?;

    // Check if the selected interface index is within the range of available interfaces.
    if interface_index + 1 > adapters.len() {
        panic!("Interface index is beyond the number of available interfaces");
    }

    // Print the name of the selected interface.
    println!("Using interface {}", adapters[interface_index].get_name(),);

    // Create a new instance of AsyncNdisapiAdapter with the selected interface.
    let mut adapter =
        AsyncNdisapiAdapter::new(Arc::clone(&driver), adapters[interface_index].get_handle())
            .unwrap();

    // Execute the main_async function using the previously defined adapter.
    monitor(&mut adapter).await?;
    Ok(())
}
