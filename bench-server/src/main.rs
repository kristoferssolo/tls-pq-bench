//! TLS benchmark server.
//!
//! Listens for TLS connections and serves the benchmark protocol:
//! - Reads 8-byte little-endian u64 (requested payload size N)
//! - Responds with exactly N bytes (deterministic pattern)

use bench_common::KeyExchangeMode;
use clap::Parser;
use std::net::SocketAddr;

/// TLS benchmark server.
#[derive(Debug, Parser)]
#[command(name = "bench-server", version, about)]
struct Args {
    /// Key exchange mode.
    #[arg(long, default_value = "x25519")]
    mode: KeyExchangeMode,

    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:4433")]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> miette::Result<()> {
    let args = Args::parse();

    eprintln!("bench-server configuration:");
    eprintln!("  mode:   {}", args.mode);
    eprintln!("  listen: {}", args.listen);

    // TODO: Implement TLS server
    eprintln!("\nServer not yet implemented.");

    Ok(())
}
