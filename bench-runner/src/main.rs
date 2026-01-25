//! TLS benchmark runner (client).
//!
//! Connects to a benchmark server, performs the protocol, and measures:
//! - Handshake latency
//! - Time-to-last-byte (TTLB)
//!
//! Outputs NDJSON records to stdout or a file.

use bench_common::KeyExchangeMode;
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;

/// TLS benchmark runner.
#[derive(Debug, Parser)]
#[command(name = "bench-runner", version, about)]
struct Args {
    /// Key exchange mode.
    #[arg(long, default_value = "x25519")]
    mode: KeyExchangeMode,

    /// Server address to connect to.
    #[arg(long)]
    server: SocketAddr,

    /// Payload size in bytes to request from server.
    #[arg(long, default_value = "1024")]
    payload_bytes: u64,

    /// Number of benchmark iterations (excluding warmup).
    #[arg(long, default_value = "100")]
    iters: u64,

    /// Number of warmup iterations (not recorded).
    #[arg(long, default_value = "10")]
    warmup: u64,

    /// Number of concurrent connections.
    #[arg(long, default_value = "1")]
    concurrency: u64,

    /// Output file for NDJSON records (stdout if not specified).
    #[arg(long)]
    out: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> miette::Result<()> {
    let args = Args::parse();

    eprintln!("bench-runner configuration:");
    eprintln!("  mode:          {}", args.mode);
    eprintln!("  server:        {}", args.server);
    eprintln!("  payload_bytes: {}", args.payload_bytes);
    eprintln!("  iters:         {}", args.iters);
    eprintln!("  warmup:        {}", args.warmup);
    eprintln!("  concurrency:   {}", args.concurrency);
    eprintln!(
        "  out:           {}",
        args.out
            .as_ref()
            .map_or_else(|| "stdout".to_string(), |p| p.display().to_string())
    );

    // TODO: Implement TLS client and benchmark loop
    eprintln!("\nRunner not yet implemented.");

    Ok(())
}
