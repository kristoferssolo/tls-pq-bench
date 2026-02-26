use clap::Parser;
use common::prelude::*;
use std::{net::SocketAddr, path::PathBuf};

/// TLS benchmark runner.
#[derive(Debug, Parser)]
#[command(name = "runner", version, about)]
pub struct Args {
    /// Key exchange mode.
    #[arg(long, default_value = "x25519")]
    pub mode: KeyExchangeMode,

    /// Server address to connect to
    #[arg(long, required_unless_present = "config")]
    pub server: Option<SocketAddr>,

    /// Payload size in bytes to request from server
    #[arg(long, default_value = "1024")]
    pub payload_bytes: u32,

    /// Number of benchmark iterations (excluding warmup)
    #[arg(long, default_value = "100")]
    pub iters: u32,

    /// Number of warmup iterations (not recorded)
    #[arg(long, default_value = "10")]
    pub warmup: u32,

    /// Number of concurrent connections
    #[arg(long, default_value = "1")]
    pub concurrency: u32,

    /// Output file for NDJSON records (stdout if not specified)
    #[arg(long)]
    pub out: Option<PathBuf>,

    /// Config file for matrix benchmarks (TOML)
    #[arg(long, short)]
    pub config: Option<PathBuf>,
}
