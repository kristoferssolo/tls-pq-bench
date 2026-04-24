use clap::Parser;
use common::prelude::*;
use std::{net::SocketAddr, path::PathBuf};

/// TLS benchmark runner.
#[derive(Debug, Parser)]
#[command(name = "runner", version, about)]
pub struct Args {
    /// Protocol carrier mode
    #[arg(long, default_value = "raw")]
    pub proto: ProtocolMode,

    /// Key exchange mode
    #[arg(long, default_value = "x25519")]
    pub mode: KeyExchangeMode,

    /// Server address to connect to
    #[arg(long, required_unless_present = "config")]
    pub server: Option<SocketAddr>,

    /// TLS server name and HTTP Host header to use for the connection
    #[arg(long, default_value = "localhost")]
    pub server_name: String,

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

    /// Per-iteration timeout in seconds
    #[arg(long, default_value = "30")]
    pub timeout_secs: u64,

    /// Output file for JSONL records (stdout if not specified)
    #[arg(long)]
    pub out: Option<PathBuf>,

    /// Output file for structured run metadata (JSON)
    #[arg(long)]
    pub run_meta_out: Option<PathBuf>,

    /// Config file for matrix benchmarks (TOML)
    #[arg(long, short)]
    pub config: Option<PathBuf>,

    /// CA certificate to verify the server certificate
    #[arg(long)]
    pub ca_cert: Option<PathBuf>,
}
