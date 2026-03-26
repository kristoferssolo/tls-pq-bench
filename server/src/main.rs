//! TLS benchmark server.
//!
//! Listens for TLS connections and serves the benchmark protocol:
//! - Reads 8-byte little-endian u64 (requested payload size N)
//! - Responds with exactly N bytes (deterministic pattern)

mod args;
mod cert;
mod error;
mod server;
mod tls;

use crate::{args::Args, cert::get_cert, server::run_server, tls::build_tls_config};
use clap::Parser;
use common::prelude::*;
use std::env;
use tracing::info;

#[tokio::main]
async fn main() -> miette::Result<()> {
    init_tracing(std::io::stderr);
    let args = Args::parse();

    info!(
        rust_version = env!("RUSTC_VERSION"),
        os = env::consts::OS,
        arch = env::consts::ARCH,
        command = env::args().collect::<Vec<_>>().join(" "),
        listen = %args.listen,
        mode = %args.mode,
        proto = %args.proto,
        "server started"
    );

    let server_cert = get_cert(&args.cert)?;
    let tls_config = build_tls_config(args.mode, &server_cert)?;

    Ok(run_server(&args, tls_config).await?)
}
