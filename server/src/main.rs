//! TLS benchmark server.
//!
//! Listens for TLS connections and serves the benchmark protocol:
//! - Reads 8-byte little-endian u64 (requested payload size N)
//! - Responds with exactly N bytes (deterministic pattern)

mod error;
mod server;
mod tls;

use crate::{server::run_server, tls::build_tls_config};
use base64::prelude::*;
use clap::Parser;
use common::{cert::CaCertificate, prelude::*};
use std::{env, net::SocketAddr};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

/// TLS benchmark server.
#[derive(Debug, Parser)]
#[command(name = "server", version, about)]
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
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let args = Args::parse();

    info!(
        rust_version = env!("RUSTC_VERSION"),
        os = env::consts::OS,
        arch = env::consts::ARCH,
        command = env::args().collect::<Vec<_>>().join(" "),
        listen = %args.listen,
        mode = %args.mode,
        "server started"
    );

    info!("Generating self-signed certificates...");
    let ca = CaCertificate::generate().map_err(common::Error::RCGen)?;
    let server_cert = ca
        .sign_server_cert("localhost")
        .map_err(common::Error::RCGen)?;

    let tls_config = build_tls_config(args.mode, &server_cert)?;

    info!(
        ca_cert_base64 = BASE64_STANDARD
            .encode(ca.cert_der)
            .chars()
            .take(256)
            .collect::<String>(),
        "CA cert (truncated)"
    );

    Ok(run_server(args, tls_config).await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::assert_ok;
    use std::sync::Arc;

    #[test]
    fn default_args() {
        let args = Args::parse_from(["server"]);
        assert_eq!(args.mode, KeyExchangeMode::X25519);
        assert_eq!(args.listen.to_string(), "127.0.0.1:4433");
    }

    #[test]
    fn custom_args() {
        let args = Args::parse_from([
            "server",
            "--mode",
            "x25519mlkem768",
            "--listen",
            "0.0.0.0:8080",
        ]);
        assert_eq!(args.mode, KeyExchangeMode::X25519Mlkem768);
        assert_eq!(args.listen.to_string(), "0.0.0.0:8080");
    }

    #[test]
    fn tls_config_x25519() {
        let ca = assert_ok!(CaCertificate::generate(), "generate CA");
        let server_cert = assert_ok!(ca.sign_server_cert("localhost"), "sign cert");
        let config = assert_ok!(
            build_tls_config(KeyExchangeMode::X25519, &server_cert),
            "build config"
        );
        assert!(Arc::strong_count(&config) >= 1);
    }

    #[test]
    fn tls_config_mlkem() {
        let ca = assert_ok!(CaCertificate::generate(), "generate CA");
        let server_cert = assert_ok!(ca.sign_server_cert("localhost"), "sign cert");
        let config = assert_ok!(
            build_tls_config(KeyExchangeMode::X25519Mlkem768, &server_cert),
            "build config"
        );
        assert!(Arc::strong_count(&config) >= 1);
    }

    #[test]
    fn tls_config_certificates() {
        let ca = assert_ok!(CaCertificate::generate(), "generate CA");
        let server_cert = assert_ok!(ca.sign_server_cert("localhost"), "sign cert");
        let config = assert_ok!(
            build_tls_config(KeyExchangeMode::X25519, &server_cert),
            "build config"
        );
        assert!(Arc::strong_count(&config) >= 1);
    }
}
