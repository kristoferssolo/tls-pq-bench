//! TLS benchmark server.
//!
//! Listens for TLS connections and serves the benchmark protocol:
//! - Reads 8-byte little-endian u64 (requested payload size N)
//! - Responds with exactly N bytes (deterministic pattern)

mod error;

use base64::prelude::*;
use clap::Parser;
use common::{
    KeyExchangeMode,
    cert::{CaCertificate, ServerCertificate},
    protocol::{read_request, write_payload},
};
use rustls::{
    ServerConfig,
    crypto::aws_lc_rs::{
        self,
        kx_group::{X25519, X25519MLKEM768},
    },
    pki_types::{CertificateDer, PrivateKeyDer},
    server::Acceptor,
    version::TLS13,
};
use std::{env, io::ErrorKind, net::SocketAddr, sync::Arc};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
};
use tokio_rustls::LazyConfigAcceptor;
use tracing::{debug, error, info, warn};
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

/// Build TLS server config for the given key exchange mode.
fn build_tls_config(
    mode: KeyExchangeMode,
    server_cert: &ServerCertificate,
) -> error::Result<Arc<ServerConfig>> {
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = match mode {
        KeyExchangeMode::X25519 => vec![X25519],
        KeyExchangeMode::X25519Mlkem768 => vec![X25519MLKEM768],
    };

    let certs = server_cert
        .cert_chain_der
        .iter()
        .map(|der| CertificateDer::from(der.clone()))
        .collect::<Vec<_>>();

    let key = PrivateKeyDer::try_from(server_cert.private_key_der.clone())
        .map_err(|e| error::Error::invalid_cert(format!("invalid private_key: {e}")))?;

    let config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&TLS13])
        .map_err(common::Error::Tls)?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(common::Error::Tls)?;

    Ok(Arc::new(config))
}

async fn handle_connection(stream: TcpStream, peer: SocketAddr, tls_config: Arc<ServerConfig>) {
    let acceptor = LazyConfigAcceptor::new(Acceptor::default(), stream);
    let start_handshake = match acceptor.await {
        Ok(sh) => sh,
        Err(e) => {
            return warn!(peer = %peer, error = %e, "TLS accept error");
        }
    };

    let mut tls_stream = match start_handshake.into_stream(tls_config).await {
        Ok(s) => s,
        Err(e) => {
            return warn!(peer = %peer, error = %e, "TLS handshake error");
        }
    };

    let (_, conn) = tls_stream.get_ref();
    info!(
        cipher = ?conn.negotiated_cipher_suite(),
        version = ?conn.protocol_version(),
        "connection established"
    );

    loop {
        let payload_size = match read_request(&mut tls_stream).await {
            Ok(size) => size,
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                debug!(peer = %peer, "client disconnected");
                break;
            }
            Err(e) => {
                warn!(peer = %peer, error = %e, "connection error");
                break;
            }
        };

        if let Err(e) = write_payload(&mut tls_stream, payload_size).await {
            warn!(peer = %peer, error = %e, "write error");
            break;
        }

        // Flush to ensure data is sent
        if let Err(e) = tls_stream.flush().await {
            warn!(peer = %peer, error = %e, "flush error");
            break;
        }
    }
}

async fn run_server(args: Args, tls_config: Arc<ServerConfig>) -> error::Result<()> {
    let listener = TcpListener::bind(args.listen)
        .await
        .map_err(|e| error::Error::network(format!("failed to bind to {}: {e}", args.listen)))?;

    info!(listen = %args.listen, mode = %args.mode, "listening");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!(error = %e, "accept error");
                continue;
            }
        };

        let config = tls_config.clone();
        tokio::spawn(handle_connection(stream, peer, config));
    }
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
    use common::cert::CaCertificate;

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
