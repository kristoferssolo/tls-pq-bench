//! TLS benchmark server.
//!
//! Listens for TLS connections and serves the benchmark protocol:
//! - Reads 8-byte little-endian u64 (requested payload size N)
//! - Responds with exactly N bytes (deterministic pattern)

use clap::Parser;
use common::{
    KeyExchangeMode,
    cert::{CaCertificate, ServerCertificate},
    protocol::{read_request, write_payload},
};
use miette::miette;
use rustls::{
    ServerConfig,
    crypto::aws_lc_rs::{self, kx_group},
    pki_types::{CertificateDer, PrivateKeyDer},
    server::Acceptor,
    version::TLS13,
};
use std::{fmt::Write, io::ErrorKind, net::SocketAddr, sync::Arc};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
};
use tokio_rustls::LazyConfigAcceptor;

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
) -> miette::Result<Arc<ServerConfig>> {
    // Select crypto provider with appropriate key exchange groups
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = match mode {
        KeyExchangeMode::X25519 => vec![kx_group::X25519],
        KeyExchangeMode::X25519Mlkem768 => {
            todo!("Configure hybrid PQ key exchange")
        }
    };

    // Convert certificate chain
    let certs: Vec<CertificateDer<'static>> = server_cert
        .cert_chain_der
        .iter()
        .map(|der| CertificateDer::from(der.clone()))
        .collect();

    // Convert private key
    let key = PrivateKeyDer::try_from(server_cert.private_key_der.clone())
        .map_err(|e| miette!("invalid private key: {e}"))?;

    let config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&TLS13])
        .map_err(|e| miette!("failed to set TLS versions: {e}"))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| miette!("failed to configure certificate: {e}"))?;

    Ok(Arc::new(config))
}

async fn handle_connection(stream: TcpStream, peer: SocketAddr, tls_config: Arc<ServerConfig>) {
    // Perform TLS handshake
    let acceptor = LazyConfigAcceptor::new(Acceptor::default(), stream);
    let start_handshake = match acceptor.await {
        Ok(sh) => sh,
        Err(e) => {
            eprintln!("[{peer}] TLS accept error: {e}");
            return;
        }
    };

    let mut tls_stream = match start_handshake.into_stream(tls_config).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[{peer}] TLS handshake error: {e}");
            return;
        }
    };

    // Handle protocol
    loop {
        let payload_size = match read_request(&mut tls_stream).await {
            Ok(size) => size,
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                break;
            }
            Err(e) => {
                eprintln!("[{peer}] read error: {e}");
                break;
            }
        };

        if let Err(e) = write_payload(&mut tls_stream, payload_size).await {
            eprintln!("[{peer}] write error: {e}");
            break;
        }

        // Flush to ensure data is sent
        if let Err(e) = tls_stream.flush().await {
            eprintln!("[{peer}] flush error: {e}");
            break;
        }
    }
}

async fn run_server(args: Args, tls_config: Arc<ServerConfig>) -> miette::Result<()> {
    let listener = TcpListener::bind(args.listen)
        .await
        .map_err(|e| miette!("failed to bind to {}: {e}", args.listen))?;

    eprintln!(
        "Listening on {} (TLS 1.3, mode: {})",
        args.listen, args.mode
    );

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("accept error: {e}");
                continue;
            }
        };

        let config = tls_config.clone();
        tokio::spawn(handle_connection(stream, peer, config));
    }
}

#[tokio::main]
async fn main() -> miette::Result<()> {
    let args = Args::parse();

    eprintln!("server configuration:");
    eprintln!("  mode:   {}", args.mode);
    eprintln!("  listen: {}", args.listen);
    eprintln!();

    // Generate certificates
    eprintln!("Generating self-signed certificates...");
    let ca = CaCertificate::generate().map_err(|e| miette!("failed to generate CA: {e}"))?;
    let server_cert = ca
        .sign_server_cert("localhost")
        .map_err(|e| miette!("failed to generate server cert: {e}"))?;

    // Build TLS config
    let tls_config = build_tls_config(args.mode, &server_cert)?;

    // Print CA certificate for client configuration
    eprintln!("CA certificate (base64 DER):");
    eprintln!("{}", base64_encode(&ca.cert_der));
    eprintln!();

    run_server(args, tls_config).await
}

/// Simple base64 encoding for certificate display.
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();
    for chunk in data.chunks(3) {
        let mut n = 0u32;
        for (i, &byte) in chunk.iter().enumerate() {
            n |= u32::from(byte) << (16 - 8 * i);
        }

        for i in 0..=chunk.len() {
            let idx = ((n >> (18 - 6 * i)) & 0x3F) as usize;
            result.push(ALPHABET[idx] as char);
        }

        for _ in chunk.len()..3 {
            result.push('=');
        }
    }

    // Wrap at 76 characters
    let mut wrapped = String::new();
    for (i, c) in result.chars().enumerate() {
        if i > 0 && i % 76 == 0 {
            let _ = writeln!(wrapped);
        }
        wrapped.push(c);
    }

    wrapped
}
