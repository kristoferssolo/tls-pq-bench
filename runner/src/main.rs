//! TLS benchmark runner (client).
//!
//! Connects to a benchmark server, performs the protocol, and measures:
//! - Handshake latency
//! - Time-to-last-byte (TTLB)
//!
//! Outputs NDJSON records to stdout or a file.

use clap::Parser;
use common::{
    BenchRecord, KeyExchangeMode,
    protocol::{read_payload, write_request},
};
use miette::miette;
use rustls::{
    ClientConfig, DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::aws_lc_rs::{
        self,
        kx_group::{X25519, X25519MLKEM768},
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
    version::TLS13,
};
use std::{
    fs::File,
    io::{BufWriter, Write, stdout},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::Instant,
};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// TLS benchmark runner.
#[derive(Debug, Parser)]
#[command(name = "runner", version, about)]
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

/// Result of a single benchmark iteration.
struct IterationResult {
    handshake_ns: u64,
    ttlb_ns: u64,
}

/// Certificate verifier that accepts any certificate.
/// Used for benchmarking where we don't need to verify the server's identity.
#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

/// Build TLS client config for the given key exchange mode.
fn build_tls_config(mode: KeyExchangeMode) -> miette::Result<Arc<ClientConfig>> {
    // Select crypto provider with appropriate key exchange groups
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = match mode {
        KeyExchangeMode::X25519 => vec![X25519],
        KeyExchangeMode::X25519Mlkem768 => vec![X25519MLKEM768],
    };

    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&TLS13])
        .map_err(|e| miette!("failed to set TLS versions: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    Ok(Arc::new(config))
}

/// Run a single benchmark iteration over TLS.
#[allow(clippy::cast_possible_truncation)] // nanoseconds won't overflow u64 for reasonable durations
async fn run_iteration(
    server: SocketAddr,
    payload_bytes: u64,
    tls_connector: &TlsConnector,
    server_name: &ServerName<'static>,
) -> miette::Result<IterationResult> {
    let start = Instant::now();

    // TCP connect
    let stream = TcpStream::connect(server)
        .await
        .map_err(|e| miette!("TCP connection failed: {e}"))?;

    // TLS handshake
    let mut tls_stream = tls_connector
        .connect(server_name.clone(), stream)
        .await
        .map_err(|e| miette!("TLS handshake failed: {e}"))?;

    let handshake_ns = start.elapsed().as_nanos() as u64;

    // Send request
    write_request(&mut tls_stream, payload_bytes)
        .await
        .map_err(|e| miette!("write request failed: {e}"))?;

    // Read response
    read_payload(&mut tls_stream, payload_bytes)
        .await
        .map_err(|e| miette!("read payload failed: {e}"))?;

    let ttlb_ns = start.elapsed().as_nanos() as u64;

    Ok(IterationResult {
        handshake_ns,
        ttlb_ns,
    })
}

async fn run_benchmark(
    args: Args,
    tls_connector: TlsConnector,
    server_name: ServerName<'static>,
) -> miette::Result<()> {
    let total_iters = args.warmup + args.iters;

    // Open output file or use stdout
    let mut output: Box<dyn Write + Send> = match &args.out {
        Some(path) => {
            let file =
                File::create(path).map_err(|e| miette!("failed to create output file: {e}"))?;
            Box::new(BufWriter::new(file))
        }
        None => Box::new(stdout()),
    };

    eprintln!(
        "Running {} warmup + {} measured iterations (concurrency: {}, TLS 1.3)",
        args.warmup, args.iters, args.concurrency
    );
    eprintln!();

    // TODO: Implement concurrency
    for i in 0..total_iters {
        let is_warmup = i < args.warmup;

        let result = run_iteration(
            args.server,
            args.payload_bytes,
            &tls_connector,
            &server_name,
        )
        .await?;

        if !is_warmup {
            let record = BenchRecord {
                iteration: i - args.warmup,
                mode: args.mode,
                payload_bytes: args.payload_bytes,
                handshake_ns: result.handshake_ns,
                ttlb_ns: result.ttlb_ns,
            };

            writeln!(output, "{record}").map_err(|e| miette!("failed to write record: {e}"))?;
        }

        if is_warmup && i == args.warmup.saturating_sub(1) {
            eprintln!("Warmup complete.");
        }
    }

    output
        .flush()
        .map_err(|e| miette!("failed to flush output: {e}"))?;

    eprintln!("Benchmark complete.");
    Ok(())
}

#[tokio::main]
async fn main() -> miette::Result<()> {
    let args = Args::parse();

    eprintln!("runner configuration:");
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
    eprintln!();

    // Build TLS config (skips certificate verification for benchmarking)
    let tls_config = build_tls_config(args.mode)?;
    let tls_connector = TlsConnector::from(tls_config);

    // Server name for TLS (use "localhost" for local testing)
    let server_name = ServerName::try_from("localhost".to_string())
        .map_err(|e| miette!("invalid server name: {e}"))?;

    run_benchmark(args, tls_connector, server_name).await
}
