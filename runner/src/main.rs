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
use futures::{StreamExt, stream::FuturesUnordered};
use miette::{Context, IntoDiagnostic};
use runner::{
    args::Args,
    config::{BenchmarkConfig, load_from_cli, load_from_file},
};
use rustls::{
    ClientConfig, DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    compress::CompressionCache,
    crypto::aws_lc_rs::{
        self,
        kx_group::{X25519, X25519MLKEM768},
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
    version::TLS13,
};
use std::{
    env,
    io::{Write, stdout},
    net::SocketAddr,
    sync::Arc,
    time::Instant,
};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::info;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

/// Result of a single benchmark iteration.
struct IterationResult {
    tcp: u128,
    handshake: u128,
    ttlb: u128,
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
fn build_tls_config(mode: KeyExchangeMode) -> miette::Result<ClientConfig> {
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = match mode {
        KeyExchangeMode::X25519 => vec![X25519],
        KeyExchangeMode::X25519Mlkem768 => vec![X25519MLKEM768],
    };

    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&TLS13])
        .into_diagnostic()
        .context("failed to set TLS versions")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    config.cert_compression_cache = Arc::new(CompressionCache::Disabled);

    Ok(config)
}

/// Run a single benchmark iteration over TLS.
async fn run_iteration(
    server: SocketAddr,
    payload_bytes: u32,
    tls_connector: &TlsConnector,
    server_name: &ServerName<'static>,
) -> miette::Result<IterationResult> {
    let tcp_start = Instant::now();

    let stream = TcpStream::connect(server)
        .await
        .into_diagnostic()
        .context("TCP connection failed")?;

    let tcp_ns = tcp_start.elapsed().as_nanos();

    let hs_start = Instant::now();
    let mut tls_stream = tls_connector
        .connect(server_name.clone(), stream)
        .await
        .into_diagnostic()
        .context("TLS handshake failed")?;

    let handshake_ns = hs_start.elapsed().as_nanos();

    let ttlb_start = Instant::now();
    write_request(&mut tls_stream, u64::from(payload_bytes))
        .await
        .into_diagnostic()
        .context("write request failed")?;

    read_payload(&mut tls_stream, u64::from(payload_bytes))
        .await
        .into_diagnostic()
        .context("read payload failed")?;

    let ttlb_ns = tcp_ns + handshake_ns + ttlb_start.elapsed().as_nanos();

    Ok(IterationResult {
        tcp: tcp_ns,
        handshake: handshake_ns,
        ttlb: ttlb_ns,
    })
}

async fn run_benchmark(
    config: &BenchmarkConfig,
    tls_connector: &TlsConnector,
    server_name: &ServerName<'static>,
) -> miette::Result<()> {
    let server = config.server;

    info!(
        warmup = config.warmup,
        iters = config.iters,
        concurrency = config.concurrency,
        "running benchmark iterations"
    );

    for _ in 0..config.warmup {
        run_iteration(server, config.payload, tls_connector, server_name).await?;
    }
    info!("warmup complete");

    #[allow(clippy::cast_possible_truncation)] // concurrency is limited to reasonable values
    let mut output = stdout();
    run_and_write(config, tls_connector, server_name, &mut output).await?;
    output
        .flush()
        .into_diagnostic()
        .context("failed to flush output")?;

    info!("benchmark complete");
    Ok(())
}

async fn run_single_iteration(
    i: u32,
    payload_bytes: u32,
    mode: KeyExchangeMode,
    server: SocketAddr,
    tls_connector: TlsConnector,
    server_name: ServerName<'static>,
) -> miette::Result<BenchRecord> {
    let result = run_iteration(server, payload_bytes, &tls_connector, &server_name).await?;

    Ok(BenchRecord {
        iteration: u64::from(i),
        mode,
        payload_bytes: u64::from(payload_bytes),
        tcp_ns: result.tcp,
        handshake_ns: result.handshake,
        ttlb_ns: result.ttlb,
    })
}

async fn run_and_write<W: Write + Send>(
    config: &BenchmarkConfig,
    tls_connector: &TlsConnector,
    server_name: &ServerName<'static>,
    output: &mut W,
) -> miette::Result<()> {
    let mut in_flight = FuturesUnordered::new();
    let mut issued = 0;

    loop {
        while issued < config.iters && in_flight.len() < config.concurrency as usize {
            in_flight.push(run_single_iteration(
                issued,
                config.payload,
                config.mode,
                config.server,
                tls_connector.clone(),
                server_name.clone(),
            ));
            issued += 1;
        }

        match in_flight.next().await {
            Some(record) => writeln!(output, "{}", record?)
                .into_diagnostic()
                .context("failed to write record")?,
            None => break,
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> miette::Result<()> {
    let run_id = Uuid::new_v4();
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    info!(
        run_id = %run_id,
        rust_version = env!("RUSTC_VERSION"),
        os = env::consts::OS,
        arch = env::consts::ARCH,
        command = env::args().collect::<Vec<_>>().join(" "),
        "benchmark started"
    );

    let args = Args::parse();

    let config = if let Some(config_path) = &args.config {
        info!(config_file = %config_path.display(), "loading config from file");
        load_from_file(config_path)?
    } else {
        info!("using CLI arguments");
        load_from_cli(&args)?
    };

    let server_name = ServerName::try_from("localhost".to_string())
        .into_diagnostic()
        .context("invalid server name")?;

    for benchmark in &config.benchmarks {
        info!(
            mode = %benchmark.mode,
            payload = benchmark.payload,
            iters = benchmark.iters,
            warmup = benchmark.warmup,
            concurrency = benchmark.concurrency,
            "running benchmark"
        );

        let tls_config = build_tls_config(benchmark.mode)?;
        let tls_connector = TlsConnector::from(Arc::new(tls_config));

        run_benchmark(benchmark, &tls_connector, &server_name).await?;
    }

    Ok(())
}
