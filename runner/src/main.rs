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
    env,
    fmt::Debug,
    fs::File,
    io::{BufWriter, Write, stdout},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::Instant,
};
use tokio::{net::TcpStream, sync::Semaphore, task::JoinHandle};
use tokio_rustls::TlsConnector;
use tracing::info;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

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
    payload_bytes: u32,

    /// Number of benchmark iterations (excluding warmup).
    #[arg(long, default_value = "100")]
    iters: u32,

    /// Number of warmup iterations (not recorded).
    #[arg(long, default_value = "10")]
    warmup: u32,

    /// Number of concurrent connections.
    #[arg(long, default_value = "1")]
    concurrency: u32,

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
    payload_bytes: u32,
    tls_connector: &TlsConnector,
    server_name: &ServerName<'static>,
) -> miette::Result<IterationResult> {
    let start = Instant::now();

    let stream = TcpStream::connect(server)
        .await
        .map_err(|e| miette!("TCP connection failed: {e}"))?;

    let mut tls_stream = tls_connector
        .connect(server_name.clone(), stream)
        .await
        .map_err(|e| miette!("TLS handshake failed: {e}"))?;

    let handshake_ns = start.elapsed().as_nanos() as u64;

    write_request(&mut tls_stream, u64::from(payload_bytes))
        .await
        .map_err(|e| miette!("write request failed: {e}"))?;

    read_payload(&mut tls_stream, u64::from(payload_bytes))
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
    let mut output: Box<dyn Write + Send> = match &args.out {
        Some(path) => {
            let file =
                File::create(path).map_err(|e| miette!("failed to create output file: {e}"))?;
            Box::new(BufWriter::new(file))
        }
        None => Box::new(stdout()),
    };

    info!(
        warmup = args.warmup,
        iters = args.iters,
        concurrency = args.concurrency,
        "runnning benchmark iterations"
    );

    for _ in 0..args.warmup {
        run_iteration(
            args.server,
            args.payload_bytes,
            &tls_connector,
            &server_name,
        )
        .await?;
    }
    info!("warmup complete");

    let test_conn = tls_connector
        .connect(
            server_name.clone(),
            TcpStream::connect(args.server)
                .await
                .map_err(|e| miette!("failed to connect to server {}: {e}", args.server))?,
        )
        .await
        .map_err(|e| miette!("TLS handshake failed: {e}"))?;

    let cipher = test_conn.get_ref().1.negotiated_cipher_suite();
    info!(cipher = ?cipher, "TLS handshake complete");

    #[allow(clippy::cast_possible_truncation)] // concurrency is limited to reasonable values
    let semaphore = Arc::new(Semaphore::new(args.concurrency as usize));
    let tasks = spawn_benchmark_tasks(&args, &semaphore, &tls_connector, &server_name);

    write_results(&mut output, tasks).await?;

    output
        .flush()
        .map_err(|e| miette!("failed to flush output: {e}"))?;

    info!("benchmark complete");
    Ok(())
}

type ReturnHandle = JoinHandle<(IterationResult, Option<BenchRecord>)>;

fn spawn_benchmark_tasks(
    args: &Args,
    semaphore: &Arc<Semaphore>,
    tls_connector: &TlsConnector,
    server_name: &ServerName<'static>,
) -> Vec<ReturnHandle> {
    let server = args.server;
    let payload_bytes = args.payload_bytes;
    let mode = args.mode;

    (0..args.iters)
        .map(|i| {
            spawn_single_iteration(
                i,
                payload_bytes,
                mode,
                server,
                semaphore.clone(),
                tls_connector.clone(),
                server_name.clone(),
            )
        })
        .collect()
}

fn spawn_single_iteration(
    i: u32,
    payload_bytes: u32,
    mode: KeyExchangeMode,
    server: SocketAddr,
    semaphore: Arc<Semaphore>,
    tls_connector: TlsConnector,
    server_name: ServerName<'static>,
) -> ReturnHandle {
    tokio::spawn(async move {
        let _permit = semaphore
            .acquire()
            .await
            .expect("semaphore should not be closed");

        let result = run_iteration(server, payload_bytes, &tls_connector, &server_name)
            .await
            .expect("iteration should not fail");

        let record = BenchRecord {
            iteration: u64::from(i),
            mode,
            payload_bytes: u64::from(payload_bytes),
            handshake_ns: result.handshake_ns,
            ttlb_ns: result.ttlb_ns,
        };

        (result, Some(record))
    })
}

async fn write_results(
    output: &mut Box<dyn Write + Send>,
    tasks: Vec<ReturnHandle>,
) -> miette::Result<()> {
    for task in tasks {
        let (_result, record) = task.await.expect("task should not panic");
        if let Some(record) = record {
            writeln!(output, "{record}").map_err(|e| miette!("failed to write record: {e}"))?;
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
    info!(
        mode=%args.mode,
        server=%args.server,
        payload_bytes=%args.payload_bytes,
        iters=%args.iters,
        warmup=%args.warmup,
        concurrency=%args.concurrency,
        out=%args.out.as_ref().map_or("stdout", |p| p.to_str().unwrap_or("invalid")),
        "runner configuration"
    );

    let tls_config = build_tls_config(args.mode)?;
    let tls_connector = TlsConnector::from(tls_config);

    let server_name = ServerName::try_from("localhost".to_string())
        .map_err(|e| miette!("invalid server name: {e}"))?;

    run_benchmark(args, tls_connector, server_name).await
}
