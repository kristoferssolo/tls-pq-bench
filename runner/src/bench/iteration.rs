use crate::{
    bench::{http1::run_http1_exchange, raw::run_raw_exchange},
    config::BenchmarkConfig,
};
use common::prelude::*;
use miette::{Context, IntoDiagnostic};
use rustls::pki_types::ServerName;
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;
use tracing::debug;
use uuid::Uuid;

const ITERATION_TIMEOUT_SECS: u64 = 30;

/// Result of a single benchmark iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IterationResult {
    tcp: u128,
    handshake: u128,
    ttlb: u128,
}

pub async fn run_single_iteration(
    iteration: u32,
    run_id: Uuid,
    config: &BenchmarkConfig,
    tls_connector: TlsConnector,
    server_name: ServerName<'static>,
) -> miette::Result<BenchRecord> {
    debug!(
        phase = "measured",
        iteration,
        server = %config.server,
        proto = %config.proto,
        payload_bytes = %config.payload,
        "iteration started"
    );
    let result = tokio::time::timeout(
        Duration::from_secs(ITERATION_TIMEOUT_SECS),
        run_iteration(
            config.server,
            config.proto,
            config.payload,
            &tls_connector,
            &server_name,
            iteration,
        ),
    )
    .await
    .map_err(|_| {
        common::Error::protocol(format!(
            "iteration {iteration} timed out after {ITERATION_TIMEOUT_SECS}s"
        ))
    })??;

    Ok(bench_record(run_id, iteration, config, &result))
}

/// Run a single benchmark iteration over TLS.
pub async fn run_iteration(
    server: SocketAddr,
    proto: ProtocolMode,
    payload_bytes: u32,
    tls_connector: &TlsConnector,
    server_name: &ServerName<'static>,
    iteration: u32,
) -> miette::Result<IterationResult> {
    let tcp_start = Instant::now();
    debug!(iteration, "tcp connection started");

    let stream = TcpStream::connect(server)
        .await
        .into_diagnostic()
        .context("TCP connection failed")?;

    let tcp_ns = tcp_start.elapsed().as_nanos();
    debug!(iteration, tcp_ns, "tcp connection complete");

    let hs_start = Instant::now();
    debug!(iteration, "tls handshake started");

    let mut tls_stream = tls_connector
        .connect(server_name.clone(), stream)
        .await
        .into_diagnostic()
        .context("TLS handshake failed")?;

    let handshake_ns = hs_start.elapsed().as_nanos();
    debug!(iteration, handshake_ns, "tls handshake complete");

    let ttlb_start = Instant::now();
    debug!(iteration, "protocol exchange started");
    run_exchange(&mut tls_stream, proto, payload_bytes).await?;

    let ttlb_ns = tcp_ns + handshake_ns + ttlb_start.elapsed().as_nanos();
    debug!(iteration, ttlb_ns, "protocol exchange complete");

    Ok(IterationResult {
        tcp: tcp_ns,
        handshake: handshake_ns,
        ttlb: ttlb_ns,
    })
}

async fn run_exchange<S>(
    tls_stream: &mut S,
    proto: ProtocolMode,
    payload_bytes: u32,
) -> miette::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match proto {
        ProtocolMode::Raw => run_raw_exchange(tls_stream, payload_bytes).await,
        ProtocolMode::Http1 => run_http1_exchange(tls_stream, payload_bytes).await,
    }
}

const fn bench_record(
    run_id: Uuid,
    iteration: u32,
    config: &BenchmarkConfig,
    result: &IterationResult,
) -> BenchRecord {
    BenchRecord {
        run_id,
        iteration,
        proto: config.proto,
        mode: config.mode,
        payload_bytes: config.payload,
        concurrency: config.concurrency,
        iters: config.iters,
        warmup: config.warmup,
        tcp_ns: result.tcp,
        handshake_ns: result.handshake,
        ttlb_ns: result.ttlb,
    }
}
