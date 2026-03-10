mod http1;
mod raw;

use crate::{
    bench::{http1::run_http1_exchange, raw::run_raw_exchange},
    config::BenchmarkConfig,
};
use common::prelude::*;
use futures::{StreamExt, stream::FuturesUnordered};
use miette::{Context, IntoDiagnostic};
use rustls::pki_types::ServerName;
use std::{
    io::{Write, stdout},
    net::SocketAddr,
    time::Instant,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;
use tracing::info;
use uuid::Uuid;

/// Result of a single benchmark iteration.
struct IterationResult {
    tcp: u128,
    handshake: u128,
    ttlb: u128,
}

pub async fn run_benchmark(
    run_id: Uuid,
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
        run_iteration(
            server,
            config.proto,
            config.payload,
            tls_connector,
            server_name,
        )
        .await?;
    }
    info!("warmup complete");

    let mut output = stdout();
    run_and_write(run_id, config, tls_connector, server_name, &mut output).await?;
    output
        .flush()
        .into_diagnostic()
        .context("failed to flush output")?;

    info!("benchmark complete");
    Ok(())
}

async fn run_and_write<W: Write + Send>(
    run_id: Uuid,
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
                run_id,
                config,
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

async fn run_single_iteration(
    iteration: u32,
    run_id: Uuid,
    config: &BenchmarkConfig,
    tls_connector: TlsConnector,
    server_name: ServerName<'static>,
) -> miette::Result<BenchRecord> {
    let result = run_iteration(
        config.server,
        config.proto,
        config.payload,
        &tls_connector,
        &server_name,
    )
    .await?;

    Ok(BenchRecord {
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
    })
}

/// Run a single benchmark iteration over TLS.
async fn run_iteration(
    server: SocketAddr,
    proto: ProtocolMode,
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
    run_exchange(&mut tls_stream, proto, payload_bytes).await?;

    let ttlb_ns = tcp_ns + handshake_ns + ttlb_start.elapsed().as_nanos();

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
