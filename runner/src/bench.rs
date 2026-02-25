use common::{
    BenchRecord, KeyExchangeMode,
    protocol::{read_payload, write_request},
};
use futures::{StreamExt, stream::FuturesUnordered};
use miette::{Context, IntoDiagnostic};
use rustls::pki_types::ServerName;
use std::{
    io::{Write, stdout},
    net::SocketAddr,
    time::Instant,
};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::info;

use crate::config::BenchmarkConfig;

/// Result of a single benchmark iteration.
struct IterationResult {
    tcp: u128,
    handshake: u128,
    ttlb: u128,
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

pub async fn run_benchmark(
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
