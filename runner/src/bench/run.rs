use crate::{
    bench::iteration::{run_iteration, run_single_iteration},
    config::BenchmarkConfig,
};
use futures::{StreamExt, stream::FuturesUnordered};
use miette::{Context, IntoDiagnostic};
use rustls::pki_types::ServerName;
use std::io::{Write, stdout};
use tokio_rustls::TlsConnector;
use tracing::{debug, info};
use uuid::Uuid;

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

    for i in 0..config.warmup {
        debug!(
            phase = "warmup",
            iteration = i,
            server = %config.server,
            proto = %config.proto,
            payload_bytes = %config.payload,
            "iteration started"
        );
        run_iteration(
            server,
            config.proto,
            config.payload,
            tls_connector,
            server_name,
            i,
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
    let mut completed = 0;

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
            Some(record) => {
                let record = record?;
                completed += 1;

                if completed % 10 == 0 || completed == config.iters {
                    debug!(
                        completed,
                        issued,
                        in_flight = in_flight.len(),
                        "benchmark progress"
                    );
                }

                writeln!(output, "{record}")
                    .into_diagnostic()
                    .context("failed to write record")?;
            }
            None => break,
        }
    }

    Ok(())
}
