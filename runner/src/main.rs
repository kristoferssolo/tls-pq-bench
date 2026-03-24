//! TLS benchmark runner (client).
//!
//! Connects to a benchmark server, performs the protocol, and measures:
//! - Handshake latency
//! - Time-to-last-byte (TTLB)
//!
//! Outputs JSONL records to stdout or a file.

mod args;
mod bench;
mod config;
mod error;
mod tls;

use crate::{args::Args, bench::run_benchmark, config::Config, tls::build_tls_config};
use clap::Parser;
use common::prelude::init_tracing;
use miette::{Context, IntoDiagnostic};
use rustls::pki_types::ServerName;
use std::{
    env,
    fs::File,
    io::{self, BufWriter, Write},
    path::Path,
    sync::Arc,
};
use tokio_rustls::TlsConnector;
use tracing::info;
use uuid::Uuid;

#[tokio::main]
async fn main() -> miette::Result<()> {
    let run_id = Uuid::new_v4();
    init_tracing(std::io::stderr);

    info!(
        run_id = %run_id,
        rust_version = env!("RUSTC_VERSION"),
        os = env::consts::OS,
        arch = env::consts::ARCH,
        command = env::args().collect::<Vec<_>>().join(" "),
        "benchmark started"
    );

    let args = Args::parse();
    let mut output = create_output(args.out.as_deref())?;

    let config: Config = if let Some(config_path) = &args.config {
        info!(config_file = %config_path.display(), "loading config from file");
        config_path.as_path().try_into()?
    } else {
        info!("using CLI arguments");
        args.try_into()?
    };

    let server_name = ServerName::try_from("localhost".to_string())
        .into_diagnostic()
        .context("invalid server name")?;

    for benchmark in &config.benchmarks {
        info!(
            proto = %benchmark.proto,
            mode = %benchmark.mode,
            payload = benchmark.payload,
            iters = benchmark.iters,
            warmup = benchmark.warmup,
            concurrency = benchmark.concurrency,
            "running benchmark"
        );

        let tls_config = build_tls_config(benchmark.mode)?;
        let tls_connector = TlsConnector::from(Arc::new(tls_config));

        run_benchmark(run_id, benchmark, &tls_connector, &server_name, &mut output).await?;
    }

    Ok(())
}

fn create_output(path: Option<&Path>) -> miette::Result<Box<dyn Write + Send>> {
    match path {
        Some(path) => {
            let file = File::create(path)
                .into_diagnostic()
                .with_context(|| format!("failed to create output file {}", path.display()))?;
            Ok(Box::new(BufWriter::new(file)))
        }
        None => Ok(Box::new(BufWriter::new(io::stdout()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::assert_ok;
    use std::{
        env::temp_dir,
        fs::{read_to_string, remove_file},
    };

    #[test]
    fn create_output_writes_to_file_when_path_is_provided() {
        let path = temp_dir().join(format!(
            "tls-pq-bench-runner-out-{}.jsonl",
            std::process::id()
        ));

        let mut output = assert_ok!(create_output(Some(path.as_path())));
        writeln!(output, "test-line").expect("writing to a file");
        drop(output);

        let content = read_to_string(&path).expect("reading from a file");
        assert_eq!(content, "test-line\n");

        let _ = remove_file(path);
    }
}
