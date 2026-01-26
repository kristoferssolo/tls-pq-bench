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
use std::{
    fs::File,
    io::{BufWriter, Write, stdout},
    net::SocketAddr,
    path::PathBuf,
    time::Instant,
};
use tokio::net::TcpStream;

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

/// Run a single benchmark iteration over plain TCP.
#[allow(clippy::cast_possible_truncation)] // nanoseconds won't overflow u64 for reasonable durations
async fn run_iteration(server: SocketAddr, payload_bytes: u64) -> miette::Result<IterationResult> {
    let start = Instant::now();

    // Connect (this is the "handshake" for plain TCP)
    let mut stream = TcpStream::connect(server)
        .await
        .map_err(|e| miette!("connection failed: {e}"))?;

    let handshake_ns = start.elapsed().as_nanos() as u64;

    // Send request
    write_request(&mut stream, payload_bytes)
        .await
        .map_err(|e| miette!("write request failed: {e}"))?;

    // Read response
    read_payload(&mut stream, payload_bytes)
        .await
        .map_err(|e| miette!("read payload failed: {e}"))?;

    let ttlb_ns = start.elapsed().as_nanos() as u64;

    Ok(IterationResult {
        handshake_ns,
        ttlb_ns,
    })
}

async fn run_benchmark(args: Args) -> miette::Result<()> {
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
        "Running {} warmup + {} measured iterations (concurrency: {}, TLS disabled)",
        args.warmup, args.iters, args.concurrency
    );
    eprintln!();

    // TODO: Implement concurrency
    for i in 0..total_iters {
        let is_warmup = i < args.warmup;

        let result = run_iteration(args.server, args.payload_bytes).await?;

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

    run_benchmark(args).await
}
