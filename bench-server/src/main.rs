//! TLS benchmark server.
//!
//! Listens for connections and serves the benchmark protocol:
//! - Reads 8-byte little-endian u64 (requested payload size N)
//! - Responds with exactly N bytes (deterministic pattern)

use bench_common::protocol::{read_request, write_payload};
use bench_common::KeyExchangeMode;
use clap::Parser;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};

/// TLS benchmark server.
#[derive(Debug, Parser)]
#[command(name = "bench-server", version, about)]
struct Args {
    /// Key exchange mode.
    #[arg(long, default_value = "x25519")]
    mode: KeyExchangeMode,

    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:4433")]
    listen: SocketAddr,
}

async fn handle_connection(mut stream: TcpStream, peer: SocketAddr) {
    loop {
        let payload_size = match read_request(&mut stream).await {
            Ok(size) => size,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Client closed connection
                break;
            }
            Err(e) => {
                eprintln!("[{peer}] read error: {e}");
                break;
            }
        };

        if let Err(e) = write_payload(&mut stream, payload_size).await {
            eprintln!("[{peer}] write error: {e}");
            break;
        }
    }
}

async fn run_server(args: Args) -> miette::Result<()> {
    let listener = TcpListener::bind(args.listen)
        .await
        .map_err(|e| miette::miette!("failed to bind to {}: {e}", args.listen))?;

    eprintln!("Listening on {} (TCP, TLS disabled)", args.listen);
    eprintln!("Mode: {} (not yet implemented)", args.mode);

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("accept error: {e}");
                continue;
            }
        };

        tokio::spawn(handle_connection(stream, peer));
    }
}

#[tokio::main]
async fn main() -> miette::Result<()> {
    let args = Args::parse();

    eprintln!("bench-server configuration:");
    eprintln!("  mode:   {}", args.mode);
    eprintln!("  listen: {}", args.listen);
    eprintln!();

    run_server(args).await
}
