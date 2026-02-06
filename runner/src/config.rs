use miette::{Context, IntoDiagnostic};
use serde::Deserialize;
use std::{fs::read_to_string, net::SocketAddr, path::PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct BenchmarkConfig {
    pub mode: String,
    pub payload: u32,
    pub iters: u32,
    pub warmup: u32,
    pub concurrency: u32,
    pub server: SocketAddr,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub benchmarks: Vec<BenchmarkConfig>,
}

/// Load benchmark configuration from a TOML file.
///
/// # Errors
/// Returns an error if the file cannot be read or parsed.
pub fn load_from_file(path: &PathBuf) -> miette::Result<Config> {
    let content = read_to_string(path)
        .into_diagnostic()
        .context(format!("failed to read config file: {}", path.display()))?;
    let config: Config = toml::from_str(&content).into_diagnostic().context(format!(
        "failed to parse TOML config from file {}",
        path.display()
    ))?;
    Ok(config)
}

/// Create benchmark configuration from CLI arguments.
///
/// # Errors
/// Never returns an error, but returns Result for consistency.
pub fn load_from_cli(args: &crate::args::Args) -> miette::Result<Config> {
    let mode = args.mode.to_string();
    Ok(Config {
        benchmarks: vec![BenchmarkConfig {
            mode,
            payload: args.payload_bytes,
            iters: args.iters,
            warmup: args.warmup,
            concurrency: args.concurrency,
            server: args.server,
        }],
    })
}

impl Config {
    /// Get the key exchange mode from the first benchmark configuration.
    #[must_use]
    pub fn server_mode(&self) -> KeyExchangeMode {
        self.benchmarks
            .first()
            .and_then(|b| b.mode.parse().ok())
            .unwrap_or(KeyExchangeMode::X25519)
    }
}

use common::KeyExchangeMode;
