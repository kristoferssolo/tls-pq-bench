mod utils;

use crate::{
    args::Args,
    config::utils::validate_config,
    error::{self, ConfigError},
};
use common::{self, KeyExchangeMode};
use miette::{NamedSource, SourceSpan};
use serde::Deserialize;
use std::{fs::read_to_string, net::SocketAddr, path::Path};

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
pub fn load_from_file(path: &Path) -> error::Result<Config> {
    let content = read_to_string(path).map_err(|source| ConfigError::ReadError {
        source,
        path: path.to_owned(),
    })?;

    let src = NamedSource::new(path.display().to_string(), content.clone());

    let config = toml::from_str::<Config>(&content).map_err(|source| {
        let span = source
            .span()
            .map(|s| SourceSpan::new(s.start.into(), s.end - s.start));

        ConfigError::TomlParseError {
            src: src.clone(),
            span,
            source,
        }
    })?;

    validate_config(&config, &content, path)?;

    Ok(config)
}

/// Create benchmark configuration from CLI arguments.
///
/// # Errors
/// Never returns an error, but returns Result for consistency.
pub fn load_from_cli(args: &Args) -> error::Result<Config> {
    Ok(Config {
        benchmarks: vec![BenchmarkConfig {
            mode: args.mode.to_string(),
            payload: args.payload_bytes,
            iters: args.iters,
            warmup: args.warmup,
            concurrency: args.concurrency,
            server: args
                .server
                .ok_or_else(|| common::Error::config("--server ir required"))?,
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
