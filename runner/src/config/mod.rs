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
    pub mode: KeyExchangeMode,
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
            mode: args.mode,
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

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok, assert_some};

    const VALID_CONFIG: &str = r#"
[[benchmarks]]
mode = "x25519"
payload = 1024
iters = 100
warmup = 10
concurrency = 1
server = "127.0.0.1:4433"

[[benchmarks]]
mode = "x25519mlkem768"
payload = 4096
iters = 50
warmup = 5
concurrency = 4
server = "127.0.0.1:4433"
"#;

    fn get_config_from_str(toml: &str) -> Config {
        assert_ok!(toml::from_str::<Config>(toml))
    }

    #[test]
    fn valid_single_benchmark() {
        let toml = r#"
[[benchmarks]]
mode = "x25519"
payload = 1024
iters = 100
warmup = 10
concurrency = 1
server = "127.0.0.1:4433"
"#;
        let config = get_config_from_str(toml);
        assert_eq!(config.benchmarks.len(), 1);
        assert_eq!(config.benchmarks[0].mode, KeyExchangeMode::X25519);
        assert_eq!(config.benchmarks[0].payload, 1024);
    }

    #[test]
    fn valid_multiple_benchmarks() {
        let config = get_config_from_str(VALID_CONFIG);
        assert_eq!(config.benchmarks.len(), 2);
        assert_eq!(config.benchmarks[0].mode, KeyExchangeMode::X25519);
        assert_eq!(config.benchmarks[1].mode, KeyExchangeMode::X25519Mlkem768);
    }

    #[test]
    fn invalid_mode() {
        let toml = r#"
[[benchmarks]]
mode = "invalid_mode"
payload = 1024
iters = 100
warmup = 10
concurrency = 1
server = "127.0.0.1:4433"
"#;
        assert_err!(toml::from_str::<Config>(toml));
    }

    #[test]
    fn payload_zero_validation() {
        let toml = r#"
[[benchmarks]]
mode = "x25519"
payload = 0
iters = 100
warmup = 10
concurrency = 1
server = "127.0.0.1:4433"
"#;
        let config = get_config_from_str(toml);
        assert_err!(validate_config(&config, toml, Path::new("test.toml")));
    }

    #[test]
    fn iters_zero_validation() {
        let toml = r#"
[[benchmarks]]
mode = "x25519"
payload = 1024
iters = 0
warmup = 10
concurrency = 1
server = "127.0.0.1:4433"
"#;
        let config = get_config_from_str(toml);
        assert_err!(validate_config(&config, toml, Path::new("test.toml")));
    }

    #[test]
    fn concurrency_zero_validation() {
        let toml = r#"
[[benchmarks]]
mode = "x25519"
payload = 1024
iters = 100
warmup = 10
concurrency = 0
server = "127.0.0.1:4433"
"#;
        let config = get_config_from_str(toml);
        assert_err!(validate_config(&config, toml, Path::new("test.toml")));
    }

    #[test]
    fn empty_benchmarks() {
        let toml = "benchmarks = []";
        let config = get_config_from_str(toml);
        assert!(config.benchmarks.is_empty());
    }

    #[test]
    fn server_mode_fallback() {
        let toml = r#"
[[benchmarks]]
mode = "x25519"
payload = 1024
iters = 100
warmup = 10
concurrency = 1
server = "127.0.0.1:4433"
"#;
        let config = get_config_from_str(toml);
        let benchmark = assert_some!(config.benchmarks.first());
        assert_eq!(benchmark.mode, KeyExchangeMode::X25519);
    }

    #[test]
    fn server_mode_mlkem() {
        let toml = r#"
[[benchmarks]]
mode = "x25519mlkem768"
payload = 1024
iters = 100
warmup = 10
concurrency = 1
server = "127.0.0.1:4433"
"#;
        let config = get_config_from_str(toml);
        let benchmark = assert_some!(config.benchmarks.first());
        assert_eq!(benchmark.mode, KeyExchangeMode::X25519Mlkem768);
    }
}
