mod utils;

use crate::{
    args::Args,
    config::utils::validate_config,
    error::{self, ConfigError},
};
use common::{VerificationMode, prelude::*};
use miette::{NamedSource, SourceSpan};
use serde::Deserialize;
use std::{fs::read_to_string, net::SocketAddr, path::Path};

const fn default_timeout_secs() -> u64 {
    30
}

fn default_server_name() -> String {
    "localhost".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct BenchmarkConfig {
    pub proto: ProtocolMode,
    pub mode: KeyExchangeMode,
    pub verification: VerificationMode,
    pub payload: u32,
    pub iters: u32,
    pub warmup: u32,
    pub concurrency: u32,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    pub server: SocketAddr,
    #[serde(default = "default_server_name")]
    pub server_name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub benchmarks: Vec<BenchmarkConfig>,
}

/// Load benchmark configuration from a TOML file.
///
/// # Errors
/// Returns an error if the file cannot be read or parsed.
impl TryFrom<&Path> for Config {
    type Error = error::Error;

    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        let content = read_to_string(path).map_err(|source| ConfigError::ReadError {
            source,
            path: path.to_owned(),
        })?;

        let src = NamedSource::new(path.display().to_string(), content.clone());

        let config = toml::from_str::<Self>(&content).map_err(|source| {
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
}

/// Create benchmark configuration from CLI arguments.
///
/// # Errors
/// Returns an error if `--server` was not provided.
impl TryFrom<Args> for Config {
    type Error = error::Error;

    fn try_from(args: Args) -> Result<Self, Self::Error> {
        Ok(Self {
            benchmarks: vec![BenchmarkConfig {
                proto: args.proto,
                mode: args.mode,
                verification: args.ca_cert.into(),
                payload: args.payload_bytes,
                iters: args.iters,
                warmup: args.warmup,
                concurrency: args.concurrency,
                timeout_secs: args.timeout_secs,
                server: args
                    .server
                    .ok_or_else(|| common::Error::config("--server is required"))?,
                server_name: args.server_name,
            }],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use std::path::PathBuf;

    const VALID_CONFIG: &str = r#"
[[benchmarks]]
proto = "raw"
mode = "x25519"
verification.kind = "insecure"
payload = 1024
iters = 100
warmup = 10
concurrency = 1
server = "127.0.0.1:4433"

[[benchmarks]]
proto = "http1"
mode = "x25519mlkem768"
verification = { kind = "cacert", path = "certs/ca.der" }
payload = 4096
iters = 50
warmup = 5
concurrency = 4
timeout_secs = 120
server = "127.0.0.1:4433"
server_name = "bench.example.com"
"#;

    fn get_config_from_str(toml: &str) -> Config {
        assert_ok!(toml::from_str::<Config>(toml))
    }

    #[test]
    fn valid_single_benchmark() {
        let toml = r#"
[[benchmarks]]
proto = "raw"
mode = "x25519"
verification.kind = "insecure"
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
        assert_eq!(config.benchmarks[0].timeout_secs, 30);
        assert_eq!(config.benchmarks[0].server_name, "localhost");
    }

    #[test]
    fn valid_multiple_benchmarks() {
        let config = get_config_from_str(VALID_CONFIG);
        assert_eq!(config.benchmarks.len(), 2);
        let bench_0 = config.benchmarks[0].clone();
        let bench_1 = config.benchmarks[1].clone();

        assert_eq!(bench_0.mode, KeyExchangeMode::X25519);
        assert_eq!(bench_0.proto, ProtocolMode::Raw);
        assert_eq!(bench_0.verification, VerificationMode::Insecure);
        assert_eq!(bench_0.server_name, "localhost");
        assert_eq!(bench_1.mode, KeyExchangeMode::X25519Mlkem768);
        assert_eq!(bench_1.proto, ProtocolMode::Http1);
        assert_eq!(bench_0.timeout_secs, 30);
        assert_eq!(bench_1.timeout_secs, 120);
        assert_eq!(bench_1.server_name, "bench.example.com");
        assert_eq!(
            bench_1.verification,
            VerificationMode::CaCert {
                path: PathBuf::from("certs/ca.der")
            }
        );
    }

    #[test]
    fn verification_insecure_deserializes_from_toml() {
        let toml = r#"
[[benchmarks]]
proto = "raw"
mode = "x25519"
verification.kind = "insecure"
payload = 1024
iters = 100
warmup = 10
concurrency = 1
server = "127.0.0.1:4433"
"#;

        let config = get_config_from_str(toml);
        assert_eq!(
            config.benchmarks[0].verification,
            VerificationMode::Insecure
        );
    }

    #[test]
    fn verification_ca_cert_deserializes_from_toml() {
        let toml = r#"
[[benchmarks]]
proto = "raw"
mode = "x25519"
verification = { kind = "cacert", path = "certs/ca.der" }
payload = 1024
iters = 100
warmup = 10
concurrency = 1
server = "127.0.0.1:4433"
"#;

        let config = get_config_from_str(toml);
        assert_eq!(
            config.benchmarks[0].verification,
            VerificationMode::CaCert {
                path: PathBuf::from("certs/ca.der"),
            }
        );
    }

    #[test]
    fn verification_string_form_is_rejected() {
        let toml = r#"
[[benchmarks]]
proto = "raw"
mode = "x25519"
verification = "insecure"
payload = 1024
iters = 100
warmup = 10
concurrency = 1
server = "127.0.0.1:4433"
"#;

        assert_err!(toml::from_str::<Config>(toml));
    }

    #[test]
    fn cli_args_without_ca_cert_default_to_insecure_verification() {
        let config = assert_ok!(Config::try_from(Args {
            proto: ProtocolMode::Raw,
            mode: KeyExchangeMode::X25519,
            server: Some("127.0.0.1:4433".parse().expect("socket addr")),
            payload_bytes: 1024,
            iters: 100,
            warmup: 10,
            concurrency: 1,
            timeout_secs: 30,
            out: None,
            run_meta_out: None,
            config: None,
            ca_cert: None,
            server_name: "localhost".to_string(),
        }));

        assert_eq!(
            config.benchmarks[0].verification,
            VerificationMode::Insecure
        );
        assert_eq!(config.benchmarks[0].server_name, "localhost");
    }

    #[test]
    fn cli_args_with_ca_cert_map_to_ca_cert_verification() {
        let config = assert_ok!(Config::try_from(Args {
            proto: ProtocolMode::Raw,
            mode: KeyExchangeMode::X25519,
            server: Some("127.0.0.1:4433".parse().expect("socket addr")),
            payload_bytes: 1024,
            iters: 100,
            warmup: 10,
            concurrency: 1,
            timeout_secs: 30,
            out: None,
            run_meta_out: None,
            config: None,
            ca_cert: Some(PathBuf::from("certs/ca.der")),
            server_name: "bench.example.com".to_string(),
        }));

        assert_eq!(
            config.benchmarks[0].verification,
            VerificationMode::CaCert {
                path: PathBuf::from("certs/ca.der"),
            }
        );
        assert_eq!(config.benchmarks[0].server_name, "bench.example.com");
    }

    #[test]
    fn invalid_proto() {
        let toml = r#"
[[benchmarks]]
proto = "invalid_proto"
mode = "x25519"
verification.kind = "insecure"
payload = 1024
iters = 100
warmup = 10
concurrency = 1
server = "127.0.0.1:4433"
"#;
        assert_err!(toml::from_str::<Config>(toml));
    }

    #[test]
    fn invalid_mode() {
        let toml = r#"
[[benchmarks]]
proto = "raw"
mode = "invalid_mode"
verification.kind = "insecure"
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
proto = "raw"
mode = "x25519"
verification.kind = "insecure"
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
proto = "raw"
mode = "x25519"
verification.kind = "insecure"
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
proto = "raw"
mode = "x25519"
verification.kind = "insecure"
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
}
