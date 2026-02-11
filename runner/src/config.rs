use crate::{
    args::Args,
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

/// Validate the configuration after parsing.
fn validate_config(config: &Config, content: &str, path: &Path) -> error::Result<()> {
    if config.benchmarks.is_empty() {
        return Err(ConfigError::EmptyBenchmarks {
            src: NamedSource::new(path.display().to_string(), content.to_string()),
        }
        .into());
    }

    for (idx, benchmark) in config.benchmarks.iter().enumerate() {
        validate_benchmark(benchmark, idx, content, path)?;
    }

    Ok(())
}

/// Validate a single benchmark configuration.
fn validate_benchmark(
    benchmark: &BenchmarkConfig,
    idx: usize,
    content: &str,
    path: &Path,
) -> error::Result<()> {
    let src = NamedSource::new(path.display().to_string(), content.to_string());

    // Validate mode
    if benchmark.mode.parse::<KeyExchangeMode>().is_err() {
        return Err(ConfigError::ValidationError {
            src,
            span: find_field_span(content, idx, "mode"),
            field: "mode".into(),
            idx,
            message: format!(
                "Invalid key exchange mode '{}'. Valid values: 'x25519', 'x25519mlkem768'",
                benchmark.mode
            ),
        }
        .into());
    }

    if benchmark.payload == 0 {
        return Err(ConfigError::ValidationError {
            src,
            span: find_field_span(content, idx, "payload"),
            field: "payload".into(),
            idx,
            message: "Must be greater than 0".into(),
        }
        .into());
    }

    if benchmark.iters == 0 {
        return Err(ConfigError::ValidationError {
            src,
            span: find_field_span(content, idx, "iters"),
            field: "iters".into(),
            idx,
            message: "Must be greater than 0".into(),
        }
        .into());
    }

    if benchmark.concurrency == 0 {
        return Err(ConfigError::ValidationError {
            src,
            span: find_field_span(content, idx, "concurrency"),
            field: "concurrency".into(),
            idx,
            message: "Must be greater than 0".into(),
        }
        .into());
    }

    Ok(())
}

/// Find the span of a field in the TOML content for better error reporting.
fn find_field_span(content: &str, benchmark_idx: usize, field_name: &str) -> Option<SourceSpan> {
    let benchmark_section = find_benchmakr_section(content, benchmark_idx)?;
    find_field_in_section(content, benchmark_section, field_name)
}

fn find_benchmakr_section(content: &str, target_idx: usize) -> Option<(usize, usize)> {
    let mut current_idx = 0;
    let mut section_start = None;
    let mut byte_offset = 0;

    for line in content.lines() {
        let line_len = line.len() + 1; // +1 for newline

        if line.trim_start().starts_with("[[benchmarks]]") {
            if current_idx == target_idx {
                section_start = Some(byte_offset);
            } else if section_start.is_some() {
                return Some((section_start?, byte_offset));
            }
            current_idx += 1;
        }
        byte_offset += line_len;
    }
    section_start.map(|start| (start, content.len()))
}

fn find_field_in_section(
    content: &str,
    (start, end): (usize, usize),
    field_name: &str,
) -> Option<SourceSpan> {
    let section = &content[start..end];
    let mut byte_offset = start;

    for line in section.lines() {
        let line_len = line.len() + 1; // +1 for newline
        if line.trim_start().starts_with('[') && byte_offset != start {
            break;
        }

        if let Some(span) = extract_field_value_span(line, field_name, byte_offset) {
            return Some(span);
        }

        byte_offset += line_len;
    }

    None
}

fn extract_field_value_span(
    line: &str,
    field_name: &str,
    line_offset: usize,
) -> Option<SourceSpan> {
    let eq_idx = line.find('=')?;
    let field = line[..eq_idx].trim();

    if field != field_name {
        return None;
    }

    let after_eq = &line[eq_idx + 1..];
    let value_start_offset = after_eq.len() - after_eq.trim_start().len();
    let value_str = after_eq.trim_start();

    let value_start = line_offset + eq_idx + 1 + value_start_offset;
    let value_len = calculate_value_len(value_str);

    Some(SourceSpan::new(value_start.into(), value_len))
}

fn calculate_value_len(value_str: &str) -> usize {
    if let Some(stripped) = value_str.strip_prefix('"') {
        return stripped.find('"').map_or(value_str.len(), |i| i + 2);
    }

    value_str.find('#').map_or_else(
        || value_str.trim_end().len(),
        |i| value_str[..i].trim_end().len(),
    )
}
