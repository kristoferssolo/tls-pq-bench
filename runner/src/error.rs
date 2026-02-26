#![allow(unused)]
//! Error types for the benchmark runner.

use miette::{Diagnostic, NamedSource, SourceSpan};
use std::path::PathBuf;
use thiserror::Error;

/// Result type using the `runner`'s custom error type.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during benchmark execution.
#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error(transparent)]
    #[diagnostic(code(runner::common_error))]
    Common(#[from] common::Error),

    #[error(transparent)]
    #[diagnostic(transparent)]
    Config(#[from] Box<ConfigError>),

    /// Network connection failure.
    #[error("Network error: {0}")]
    #[diagnostic(code(runner::network_error))]
    Network(String),
}

impl Error {
    /// Create a network error.
    #[inline]
    pub fn network(error: impl Into<String>) -> Self {
        Self::Network(error.into())
    }
}

#[derive(Debug, Error, Diagnostic)]
pub enum ConfigError {
    #[error("Failed to read config file: {path}")]
    #[diagnostic(
        code(config::read_error),
        help("Make sure the file exists and you have read permissions")
    )]
    ReadError {
        #[source]
        source: std::io::Error,
        path: PathBuf,
    },

    #[error("Invalid TOML syntax in config file")]
    #[diagnostic(code(config::toml_parse_error))]
    TomlParseError {
        #[source_code]
        src: NamedSource<String>,
        #[label("here")]
        span: Option<SourceSpan>,
        #[source]
        source: toml::de::Error,
    },

    #[error("Invalid value for field '{field}' in benchmarks[{idx}]")]
    #[diagnostic(code(config::validation_error))]
    ValidationError {
        #[source_code]
        src: NamedSource<String>,
        #[label("{message}")]
        span: Option<SourceSpan>,
        field: String,
        idx: usize,
        message: String,
    },

    #[error("Configuration must contain at least one [[benchmarks]] entry")]
    #[diagnostic(
        code(config::empty_benchmarks),
        help("Add at least one [[benchmarks]] section to your config file")
    )]
    EmptyBenchmarks {
        #[source_code]
        src: NamedSource<String>,
    },
}

impl From<ConfigError> for Error {
    fn from(err: ConfigError) -> Self {
        Self::Config(Box::new(err))
    }
}
