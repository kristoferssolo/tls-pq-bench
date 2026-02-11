//! Error types for the benchmark runner.

use miette::Diagnostic;
use thiserror::Error;

/// Result type using the runner's custom error type.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during benchmark execution.
#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    /// TLS configuration or handshake failure.
    #[error(transparent)]
    #[diagnostic(code(runner::tls_error))]
    TlsConfig(#[from] rustls::Error),

    /// File or network I/O error.
    #[error(transparent)]
    #[diagnostic(code(runner::io_error))]
    Io(#[from] std::io::Error),

    /// TOML configuration file parse error.
    #[error(transparent)]
    #[diagnostic(code(runner::toml_error))]
    Toml(#[from] toml::de::Error),

    /// Invalid key exchange mode string.
    #[error("Invalid mode: {0}")]
    #[diagnostic(code(runner::invalid_mode))]
    InvalidMode(String),

    /// Configuration validation or missing required fields.
    #[error("Config error: {0}")]
    #[diagnostic(code(runner::config_error))]
    Config(String),

    /// Network connection failure.
    #[error("Network error: {0}")]
    #[diagnostic(code(runner::network_error))]
    Network(String),

    /// Protocol-level error (malformed requests, unexpected responses).
    #[error("Protocol error: {0}")]
    #[diagnostic(code(runner::protocol_error))]
    Protocol(String),
}

impl Error {
    /// Create an invalid mode error.
    #[inline]
    pub fn invalid_mode(error: impl Into<String>) -> Self {
        Self::InvalidMode(error.into())
    }

    /// Create a config error.
    #[inline]
    pub fn config(error: impl Into<String>) -> Self {
        Self::Config(error.into())
    }

    /// Create a network error.
    #[inline]
    pub fn network(error: impl Into<String>) -> Self {
        Self::Network(error.into())
    }

    /// Create a protocol error.
    #[inline]
    pub fn protocol(error: impl Into<String>) -> Self {
        Self::Protocol(error.into())
    }
}
