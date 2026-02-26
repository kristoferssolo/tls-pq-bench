use miette::Diagnostic;
use thiserror::Error;

/// Result type using the `common`'s custom error type.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    /// File or network I/O error.
    #[error(transparent)]
    #[diagnostic(code(common::io_error))]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    #[diagnostic(code(common::rustls_error))]
    Tls(#[from] rustls::Error),

    /// TOML configuration file parse error.
    #[error(transparent)]
    #[diagnostic(code(common::toml_error))]
    Toml(#[from] toml::de::Error),

    #[error(transparent)]
    #[diagnostic(code(common::json_error))]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    #[diagnostic(code(common::rcgen_error))]
    RCGen(#[from] rcgen::Error),

    /// Configuration validation or missing required fields.
    #[error("Config error: {0}")]
    #[diagnostic(code(common::config_error))]
    Config(String),

    /// Invalid key exchange mode string.
    #[error("Invalid mode: {0}")]
    #[diagnostic(code(common::invalid_mode))]
    InvalidMode(String),

    /// Protocol-level error (malformed requests, unexpected responses).
    #[error("Protocol error: {0}")]
    #[diagnostic(code(common::protocol_error))]
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

    /// Create a protocol error.
    #[inline]
    pub fn protocol(error: impl Into<String>) -> Self {
        Self::Protocol(error.into())
    }
}
