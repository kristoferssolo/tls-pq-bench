use miette::Diagnostic;
use thiserror::Error;

/// Result type using the servers's custom error type.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error(transparent)]
    #[diagnostic(code(runner::common_error))]
    Common(#[from] common::Error),

    #[error(transparent)]
    #[diagnostic(code(server::cert_validation_error))]
    CertValidation(#[from] rustls::pki_types::InvalidDnsNameError),

    /// Network connection failure.
    #[error("Network error: {0}")]
    #[diagnostic(code(server::network_error))]
    Network(String),

    #[error("Invalid certificate: {0}")]
    #[diagnostic(code(server::invalid_cert))]
    InvalidCert(String),
}

impl Error {
    /// Create a network error.
    #[inline]
    pub fn network(error: impl Into<String>) -> Self {
        Self::Network(error.into())
    }

    #[inline]
    pub fn invalid_cert(error: impl Into<String>) -> Self {
        Self::InvalidCert(error.into())
    }
}
