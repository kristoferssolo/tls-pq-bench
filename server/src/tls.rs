use crate::error;
use common::{KeyExchangeMode, cert::ServerCertificate};
use rustls::{
    ServerConfig,
    crypto::aws_lc_rs::{
        self,
        kx_group::{X25519, X25519MLKEM768},
    },
    pki_types::{CertificateDer, PrivateKeyDer},
    version::TLS13,
};
use std::sync::Arc;

/// Build TLS server config for the given key exchange mode.
pub fn build_tls_config(
    mode: KeyExchangeMode,
    server_cert: &ServerCertificate,
) -> error::Result<Arc<ServerConfig>> {
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = match mode {
        KeyExchangeMode::X25519 => vec![X25519],
        KeyExchangeMode::X25519Mlkem768 => vec![X25519MLKEM768],
    };

    let certs = server_cert
        .cert_chain_der
        .iter()
        .map(|der| CertificateDer::from(der.clone()))
        .collect::<Vec<_>>();

    let key = PrivateKeyDer::try_from(server_cert.private_key_der.clone())
        .map_err(|e| error::Error::invalid_cert(format!("invalid private_key: {e}")))?;

    let config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&TLS13])
        .map_err(common::Error::Tls)?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(common::Error::Tls)?;

    Ok(Arc::new(config))
}
