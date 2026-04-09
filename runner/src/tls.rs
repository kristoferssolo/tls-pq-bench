use common::{VerificationMode, prelude::*};
use miette::{Context, IntoDiagnostic};
use rustls::{
    ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    compress::CompressionCache,
    crypto::aws_lc_rs::{
        self,
        kx_group::{SECP256R1, SECP256R1MLKEM768, X25519, X25519MLKEM768},
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
    version::TLS13,
};
use std::{fs, path::Path, sync::Arc};

/// Certificate verifier that accepts any certificate.
/// Used for benchmarking where we don't need to verify the server's identity.
#[derive(Debug)]
pub struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

/// Build TLS client config for the given key exchange mode.
pub fn build_tls_config(
    mode: KeyExchangeMode,
    verification: &VerificationMode,
) -> miette::Result<ClientConfig> {
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = match mode {
        KeyExchangeMode::X25519 => vec![X25519],
        KeyExchangeMode::Secp256r1 => vec![SECP256R1],
        KeyExchangeMode::X25519Mlkem768 => vec![X25519MLKEM768],
        KeyExchangeMode::Secp256r1Mlkem768 => vec![SECP256R1MLKEM768],
    };

    let builder = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&TLS13])
        .into_diagnostic()
        .context("failed to set TLS versions")?;

    let mut config = match verification {
        VerificationMode::Insecure => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth(),
        VerificationMode::CaCert { path } => {
            let roots = load_roots_store(path)?;
            builder.with_root_certificates(roots).with_no_client_auth()
        }
    };

    config.cert_compression_cache = Arc::new(CompressionCache::Disabled);

    Ok(config)
}

fn load_roots_store<P: AsRef<Path>>(ca_cert_path: &P) -> miette::Result<RootCertStore> {
    let cert_bytes = fs::read(ca_cert_path).into_diagnostic().with_context(|| {
        format!(
            "failed to read CA certificate {}",
            ca_cert_path.as_ref().display()
        )
    })?;

    let mut roots = RootCertStore::empty();

    roots
        .add(CertificateDer::from(cert_bytes))
        .into_diagnostic()
        .context("failed to add CA certificate to root store")?;

    Ok(roots)
}
