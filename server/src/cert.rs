use crate::{args::CertArgs, error};
use base64::{Engine, prelude::BASE64_STANDARD};
use common::cert::{CaCertificate, ServerCertificate};
use std::{fs, path::Path};
use tracing::info;

pub fn get_cert(cert_args: &CertArgs) -> error::Result<ServerCertificate> {
    match cert_args.as_pair() {
        None => generate_self_cert(),
        Some((cert, key)) => load_cert_pair(cert, key),
    }
}

fn generate_self_cert() -> error::Result<ServerCertificate> {
    info!("Generating self-signed certificates...");
    let ca = CaCertificate::generate().map_err(common::Error::RCGen)?;
    let server_cert = ca
        .sign_server_cert("localhost")
        .map_err(common::Error::RCGen)?;
    info!(
        ca_cert_base64 = BASE64_STANDARD
            .encode(ca.cert_der)
            .chars()
            .take(256)
            .collect::<String>(),
        "CA cert (truncated)"
    );
    Ok(server_cert)
}

fn load_cert_pair(cert_path: &Path, key_path: &Path) -> error::Result<ServerCertificate> {
    let cert_der = fs::read(cert_path).map_err(|e| {
        error::Error::invalid_cert(format!(
            "failed to read certificate {}: {e}",
            cert_path.display()
        ))
    })?;
    let key_der = fs::read(key_path).map_err(|e| {
        error::Error::invalid_cert(format!(
            "failed to read private key {}: {e}",
            key_path.display()
        ))
    })?;

    if cert_der.is_empty() {
        return Err(error::Error::invalid_cert(format!(
            "certificate {} is empty",
            cert_path.display()
        )));
    }

    if key_der.is_empty() {
        return Err(error::Error::invalid_cert(format!(
            "private key {} is empty",
            key_path.display()
        )));
    }

    info!(cert = %cert_path.display(), key = %key_path.display(), "loading certificate pair from disk");

    Ok(ServerCertificate {
        cert_chain_der: vec![cert_der],
        private_key_der: key_der,
    })
}
