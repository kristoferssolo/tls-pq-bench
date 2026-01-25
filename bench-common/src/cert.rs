//! Self-signed certificate generation for local testing.
//!
//! Generates a CA certificate and server certificate for TLS benchmarking.
//! These certificates are NOT suitable for production use.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, SanType};

/// Generated certificate material for TLS server.
#[derive(Clone)]
pub struct ServerCertificate {
    /// DER-encoded certificate chain (server cert, then CA cert).
    pub cert_chain_der: Vec<Vec<u8>>,
    /// DER-encoded private key.
    pub private_key_der: Vec<u8>,
}

/// Generated CA certificate for client verification.
pub struct CaCertificate {
    /// DER-encoded CA certificate.
    pub cert_der: Vec<u8>,
    /// The CA key pair for signing.
    key_pair: KeyPair,
    /// The CA certificate params for creating an Issuer.
    params: CertificateParams,
}

impl CaCertificate {
    /// Generate a new self-signed CA certificate.
    ///
    /// # Errors
    /// Returns an error if certificate generation fails.
    pub fn generate() -> Result<Self, rcgen::Error> {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "tls-pq-bench CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "tls-pq-bench");

        let key_pair = KeyPair::generate()?;
        let cert = params.self_signed(&key_pair)?;

        Ok(Self {
            cert_der: cert.der().to_vec(),
            key_pair,
            params,
        })
    }

    /// Generate a server certificate signed by this CA.
    ///
    /// # Arguments
    /// * `server_name` - The server's DNS name (e.g., "localhost").
    ///
    /// # Errors
    /// Returns an error if certificate generation fails.
    pub fn sign_server_cert(&self, server_name: &str) -> Result<ServerCertificate, rcgen::Error> {
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, server_name);
        params.subject_alt_names = vec![
            SanType::DnsName(server_name.try_into()?),
            SanType::DnsName("localhost".try_into()?),
            SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            SanType::IpAddress(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        ];

        let server_key = KeyPair::generate()?;
        let issuer = Issuer::from_params(&self.params, &self.key_pair);
        let server_cert = params.signed_by(&server_key, &issuer)?;

        Ok(ServerCertificate {
            cert_chain_der: vec![server_cert.der().to_vec(), self.cert_der.clone()],
            private_key_der: server_key.serialize_der(),
        })
    }
}

/// Generate a complete certificate pair (CA + server) for testing.
///
/// # Arguments
/// * `server_name` - The server's DNS name (e.g., "localhost").
///
/// # Errors
/// Returns an error if certificate generation fails.
pub fn generate_test_certs(
    server_name: &str,
) -> Result<(CaCertificate, ServerCertificate), rcgen::Error> {
    let ca = CaCertificate::generate()?;
    let server = ca.sign_server_cert(server_name)?;
    Ok((ca, server))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_ca_certificate() {
        let ca = CaCertificate::generate().expect("CA generation should succeed");
        assert!(!ca.cert_der.is_empty());
    }

    #[test]
    fn generate_server_certificate() {
        let ca = CaCertificate::generate().expect("CA generation should succeed");
        let server = ca
            .sign_server_cert("localhost")
            .expect("server cert generation should succeed");
        assert_eq!(server.cert_chain_der.len(), 2);
        assert!(!server.private_key_der.is_empty());
    }

    #[test]
    fn generate_test_certs_helper() {
        let (ca, server) =
            generate_test_certs("test.local").expect("test cert generation should succeed");
        assert!(!ca.cert_der.is_empty());
        assert_eq!(server.cert_chain_der.len(), 2);
    }
}
