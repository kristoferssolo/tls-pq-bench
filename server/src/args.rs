use clap::Parser;
use common::prelude::*;
use std::{net::SocketAddr, path::PathBuf};

/// TLS benchmark server.
#[derive(Debug, Parser)]
#[command(name = "server", version, about)]
pub struct Args {
    /// Key exchange mode
    #[arg(long, default_value = "x25519")]
    pub mode: KeyExchangeMode,

    /// Protocol carrier mode
    #[arg(long, default_value = "raw")]
    pub proto: ProtocolMode,

    /// Address to listen on
    #[arg(long, default_value = "127.0.0.1:4433")]
    pub listen: SocketAddr,

    #[command(flatten)]
    pub cert: CertArgs,
}

#[derive(Debug, Parser)]
#[group(id = "cert_pair", multiple = true)]
pub struct CertArgs {
    /// DER-encoded leaf certificate to present to clients
    #[arg(long, requires = "key")]
    pub cert: Option<PathBuf>,

    /// DER-encoded private key matching --cert
    #[arg(long, requires = "cert")]
    pub key: Option<PathBuf>,
}

impl CertArgs {
    pub fn as_pair(&self) -> Option<(&PathBuf, &PathBuf)> {
        self.cert.as_ref().zip(self.key.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::build_tls_config;
    use claims::assert_ok;
    use common::cert::CaCertificate;
    use std::sync::Arc;

    #[test]
    fn default_args() {
        let args = Args::parse_from(["server"]);
        assert_eq!(args.mode, KeyExchangeMode::X25519);
        assert_eq!(args.proto, ProtocolMode::Raw);
        assert_eq!(args.listen.to_string(), "127.0.0.1:4433");
    }

    #[test]
    fn custom_args() {
        let args = Args::parse_from([
            "server",
            "--mode",
            "x25519mlkem768",
            "--listen",
            "0.0.0.0:8080",
        ]);
        assert_eq!(args.mode, KeyExchangeMode::X25519Mlkem768);
        assert_eq!(args.listen.to_string(), "0.0.0.0:8080");
    }

    #[test]
    fn tls_config_x25519() {
        let ca = assert_ok!(CaCertificate::generate(), "generate CA");
        let server_cert = assert_ok!(ca.sign_server_cert("localhost"), "sign cert");
        let config = assert_ok!(
            build_tls_config(KeyExchangeMode::X25519, &server_cert),
            "build config"
        );
        assert!(Arc::strong_count(&config) >= 1);
    }

    #[test]
    fn tls_config_mlkem() {
        let ca = assert_ok!(CaCertificate::generate(), "generate CA");
        let server_cert = assert_ok!(ca.sign_server_cert("localhost"), "sign cert");
        let config = assert_ok!(
            build_tls_config(KeyExchangeMode::X25519Mlkem768, &server_cert),
            "build config"
        );
        assert!(Arc::strong_count(&config) >= 1);
    }

    #[test]
    fn tls_config_certificates() {
        let ca = assert_ok!(CaCertificate::generate(), "generate CA");
        let server_cert = assert_ok!(ca.sign_server_cert("localhost"), "sign cert");
        let config = assert_ok!(
            build_tls_config(KeyExchangeMode::X25519, &server_cert),
            "build config"
        );
        assert!(Arc::strong_count(&config) >= 1);
    }
}
