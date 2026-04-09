pub mod cert;
pub mod error;
pub mod prelude;
pub mod protocol;
pub mod telemetry;

use clap::ValueEnum;
pub use error::Error;
use serde::{Deserialize, Serialize};
use std::{fmt, path::PathBuf};
use strum::Display;
use uuid::Uuid;

/// TLS 1.3 key exchange mode used for benchmark runs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display, ValueEnum)]
#[strum(serialize_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum KeyExchangeMode {
    /// Classical X25519 ECDH.
    X25519,
    #[value(name = "secp256r1")]
    /// Classical NIST P-256 ECDH.
    Secp256r1,
    #[value(name = "x25519mlkem768")]
    /// Hybrid post-quantum: X25519 + ML-KEM-768.
    X25519Mlkem768,
    #[value(name = "secp256r1mlkem768")]
    /// Hybrid post-quantum: P-256 + ML-KEM-768.
    Secp256r1Mlkem768,
}

/// Application protocol carried over TLS in benchmark runs.
///
/// `Raw` is a minimal custom framing protocol (8-byte LE length request, then N payload bytes)
/// used for low-overhead microbenchmarks.
///
/// `Http1` is an HTTP/1.1 request/response mode (`GET /bytes/{n}`) used for realism-oriented
/// comparisons where HTTP parsing and headers are part of measured overhead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display, ValueEnum)]
#[strum(serialize_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum ProtocolMode {
    /// Minimal custom framing protocol for primary microbenchmarks.
    Raw,
    /// HTTP/1.1 mode for realism-oriented comparisons.
    Http1,
}

/// TLS certificate verification mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", tag = "kind")]
pub enum VerificationMode {
    /// Skip certificate verification (danger: MITM-vulnerable).
    Insecure,
    /// Verify against a custom CA certificate
    CaCert { path: PathBuf },
}

/// A single benchmark measurement record, output as JSONL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchRecord {
    /// Run ID
    pub run_id: Uuid,
    /// Iteration number (0-indexed, excludes warmup)
    pub iteration: u32,
    /// Protocol carrier mode
    pub proto: ProtocolMode,
    /// Key exchange mode used
    pub mode: KeyExchangeMode,
    /// Payload size in bytes
    pub payload_bytes: u32,
    /// Number of concurrent connections
    pub concurrency: u32,
    /// Number of benchmark iterations (excluding warmup)
    pub iters: u32,
    /// Number of warmup iterations
    pub warmup: u32,
    /// TCP connection latency in nanoseconds
    pub tcp_ns: u128,
    /// Handshake latency in nanoseconds
    pub handshake_ns: u128,
    /// Time-to-last-byte in nanoseconds (from connection start)
    pub ttlb_ns: u128,
}

impl BenchRecord {
    #[allow(clippy::too_many_arguments)]
    #[inline]
    #[must_use]
    pub const fn new(
        run_id: Uuid,
        iteration: u32,
        proto: ProtocolMode,
        mode: KeyExchangeMode,
        payload_bytes: u32,
        concurrency: u32,
        iters: u32,
        warmup: u32,
        tcp_ns: u128,
        handshake_ns: u128,
        ttlb_ns: u128,
    ) -> Self {
        Self {
            run_id,
            iteration,
            proto,
            mode,
            payload_bytes,
            concurrency,
            iters,
            warmup,
            tcp_ns,
            handshake_ns,
            ttlb_ns,
        }
    }
    /// Serialize this record as a single JSONL line (no trailing newline).
    ///
    /// # Errors
    /// Returns an error if serialization fails
    pub fn to_jsonl(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

impl fmt::Display for BenchRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_jsonl() {
            Ok(json) => write!(f, "{json}"),
            Err(e) => write!(f, r#"{{"error": "{e}"}}"#),
        }
    }
}

impl From<Option<PathBuf>> for VerificationMode {
    fn from(ca_cert_path: Option<PathBuf>) -> Self {
        ca_cert_path.map_or(Self::Insecure, |path| Self::CaCert { path })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use serde_json::Value;

    #[test]
    fn bench_record_serializes_to_jsonl() {
        let record = BenchRecord {
            run_id: Uuid::new_v4(),
            iteration: 0,
            proto: ProtocolMode::Raw,
            mode: KeyExchangeMode::X25519,
            payload_bytes: 1024,
            concurrency: 1,
            iters: 4,
            warmup: 4,
            tcp_ns: 500_000,
            handshake_ns: 1_000_000,
            ttlb_ns: 2_000_000,
        };
        let json = assert_ok!(record.to_jsonl());
        assert!(json.contains(r#""iteration":0"#));
        assert!(json.contains(r#""proto":"raw""#));
        assert!(json.contains(r#""mode":"x25519""#));
        assert!(json.contains(r#""payload_bytes":1024"#));
    }

    #[test]
    fn bench_record_roundtrip() {
        let original = BenchRecord {
            run_id: Uuid::new_v4(),
            iteration: 42,
            proto: ProtocolMode::Http1,
            mode: KeyExchangeMode::X25519Mlkem768,
            payload_bytes: 4096,
            concurrency: 1,
            iters: 4,
            warmup: 4,
            tcp_ns: 1_000_000,
            handshake_ns: 5_000_000,
            ttlb_ns: 10_000_000,
        };
        let json = assert_ok!(original.to_jsonl());
        let deserialized = assert_ok!(serde_json::from_str::<BenchRecord>(&json));

        assert_eq!(original.iteration, deserialized.iteration);
        assert_eq!(original.proto, deserialized.proto);
        assert_eq!(original.mode, deserialized.mode);
        assert_eq!(original.payload_bytes, deserialized.payload_bytes);
        assert_eq!(original.handshake_ns, deserialized.handshake_ns);
        assert_eq!(original.ttlb_ns, deserialized.ttlb_ns);
    }

    #[test]
    fn key_exchange_mode_parse_error() {
        assert_err!(KeyExchangeMode::from_str("invalid", true));
        assert_err!(KeyExchangeMode::from_str("x25519invalid", true));
        assert_err!(KeyExchangeMode::from_str("", true));
    }

    #[test]
    fn key_exchange_mode_serde() {
        let json = r#"{"mode":"x25519mlkem768"}"#;
        let value = assert_ok!(serde_json::from_str::<Value>(json));
        let mode = assert_ok!(serde_json::from_value::<KeyExchangeMode>(
            value["mode"].clone()
        ));
        assert_eq!(mode, KeyExchangeMode::X25519Mlkem768);

        let json = r#"{"mode":"secp256r1mlkem768"}"#;
        let value = assert_ok!(serde_json::from_str::<Value>(json));
        let mode = assert_ok!(serde_json::from_value::<KeyExchangeMode>(
            value["mode"].clone()
        ));
        assert_eq!(mode, KeyExchangeMode::Secp256r1Mlkem768);
    }

    #[test]
    fn key_exchange_mode_serde_case_insensitive() {
        let mode_lower = assert_ok!(serde_json::from_str::<KeyExchangeMode>(r#""x25519""#));
        assert_eq!(mode_lower, KeyExchangeMode::X25519);

        let mode_p256_lower = assert_ok!(serde_json::from_str::<KeyExchangeMode>(r#""secp256r1""#));
        assert_eq!(mode_p256_lower, KeyExchangeMode::Secp256r1);

        let mode_mlkem_lower = assert_ok!(serde_json::from_str::<KeyExchangeMode>(
            r#""x25519mlkem768""#
        ));
        assert_eq!(mode_mlkem_lower, KeyExchangeMode::X25519Mlkem768);

        let mode_p256_mlkem_lower = assert_ok!(serde_json::from_str::<KeyExchangeMode>(
            r#""secp256r1mlkem768""#
        ));
        assert_eq!(mode_p256_mlkem_lower, KeyExchangeMode::Secp256r1Mlkem768);
    }

    #[test]
    fn key_protocol_mod_from_str() {
        let proto = assert_ok!(ProtocolMode::from_str("raw", true));
        assert_eq!(proto, ProtocolMode::Raw);

        let proto = assert_ok!(ProtocolMode::from_str("http1", true));
        assert_eq!(proto, ProtocolMode::Http1);
    }

    #[test]
    fn key_protocol_mode_parse_error() {
        assert_err!(ProtocolMode::from_str("invalid", true));
        assert_err!(ProtocolMode::from_str("", true));
    }

    #[test]
    fn key_exchange_mode_from_str() {
        let mode = assert_ok!(KeyExchangeMode::from_str("x25519", true));
        assert_eq!(mode, KeyExchangeMode::X25519);

        let mode = assert_ok!(KeyExchangeMode::from_str("x25519mlkem768", true));
        assert_eq!(mode, KeyExchangeMode::X25519Mlkem768);

        let mode = assert_ok!(KeyExchangeMode::from_str("secp256r1", true));
        assert_eq!(mode, KeyExchangeMode::Secp256r1);

        let mode = assert_ok!(KeyExchangeMode::from_str("secp256r1mlkem768", true));
        assert_eq!(mode, KeyExchangeMode::Secp256r1Mlkem768);
    }

    #[test]
    fn key_protocol_mode_serde() {
        let json = r#"{"proto":"http1"}"#;
        let value = assert_ok!(serde_json::from_str::<Value>(json));
        let proto = assert_ok!(serde_json::from_value::<ProtocolMode>(
            value["proto"].clone()
        ));
        assert_eq!(proto, ProtocolMode::Http1);
    }
}
