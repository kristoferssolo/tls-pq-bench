//! Common types and utilities for the TLS benchmark harness

pub mod cert;
pub mod error;
pub mod protocol;

pub use error::Error;
use serde::{Deserialize, Serialize};
use std::fmt;
use strum::{Display, EnumString};

/// TLS key exchange mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, EnumString, Display)]
#[strum(serialize_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum KeyExchangeMode {
    /// Classical X25519 ECDH.
    X25519,
    /// Hybrid post-quantum: X25519 + ML-KEM-768.
    X25519Mlkem768,
}

/// A single benchmark measurement record, output as NDJSON
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchRecord {
    /// Iteration number (0-indexed, excludes warmup)
    pub iteration: u64,
    /// Key exchange mode used
    pub mode: KeyExchangeMode,
    /// Payload size in bytes
    pub payload_bytes: u64,
    /// Handshake latency in nanoseconds
    pub handshake_ns: u64,
    /// Time-to-last-byte in nanoseconds (from connection start)
    pub ttlb_ns: u64,
}

impl BenchRecord {
    /// Serialize this record as a single NDJSON line (no trailing newline).
    ///
    /// # Errors
    /// Returns an error if serialization fails
    pub fn to_ndjson(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

impl fmt::Display for BenchRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_ndjson() {
            Ok(json) => write!(f, "{json}"),
            Err(e) => write!(f, r#"{{"error": "{e}"}}"#),
        }
    }
}

#[cfg(test)]
mod tests {
    use claims::{assert_err, assert_ok};
    use serde_json::Value;

    use super::*;
    use std::str::FromStr;

    #[test]
    fn bench_record_serializes_to_ndjson() {
        let record = BenchRecord {
            iteration: 0,
            mode: KeyExchangeMode::X25519,
            payload_bytes: 1024,
            handshake_ns: 1_000_000,
            ttlb_ns: 2_000_000,
        };
        let json = assert_ok!(record.to_ndjson());
        assert!(json.contains(r#""iteration":0"#));
        assert!(json.contains(r#""mode":"x25519""#));
        assert!(json.contains(r#""payload_bytes":1024"#));
    }

    #[test]
    fn bench_record_roundtrip() {
        let original = BenchRecord {
            iteration: 42,
            mode: KeyExchangeMode::X25519Mlkem768,
            payload_bytes: 4096,
            handshake_ns: 5_000_000,
            ttlb_ns: 10_000_000,
        };
        let json = assert_ok!(original.to_ndjson());
        let deserialized = assert_ok!(serde_json::from_str::<BenchRecord>(&json));

        assert_eq!(original.iteration, deserialized.iteration);
        assert_eq!(original.mode, deserialized.mode);
        assert_eq!(original.payload_bytes, deserialized.payload_bytes);
        assert_eq!(original.handshake_ns, deserialized.handshake_ns);
        assert_eq!(original.ttlb_ns, deserialized.ttlb_ns);
    }

    #[test]
    fn key_exchange_mode_from_str() {
        let mode = assert_ok!(KeyExchangeMode::from_str("x25519"));
        assert_eq!(mode, KeyExchangeMode::X25519);

        let mode = assert_ok!(KeyExchangeMode::from_str("x25519mlkem768"));
        assert_eq!(mode, KeyExchangeMode::X25519Mlkem768);
    }

    #[test]
    fn key_exchange_mode_parse_error() {
        assert_err!(KeyExchangeMode::from_str("invalid"));
        assert_err!(KeyExchangeMode::from_str("x25519invalid"));
        assert_err!(KeyExchangeMode::from_str(""));
    }

    #[test]
    fn key_exchange_mode_serde() {
        let json = r#"{"mode":"x25519mlkem768"}"#;
        let value = assert_ok!(serde_json::from_str::<Value>(json));
        let mode = assert_ok!(serde_json::from_value::<KeyExchangeMode>(
            value["mode"].clone()
        ));
        assert_eq!(mode, KeyExchangeMode::X25519Mlkem768);
    }

    #[test]
    fn key_exchange_mode_serde_case_insensitive() {
        let mode_lower = assert_ok!(serde_json::from_str::<KeyExchangeMode>(r#""x25519""#));
        assert_eq!(mode_lower, KeyExchangeMode::X25519);

        let mode_mlkem_lower = assert_ok!(serde_json::from_str::<KeyExchangeMode>(
            r#""x25519mlkem768""#
        ));
        assert_eq!(mode_mlkem_lower, KeyExchangeMode::X25519Mlkem768);
    }
}
