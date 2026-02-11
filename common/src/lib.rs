//! Common types and utilities for the TLS benchmark harness.

pub mod cert;
pub mod error;
pub mod protocol;

pub use error::Error;
use serde::{Deserialize, Serialize};
use std::fmt;
use strum::{Display, EnumString};

/// TLS key exchange mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, EnumString, Display)]
#[strum(serialize_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum KeyExchangeMode {
    /// Classical X25519 ECDH.
    X25519,
    /// Hybrid post-quantum: X25519 + ML-KEM-768.
    X25519Mlkem768,
}

/// A single benchmark measurement record, output as NDJSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchRecord {
    /// Iteration number (0-indexed, excludes warmup).
    pub iteration: u64,
    /// Key exchange mode used.
    pub mode: KeyExchangeMode,
    /// Payload size in bytes.
    pub payload_bytes: u64,
    /// Handshake latency in nanoseconds.
    pub handshake_ns: u64,
    /// Time-to-last-byte in nanoseconds (from connection start).
    pub ttlb_ns: u64,
}

impl BenchRecord {
    /// Serialize this record as a single NDJSON line (no trailing newline).
    ///
    /// # Errors
    /// Returns an error if serialization fails.
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
        let json = record.to_ndjson().expect("serialization should succeed");
        assert!(json.contains(r#""iteration":0"#));
        assert!(json.contains(r#""mode":"x25519""#));
        assert!(json.contains(r#""payload_bytes":1024"#));
    }

    #[test]
    fn key_exchange_mode_from_str() {
        assert_eq!(
            KeyExchangeMode::from_str("x25519").expect("should parse"),
            KeyExchangeMode::X25519
        );
        assert_eq!(
            KeyExchangeMode::from_str("x25519mlkem768").expect("should parse"),
            KeyExchangeMode::X25519Mlkem768
        );
    }
}
