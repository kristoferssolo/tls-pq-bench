use crate::model::{MetricSummary, ScenarioKey, ordering::proto_order};
use common::{KeyExchangeMode, ProtocolMode};
use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComparisonContext {
    pub schedule_profile: String,
    pub proto: ProtocolMode,
    pub payload_bytes: u32,
    pub concurrency: u32,
}

impl From<&ScenarioKey> for ComparisonContext {
    fn from(key: &ScenarioKey) -> Self {
        Self {
            schedule_profile: key.schedule_profile.clone(),
            proto: key.proto,
            payload_bytes: key.payload_bytes,
            concurrency: key.concurrency,
        }
    }
}

impl Ord for ComparisonContext {
    fn cmp(&self, other: &Self) -> Ordering {
        (
            self.schedule_profile.as_str(),
            proto_order(self.proto),
            self.payload_bytes,
            self.concurrency,
        )
            .cmp(&(
                other.schedule_profile.as_str(),
                proto_order(other.proto),
                other.payload_bytes,
                other.concurrency,
            ))
    }
}

impl PartialOrd for ComparisonContext {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ComparisonFamily {
    X25519,
    Secp256r1,
}

impl ComparisonFamily {
    #[must_use]
    pub const fn from_mode(mode: KeyExchangeMode) -> Self {
        match mode {
            KeyExchangeMode::X25519 | KeyExchangeMode::X25519Mlkem768 => Self::X25519,
            KeyExchangeMode::Secp256r1 | KeyExchangeMode::Secp256r1Mlkem768 => Self::Secp256r1,
        }
    }

    #[must_use]
    pub const fn modes(self) -> (KeyExchangeMode, KeyExchangeMode) {
        match self {
            Self::X25519 => (KeyExchangeMode::X25519, KeyExchangeMode::X25519Mlkem768),
            Self::Secp256r1 => (
                KeyExchangeMode::Secp256r1,
                KeyExchangeMode::Secp256r1Mlkem768,
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Delta<T> {
    pub absolute: T,
    pub relative: Option<f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MetricComparison {
    pub classical: MetricSummary,
    pub pq: MetricSummary,
    pub mean: Delta<f64>,
    pub p50: Delta<i128>,
    pub p90: Delta<i128>,
    pub p99: Delta<i128>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PairwiseComparison {
    pub family: ComparisonFamily,
    pub context: ComparisonContext,
    pub classical_mode: KeyExchangeMode,
    pub pq_mode: KeyExchangeMode,
    pub tcp: MetricComparison,
    pub handshake: MetricComparison,
    pub ttlb: MetricComparison,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComparisonWarning {
    pub family: ComparisonFamily,
    pub context: ComparisonContext,
    pub metric: &'static str,
    pub field: &'static str,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct ComparisonReport {
    pub comparisons: Vec<PairwiseComparison>,
    pub warnings: Vec<ComparisonWarning>,
}
