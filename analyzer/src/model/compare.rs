use crate::model::{MetricSummary, ordering::proto_order};
use common::{KeyExchangeMode, ProtocolMode};
use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComparisonContext {
    pub schedule_profile: String,
    pub proto: ProtocolMode,
    pub payload_bytes: u32,
    pub concurrency: u32,
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
