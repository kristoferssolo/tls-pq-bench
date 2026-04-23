use common::{BenchRecord, KeyExchangeMode, ProtocolMode, VerificationMode};
use serde::Deserialize;
use std::cmp::Ordering;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredRun {
    pub stem: String,
    pub result_path: PathBuf,
    pub meta_path: PathBuf,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DiscoveryDiagnostics {
    pub unmatched_results: Vec<PathBuf>,
    pub unmatched_meta: Vec<PathBuf>,
    pub invalid_pairings: Vec<InvalidPairing>,
}

impl DiscoveryDiagnostics {
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.unmatched_results.is_empty()
            && self.unmatched_meta.is_empty()
            && self.invalid_pairings.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidPairing {
    pub stem: String,
    pub result_paths: Vec<PathBuf>,
    pub meta_paths: Vec<PathBuf>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DiscoveryReport {
    pub runs: Vec<DiscoveredRun>,
    pub diagnostics: DiscoveryDiagnostics,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct BenchmarkMetadata {
    pub server: String,
    pub server_name: String,
    pub proto: ProtocolMode,
    pub mode: KeyExchangeMode,
    pub verification: VerificationMode,
    pub payload: u32,
    pub iters: u32,
    pub warmup: u32,
    pub concurrency: u32,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RunMetadata {
    pub run_id: Uuid,
    pub status: String,
    pub error: Option<String>,
    pub started_at_unix_ms: u128,
    pub finished_at_unix_ms: u128,
    pub rust_version: String,
    pub os: String,
    pub arch: String,
    pub command: String,
    pub config_file: Option<PathBuf>,
    pub result_path: Option<PathBuf>,
    pub log_path: Option<PathBuf>,
    pub schedule_profile: Option<String>,
    pub runner_git_commit: Option<String>,
    pub runner_host: Option<String>,
    pub runner_instance_type: Option<String>,
    pub runner_region: Option<String>,
    pub runner_availability_zone: Option<String>,
    pub server_git_commit: Option<String>,
    pub server_host: Option<String>,
    pub server_instance_type: Option<String>,
    pub server_region: Option<String>,
    pub server_availability_zone: Option<String>,
    pub benchmarks: Vec<BenchmarkMetadata>,
}

#[derive(Debug, Clone)]
pub struct ValidRun {
    pub discovered: DiscoveredRun,
    pub metadata: RunMetadata,
    pub records: Vec<BenchRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedRun {
    pub discovered: DiscoveredRun,
    pub reason: SkipReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    MetadataParseError {
        message: String,
    },
    ResultParseError {
        message: String,
    },
    MetadataStatusError {
        status: String,
        error: Option<String>,
    },
    EmptyResultFile,
    RunIdMismatch,
    ScenarioMismatch,
}

#[derive(Debug, Default, Clone)]
pub struct ValidationReport {
    pub valid_runs: Vec<ValidRun>,
    pub skipped_runs: Vec<SkippedRun>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioKey {
    pub schedule_profile: String,
    pub proto: ProtocolMode,
    pub mode: KeyExchangeMode,
    pub payload_bytes: u32,
    pub concurrency: u32,
}

impl Ord for ScenarioKey {
    fn cmp(&self, other: &Self) -> Ordering {
        (
            self.schedule_profile.as_str(),
            proto_order(self.proto),
            mode_order(self.mode),
            self.payload_bytes,
            self.concurrency,
        )
            .cmp(&(
                other.schedule_profile.as_str(),
                proto_order(other.proto),
                mode_order(other.mode),
                other.payload_bytes,
                other.concurrency,
            ))
    }
}

impl PartialOrd for ScenarioKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

const fn proto_order(proto: ProtocolMode) -> u8 {
    match proto {
        ProtocolMode::Raw => 0,
        ProtocolMode::Http1 => 1,
    }
}

const fn mode_order(mode: KeyExchangeMode) -> u8 {
    match mode {
        KeyExchangeMode::X25519 => 0,
        KeyExchangeMode::Secp256r1 => 1,
        KeyExchangeMode::X25519Mlkem768 => 2,
        KeyExchangeMode::Secp256r1Mlkem768 => 3,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MetricSummary {
    pub sample_count: usize,
    pub run_count: usize,
    pub mean: f64,
    pub min: u128,
    pub max: u128,
    pub p50: u128,
    pub p90: u128,
    pub p99: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunProvenance {
    pub run_id: Uuid,
    pub result_path: PathBuf,
    pub started_at_unix_ms: u128,
    pub finished_at_unix_ms: u128,
    pub runner_git_commit: Option<String>,
    pub runner_host: Option<String>,
    pub server_git_commit: Option<String>,
    pub server_host: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScenarioAggregate {
    pub key: ScenarioKey,
    pub tcp: MetricSummary,
    pub handshake: MetricSummary,
    pub ttlb: MetricSummary,
    pub provenance: Vec<RunProvenance>,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct AggregateReport {
    pub scenarios: Vec<ScenarioAggregate>,
}

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
