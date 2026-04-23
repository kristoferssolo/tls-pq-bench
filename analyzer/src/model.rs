use common::{BenchRecord, KeyExchangeMode, ProtocolMode, VerificationMode};
use serde::Deserialize;
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

#[allow(dead_code)]
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
