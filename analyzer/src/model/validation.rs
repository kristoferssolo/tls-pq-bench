use crate::model::{DiscoveredRun, RunMetadata};
use common::BenchRecord;

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
