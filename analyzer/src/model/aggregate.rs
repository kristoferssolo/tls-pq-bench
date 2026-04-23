use crate::model::{
    ValidRun,
    ordering::{mode_order, proto_order},
};
use common::{KeyExchangeMode, ProtocolMode};
use std::cmp::Ordering;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioKey {
    pub schedule_profile: String,
    pub proto: ProtocolMode,
    pub mode: KeyExchangeMode,
    pub payload_bytes: u32,
    pub concurrency: u32,
}

impl ScenarioKey {
    #[must_use]
    pub fn from_run(run: &ValidRun) -> Option<Self> {
        let first = run.records.first()?;

        Some(Self {
            schedule_profile: run
                .metadata
                .schedule_profile
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            proto: first.proto,
            mode: first.mode,
            payload_bytes: first.payload_bytes,
            concurrency: first.concurrency,
        })
    }
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

impl From<&ValidRun> for RunProvenance {
    fn from(run: &ValidRun) -> Self {
        Self {
            run_id: run.metadata.run_id,
            result_path: run.discovered.result_path.clone(),
            started_at_unix_ms: run.metadata.started_at_unix_ms,
            finished_at_unix_ms: run.metadata.finished_at_unix_ms,
            runner_git_commit: run.metadata.runner_git_commit.clone(),
            runner_host: run.metadata.runner_host.clone(),
            server_git_commit: run.metadata.server_git_commit.clone(),
            server_host: run.metadata.server_host.clone(),
        }
    }
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
