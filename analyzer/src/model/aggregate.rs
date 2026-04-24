use crate::model::{
    ValidRun,
    ordering::{mode_order, proto_order},
};
use common::{BenchRecord, KeyExchangeMode, ProtocolMode};
use std::path::PathBuf;
use std::{cmp::Ordering, collections::BTreeSet};
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
    pub const fn from_record(schedule_profile: String, record: &BenchRecord) -> Self {
        Self {
            schedule_profile,
            proto: record.proto,
            mode: record.mode,
            payload_bytes: record.payload_bytes,
            concurrency: record.concurrency,
        }
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
    pub iters: u32,
    pub warmup: u32,
}

impl RunProvenance {
    #[must_use]
    pub fn from_run(run: &ValidRun, record: &BenchRecord) -> Self {
        Self {
            run_id: run.metadata.run_id,
            result_path: run.discovered.result_path.clone(),
            started_at_unix_ms: run.metadata.started_at_unix_ms,
            finished_at_unix_ms: run.metadata.finished_at_unix_ms,
            runner_git_commit: run.metadata.runner_git_commit.clone(),
            runner_host: run.metadata.runner_host.clone(),
            server_git_commit: run.metadata.server_git_commit.clone(),
            server_host: run.metadata.server_host.clone(),
            iters: record.iters,
            warmup: record.warmup,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioProvenance {
    pub run_ids: Vec<Uuid>,
    pub result_paths: Vec<PathBuf>,
    pub started_at_unix_ms: Vec<u128>,
    pub finished_at_unix_ms: Vec<u128>,
    pub runner_hosts: Vec<String>,
    pub runner_git_commits: Vec<String>,
    pub server_hosts: Vec<String>,
    pub server_git_commits: Vec<String>,
    pub iters: Vec<u32>,
    pub warmup: Vec<u32>,
    pub runs: Vec<RunProvenance>,
}

impl ScenarioProvenance {
    #[must_use]
    pub fn from_runs(runs: Vec<RunProvenance>) -> Self {
        Self {
            run_ids: runs.iter().map(|run| run.run_id).collect(),
            result_paths: runs.iter().map(|run| run.result_path.clone()).collect(),
            started_at_unix_ms: runs.iter().map(|run| run.started_at_unix_ms).collect(),
            finished_at_unix_ms: runs.iter().map(|run| run.finished_at_unix_ms).collect(),
            runner_hosts: unique_strings(runs.iter().filter_map(|run| run.runner_host.as_deref())),
            runner_git_commits: unique_strings(
                runs.iter()
                    .filter_map(|run| run.runner_git_commit.as_deref()),
            ),
            server_hosts: unique_strings(runs.iter().filter_map(|run| run.server_host.as_deref())),
            server_git_commits: unique_strings(
                runs.iter()
                    .filter_map(|run| run.server_git_commit.as_deref()),
            ),
            iters: unique_numbers(runs.iter().map(|run| run.iters)),
            warmup: unique_numbers(runs.iter().map(|run| run.warmup)),
            runs,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScenarioAggregate {
    pub key: ScenarioKey,
    pub tcp: MetricSummary,
    pub handshake: MetricSummary,
    pub ttlb: MetricSummary,
    pub provenance: ScenarioProvenance,
    pub warnings: Vec<String>,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct AggregateReport {
    pub scenarios: Vec<ScenarioAggregate>,
}

fn unique_strings<'a>(values: impl Iterator<Item = &'a str>) -> Vec<String> {
    values
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn unique_numbers<T>(values: impl Iterator<Item = T>) -> Vec<T>
where
    T: Ord,
{
    values.collect::<BTreeSet<_>>().into_iter().collect()
}
