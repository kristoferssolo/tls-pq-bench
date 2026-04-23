use common::{KeyExchangeMode, ProtocolMode, VerificationMode};
use serde::Deserialize;
use std::path::PathBuf;
use uuid::Uuid;

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
