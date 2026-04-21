use crate::config::Config;
use common::{KeyExchangeMode, ProtocolMode, VerificationMode};
use miette::{Context, IntoDiagnostic};
use serde::Serialize;
use std::{
    env,
    fs::File,
    io::BufWriter,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
pub struct RunMetadata {
    pub run_id: Uuid,
    pub status: &'static str,
    pub error: Option<String>,
    pub started_at_unix_ms: u128,
    pub finished_at_unix_ms: u128,
    pub rust_version: &'static str,
    pub os: &'static str,
    pub arch: &'static str,
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

impl RunMetadata {
    #[must_use]
    pub fn from_config(
        run_id: Uuid,
        config: &Config,
        config_file: Option<PathBuf>,
        result_path: Option<PathBuf>,
        started_at_unix_ms: u128,
        finished_at_unix_ms: u128,
        error: Option<String>,
    ) -> Self {
        Self {
            run_id,
            status: if error.is_some() { "error" } else { "ok" },
            error,
            started_at_unix_ms,
            finished_at_unix_ms,
            rust_version: env!("RUSTC_VERSION"),
            os: env::consts::OS,
            arch: env::consts::ARCH,
            command: env::args().collect::<Vec<_>>().join(" "),
            config_file,
            result_path: env_path("TLS_PQ_BENCH_RESULT_PATH").or(result_path),
            log_path: env_path("TLS_PQ_BENCH_LOG_PATH"),
            schedule_profile: env_string("TLS_PQ_BENCH_SCHEDULE_PROFILE"),
            runner_git_commit: env_string("TLS_PQ_BENCH_RUNNER_GIT_COMMIT").or_else(git_commit),
            runner_host: env_string("TLS_PQ_BENCH_RUNNER_HOST").or_else(hostname),
            runner_instance_type: env_string("TLS_PQ_BENCH_RUNNER_INSTANCE_TYPE"),
            runner_region: env_string("TLS_PQ_BENCH_RUNNER_REGION"),
            runner_availability_zone: env_string("TLS_PQ_BENCH_RUNNER_AZ"),
            server_git_commit: env_string("TLS_PQ_BENCH_SERVER_GIT_COMMIT"),
            server_host: env_string("TLS_PQ_BENCH_SERVER_HOST"),
            server_instance_type: env_string("TLS_PQ_BENCH_SERVER_INSTANCE_TYPE"),
            server_region: env_string("TLS_PQ_BENCH_SERVER_REGION"),
            server_availability_zone: env_string("TLS_PQ_BENCH_SERVER_AZ"),
            benchmarks: config
                .benchmarks
                .iter()
                .map(|benchmark| BenchmarkMetadata {
                    server: benchmark.server.to_string(),
                    server_name: benchmark.server_name.clone(),
                    proto: benchmark.proto,
                    mode: benchmark.mode,
                    verification: benchmark.verification.clone(),
                    payload: benchmark.payload,
                    iters: benchmark.iters,
                    warmup: benchmark.warmup,
                    concurrency: benchmark.concurrency,
                    timeout_secs: benchmark.timeout_secs,
                })
                .collect(),
        }
    }
}

pub fn write_run_metadata(path: &Path, metadata: &RunMetadata) -> miette::Result<()> {
    let file = File::create(path)
        .into_diagnostic()
        .with_context(|| format!("failed to create run metadata file {}", path.display()))?;
    serde_json::to_writer_pretty(BufWriter::new(file), metadata)
        .into_diagnostic()
        .with_context(|| format!("failed to serialize run metadata to {}", path.display()))
}

#[inline]
#[must_use]
pub fn unix_time_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_millis()
}

fn env_string(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.is_empty())
}

fn env_path(name: &str) -> Option<PathBuf> {
    env_string(name).map(PathBuf::from)
}

fn hostname() -> Option<String> {
    env_string("HOSTNAME").or_else(|| {
        std::fs::read_to_string("/etc/hostname")
            .ok()
            .map(|hostname| hostname.trim().to_string())
            .filter(|hostname| !hostname.is_empty())
    })
}

fn git_commit() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let commit = String::from_utf8(output.stdout).ok()?;
    let commit = commit.trim();
    (!commit.is_empty()).then(|| commit.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::assert_ok;
    use common::{KeyExchangeMode, ProtocolMode};
    use std::{fs::read_to_string, net::SocketAddr, str::FromStr};

    #[test]
    fn write_run_metadata_serializes_json() {
        let path =
            std::env::temp_dir().join(format!("tls-pq-bench-run-meta-{}.json", std::process::id()));
        let config = Config {
            benchmarks: vec![crate::config::BenchmarkConfig {
                proto: ProtocolMode::Raw,
                mode: KeyExchangeMode::X25519,
                verification: VerificationMode::Insecure,
                payload: 1024,
                iters: 100,
                warmup: 10,
                concurrency: 1,
                timeout_secs: 30,
                server: SocketAddr::from_str("127.0.0.1:4433").expect("socket addr"),
                server_name: "localhost".to_string(),
            }],
        };

        let metadata = RunMetadata::from_config(
            Uuid::nil(),
            &config,
            Some(PathBuf::from("bench.toml")),
            Some(PathBuf::from("results.jsonl")),
            1,
            2,
            None,
        );

        assert_ok!(write_run_metadata(&path, &metadata));
        let content = read_to_string(&path).expect("metadata file should exist");

        assert!(content.contains(r#""run_id": "00000000-0000-0000-0000-000000000000""#));
        assert!(content.contains(r#""status": "ok""#));
        assert!(content.contains(r#""server": "127.0.0.1:4433""#));

        let _ = std::fs::remove_file(path);
    }
}
