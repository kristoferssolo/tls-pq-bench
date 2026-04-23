use crate::model::RunMetadata;
use common::BenchRecord;
use miette::{Context, IntoDiagnostic};
use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

#[allow(dead_code)]
pub fn load_bench_records(path: &Path) -> miette::Result<Vec<BenchRecord>> {
    let file = File::open(path)
        .into_diagnostic()
        .with_context(|| format!("failed to open result file {}", path.display()))?;
    let reader = BufReader::new(file);

    let mut records = Vec::new();
    for (line_index, line) in reader.lines().enumerate() {
        let line = line
            .into_diagnostic()
            .with_context(|| format!("failed to read result file {}", path.display()))?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let record = serde_json::from_str::<BenchRecord>(line)
            .into_diagnostic()
            .with_context(|| {
                format!(
                    "failed to parse JSONL record at {}:{}",
                    path.display(),
                    line_index + 1
                )
            })?;
        records.push(record);
    }

    Ok(records)
}

#[allow(dead_code)]
pub fn load_run_metadata(path: &Path) -> miette::Result<RunMetadata> {
    let file = File::open(path)
        .into_diagnostic()
        .with_context(|| format!("failed to open metadata file {}", path.display()))?;

    serde_json::from_reader(BufReader::new(file))
        .into_diagnostic()
        .with_context(|| format!("failed to parse metadata file {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn parses_valid_jsonl_records() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("results.jsonl");
        std::fs::write(
            &path,
            concat!(
                r##"{"run_id":"00000000-0000-0000-0000-000000000001","iteration":0,"##,
                r##""proto":"raw","mode":"x25519","payload_bytes":1024,"##,
                r##""concurrency":1,"iters":2,"warmup":1,"tcp_ns":10,"##,
                r##""handshake_ns":20,"ttlb_ns":30}"##,
                "\n",
                "\n",
                r##"{"run_id":"00000000-0000-0000-0000-000000000001","iteration":1,"##,
                r##""proto":"raw","mode":"x25519","payload_bytes":1024,"##,
                r##""concurrency":1,"iters":2,"warmup":1,"tcp_ns":11,"##,
                r##""handshake_ns":21,"ttlb_ns":31}"##,
                "\n"
            ),
        )
        .expect("result file");

        let records = assert_ok!(load_bench_records(&path), "records should parse");

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].tcp_ns, 10);
        assert_eq!(records[1].iteration, 1);
    }

    #[test]
    fn rejects_malformed_jsonl_records() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("results.jsonl");
        fs::write(&path, "{not json}\n").expect("result file");

        let error = assert_err!(load_bench_records(&path), "records should fail");

        assert!(format!("{error:?}").contains("failed to parse JSONL record"));
    }

    #[test]
    fn parses_valid_metadata_json() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("run.meta");
        std::fs::write(
            &path,
            concat!(
                r##"{"##,
                r##""run_id":"00000000-0000-0000-0000-000000000001","##,
                r##""status":"ok","##,
                r##""error":null,"##,
                r##""started_at_unix_ms":1,"##,
                r##""finished_at_unix_ms":2,"##,
                r##""rust_version":"rustc 1.0.0","##,
                r##""os":"linux","##,
                r##""arch":"x86_64","##,
                r##""command":"runner --config bench.toml","##,
                r##""config_file":"bench.toml","##,
                r##""result_path":"results.jsonl","##,
                r##""log_path":"run.log","##,
                r##""schedule_profile":"lite","##,
                r##""runner_git_commit":"abc","##,
                r##""runner_host":"runner-1","##,
                r##""runner_instance_type":null,"##,
                r##""runner_region":null,"##,
                r##""runner_availability_zone":null,"##,
                r##""server_git_commit":"def","##,
                r##""server_host":"server-1","##,
                r##""server_instance_type":null,"##,
                r##""server_region":null,"##,
                r##""server_availability_zone":null,"##,
                r##""benchmarks":[{"##,
                r##""server":"127.0.0.1:4433","##,
                r##""server_name":"localhost","##,
                r##""proto":"raw","##,
                r##""mode":"x25519","##,
                r##""verification":{"kind":"insecure"},"##,
                r##""payload":1024,"##,
                r##""iters":100,"##,
                r##""warmup":10,"##,
                r##""concurrency":1,"##,
                r##""timeout_secs":30"##,
                r##"}]}"##
            ),
        )
        .expect("metadata file");

        let metadata = assert_ok!(load_run_metadata(&path), "metadata should parse");

        assert_eq!(metadata.status, "ok");
        assert_eq!(metadata.schedule_profile.as_deref(), Some("lite"));
        assert_eq!(metadata.benchmarks.len(), 1);
        assert_eq!(metadata.benchmarks[0].payload, 1024);
    }

    #[test]
    fn rejects_malformed_metadata_json() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("run.meta");
        fs::write(&path, "{").expect("metadata file");

        let error = assert_err!(load_run_metadata(&path), "metadata should fail");

        assert!(format!("{error:?}").contains("failed to parse metadata file"));
    }
}
