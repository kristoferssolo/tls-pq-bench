use crate::{
    error::{Error, Result},
    load::{load_bench_records, load_run_metadata},
    model::{
        BenchmarkMetadata, DiscoveredRun, RunMetadata, SkipReason, SkippedRun, ValidRun,
        ValidationReport,
    },
};
use common::{BenchRecord, KeyExchangeMode, ProtocolMode};
use std::{cmp::Ordering, collections::BTreeSet};

pub fn validate_runs(
    discovered_runs: Vec<DiscoveredRun>,
    strict: bool,
) -> Result<ValidationReport> {
    let mut report = ValidationReport::default();

    for discovered in discovered_runs {
        let Some(metadata) = parse_metadata(&discovered, strict, &mut report)? else {
            continue;
        };
        let Some(records) = parse_records(&discovered, strict, &mut report)? else {
            continue;
        };

        if let Some(reason) = validation_failure(&discovered, &metadata, &records, strict)? {
            report.skipped_runs.push(SkippedRun { discovered, reason });
            continue;
        }

        report.valid_runs.push(ValidRun {
            discovered,
            metadata,
            records,
        });
    }

    Ok(report)
}

fn parse_metadata(
    discovered: &DiscoveredRun,
    strict: bool,
    report: &mut ValidationReport,
) -> Result<Option<RunMetadata>> {
    match load_run_metadata(&discovered.meta_path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) => {
            if strict {
                return Err(error);
            }
            report.skipped_runs.push(SkippedRun {
                discovered: discovered.clone(),
                reason: SkipReason::MetadataParseError {
                    message: error.to_string(),
                },
            });
            Ok(None)
        }
    }
}

fn parse_records(
    discovered: &DiscoveredRun,
    strict: bool,
    report: &mut ValidationReport,
) -> Result<Option<Vec<BenchRecord>>> {
    match load_bench_records(&discovered.result_path) {
        Ok(records) => Ok(Some(records)),
        Err(error) => {
            if strict {
                return Err(error);
            }
            report.skipped_runs.push(SkippedRun {
                discovered: discovered.clone(),
                reason: SkipReason::ResultParseError {
                    message: error.to_string(),
                },
            });
            Ok(None)
        }
    }
}

fn validation_failure(
    discovered: &DiscoveredRun,
    metadata: &RunMetadata,
    records: &[BenchRecord],
    strict: bool,
) -> Result<Option<SkipReason>> {
    if metadata.status != "ok" {
        return non_strict_skip_or_error(
            strict,
            SkipReason::MetadataStatusError {
                status: metadata.status.clone(),
                error: metadata.error.clone(),
            },
            format!(
                "run {} is not successful: status={}",
                discovered.meta_path.display(),
                metadata.status
            ),
        );
    }

    if records.is_empty() {
        return non_strict_skip_or_error(
            strict,
            SkipReason::EmptyResultFile,
            format!(
                "result file {} contains no benchmark records",
                discovered.result_path.display()
            ),
        );
    }

    if !all_records_share_run_id(records) {
        return non_strict_skip_or_error(
            strict,
            SkipReason::RunIdMismatch,
            format!(
                "result file {} contains multiple run_id values",
                discovered.result_path.display()
            ),
        );
    }

    if !records_match_benchmarks(metadata, records) {
        return non_strict_skip_or_error(
            strict,
            SkipReason::ScenarioMismatch,
            format!(
                "result file {} contains records that do not match metadata benchmarks",
                discovered.result_path.display()
            ),
        );
    }

    Ok(None)
}

fn non_strict_skip_or_error(
    strict: bool,
    reason: SkipReason,
    message: String,
) -> Result<Option<SkipReason>> {
    if strict {
        return Err(Error::StrictValidation { message });
    }

    Ok(Some(reason))
}

fn all_records_share_run_id(records: &[BenchRecord]) -> bool {
    let Some(first) = records.first() else {
        return true;
    };
    records.iter().all(|record| record.run_id == first.run_id)
}

fn records_match_benchmarks(metadata: &RunMetadata, records: &[BenchRecord]) -> bool {
    let benchmarks = metadata
        .benchmarks
        .iter()
        .map(BenchmarkKey::from)
        .collect::<BTreeSet<_>>();

    !benchmarks.is_empty()
        && records
            .iter()
            .map(BenchmarkKey::from)
            .all(|record| benchmarks.contains(&record))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BenchmarkKey {
    proto: common::ProtocolMode,
    mode: common::KeyExchangeMode,
    payload_bytes: u32,
    concurrency: u32,
    iters: u32,
    warmup: u32,
}

impl Ord for BenchmarkKey {
    fn cmp(&self, other: &Self) -> Ordering {
        (
            benchmark_proto_order(self.proto),
            benchmark_mode_order(self.mode),
            self.payload_bytes,
            self.concurrency,
            self.iters,
            self.warmup,
        )
            .cmp(&(
                benchmark_proto_order(other.proto),
                benchmark_mode_order(other.mode),
                other.payload_bytes,
                other.concurrency,
                other.iters,
                other.warmup,
            ))
    }
}

impl PartialOrd for BenchmarkKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

const fn benchmark_proto_order(proto: ProtocolMode) -> u8 {
    match proto {
        ProtocolMode::Raw => 0,
        ProtocolMode::Http1 => 1,
    }
}

const fn benchmark_mode_order(mode: KeyExchangeMode) -> u8 {
    match mode {
        KeyExchangeMode::X25519 => 0,
        KeyExchangeMode::Secp256r1 => 1,
        KeyExchangeMode::X25519Mlkem768 => 2,
        KeyExchangeMode::Secp256r1Mlkem768 => 3,
    }
}

impl From<&BenchRecord> for BenchmarkKey {
    fn from(record: &BenchRecord) -> Self {
        Self {
            proto: record.proto,
            mode: record.mode,
            payload_bytes: record.payload_bytes,
            concurrency: record.concurrency,
            iters: record.iters,
            warmup: record.warmup,
        }
    }
}

impl From<&BenchmarkMetadata> for BenchmarkKey {
    fn from(benchmark: &BenchmarkMetadata) -> Self {
        Self {
            proto: benchmark.proto,
            mode: benchmark.mode,
            payload_bytes: benchmark.payload,
            concurrency: benchmark.concurrency,
            iters: benchmark.iters,
            warmup: benchmark.warmup,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn validates_successful_run_pair() {
        let dir = TempDir::new().expect("temp dir");
        let discovered = write_discovered_run(
            &dir,
            "lite-ok",
            &valid_jsonl(
                "00000000-0000-0000-0000-000000000001",
                r#""mode":"x25519","payload_bytes":1024,"concurrency":1,"iters":2,"warmup":1"#,
            ),
            &valid_meta("ok", None, Some("lite")),
        );

        let report = assert_ok!(validate_runs(vec![discovered], false));

        assert_eq!(report.valid_runs.len(), 1);
        assert!(report.skipped_runs.is_empty());
    }

    #[test]
    fn validates_multi_scenario_run_pair() {
        let dir = TempDir::new().expect("temp dir");
        let discovered = write_discovered_run(
            &dir,
            "lite-matrix",
            concat!(
                r#"{"run_id":"00000000-0000-0000-0000-000000000001","iteration":0,"proto":"raw","mode":"x25519","payload_bytes":1024,"concurrency":1,"iters":2,"warmup":1,"tcp_ns":10,"handshake_ns":20,"ttlb_ns":30}"#,
                "\n",
                r#"{"run_id":"00000000-0000-0000-0000-000000000001","iteration":1,"proto":"raw","mode":"x25519","payload_bytes":1024,"concurrency":1,"iters":2,"warmup":1,"tcp_ns":11,"handshake_ns":21,"ttlb_ns":31}"#,
                "\n",
                r#"{"run_id":"00000000-0000-0000-0000-000000000001","iteration":0,"proto":"http1","mode":"x25519mlkem768","payload_bytes":2048,"concurrency":4,"iters":2,"warmup":1,"tcp_ns":12,"handshake_ns":22,"ttlb_ns":32}"#,
                "\n",
                r#"{"run_id":"00000000-0000-0000-0000-000000000001","iteration":1,"proto":"http1","mode":"x25519mlkem768","payload_bytes":2048,"concurrency":4,"iters":2,"warmup":1,"tcp_ns":13,"handshake_ns":23,"ttlb_ns":33}"#,
                "\n"
            ),
            &valid_meta_with_benchmarks(
                "ok",
                None,
                Some("lite"),
                &[
                    BenchmarkSpec {
                        proto: "raw",
                        mode: "x25519",
                        payload: 1024,
                        iters: 2,
                        warmup: 1,
                        concurrency: 1,
                    },
                    BenchmarkSpec {
                        proto: "http1",
                        mode: "x25519mlkem768",
                        payload: 2048,
                        iters: 2,
                        warmup: 1,
                        concurrency: 4,
                    },
                ],
            ),
        );

        let report = assert_ok!(validate_runs(vec![discovered], false));

        assert_eq!(report.valid_runs.len(), 1);
        assert!(report.skipped_runs.is_empty());
    }

    #[test]
    fn skips_metadata_status_error_in_non_strict_mode() {
        let dir = TempDir::new().expect("temp dir");
        let discovered = write_discovered_run(
            &dir,
            "lite-error",
            &valid_jsonl(
                "00000000-0000-0000-0000-000000000001",
                r#""mode":"x25519","payload_bytes":1024,"concurrency":1,"iters":2,"warmup":1"#,
            ),
            &valid_meta("error", Some("runner failed"), Some("lite")),
        );

        let report = assert_ok!(validate_runs(vec![discovered], false));

        assert!(report.valid_runs.is_empty());
        assert_eq!(report.skipped_runs.len(), 1);
        assert!(matches!(
            report.skipped_runs[0].reason,
            SkipReason::MetadataStatusError { .. }
        ));
    }

    #[test]
    fn skips_empty_result_file_in_non_strict_mode() {
        let dir = TempDir::new().expect("temp dir");
        let discovered = write_discovered_run(
            &dir,
            "lite-empty",
            "\n",
            &valid_meta("ok", None, Some("lite")),
        );

        let report = assert_ok!(validate_runs(vec![discovered], false));

        assert!(report.valid_runs.is_empty());
        assert!(matches!(
            report.skipped_runs[0].reason,
            SkipReason::EmptyResultFile
        ));
    }

    #[test]
    fn skips_mismatched_run_ids_in_non_strict_mode() {
        let dir = TempDir::new().expect("temp dir");
        let discovered = write_discovered_run(
            &dir,
            "lite-run-id-mismatch",
            concat!(
                r#"{"run_id":"00000000-0000-0000-0000-000000000001","iteration":0,"proto":"raw","mode":"x25519","payload_bytes":1024,"concurrency":1,"iters":2,"warmup":1,"tcp_ns":10,"handshake_ns":20,"ttlb_ns":30}"#,
                "\n",
                r#"{"run_id":"00000000-0000-0000-0000-000000000002","iteration":1,"proto":"raw","mode":"x25519","payload_bytes":1024,"concurrency":1,"iters":2,"warmup":1,"tcp_ns":11,"handshake_ns":21,"ttlb_ns":31}"#,
                "\n"
            ),
            &valid_meta("ok", None, Some("lite")),
        );

        let report = assert_ok!(validate_runs(vec![discovered], false));

        assert!(report.valid_runs.is_empty());
        assert!(matches!(
            report.skipped_runs[0].reason,
            SkipReason::RunIdMismatch
        ));
    }

    #[test]
    fn skips_inconsistent_scenario_rows_in_non_strict_mode() {
        let dir = TempDir::new().expect("temp dir");
        let discovered = write_discovered_run(
            &dir,
            "lite-scenario-mismatch",
            concat!(
                r#"{"run_id":"00000000-0000-0000-0000-000000000001","iteration":0,"proto":"raw","mode":"x25519","payload_bytes":1024,"concurrency":1,"iters":2,"warmup":1,"tcp_ns":10,"handshake_ns":20,"ttlb_ns":30}"#,
                "\n",
                r#"{"run_id":"00000000-0000-0000-0000-000000000001","iteration":1,"proto":"raw","mode":"x25519mlkem768","payload_bytes":1024,"concurrency":1,"iters":2,"warmup":1,"tcp_ns":11,"handshake_ns":21,"ttlb_ns":31}"#,
                "\n"
            ),
            &valid_meta("ok", None, Some("lite")),
        );

        let report = assert_ok!(validate_runs(vec![discovered], false));

        assert!(report.valid_runs.is_empty());
        assert!(matches!(
            report.skipped_runs[0].reason,
            SkipReason::ScenarioMismatch
        ));
    }

    #[test]
    fn aborts_on_first_validation_error_in_strict_mode() {
        let dir = TempDir::new().expect("temp dir");
        let discovered = write_discovered_run(
            &dir,
            "lite-bad-meta",
            &valid_jsonl(
                "00000000-0000-0000-0000-000000000001",
                r#""mode":"x25519","payload_bytes":1024,"concurrency":1,"iters":2,"warmup":1"#,
            ),
            "{",
        );

        let error = assert_err!(validate_runs(vec![discovered], true));

        assert!(error.to_string().contains("failed to parse metadata file"));
    }

    fn write_discovered_run(
        dir: &TempDir,
        stem: &str,
        result_contents: &str,
        meta_contents: &str,
    ) -> DiscoveredRun {
        let result_path = dir.path().join(format!("{stem}.jsonl"));
        let meta_path = dir.path().join(format!("{stem}.meta"));
        fs::write(&result_path, result_contents).expect("result file");
        fs::write(&meta_path, meta_contents).expect("meta file");

        DiscoveredRun {
            stem: stem.to_string(),
            result_path,
            meta_path,
        }
    }

    fn valid_jsonl(run_id: &str, scenario_fields: &str) -> String {
        format!(
            concat!(
                r#"{{"run_id":"{run_id}","iteration":0,"proto":"raw",{scenario_fields},"tcp_ns":10,"handshake_ns":20,"ttlb_ns":30}}"#,
                "\n",
                r#"{{"run_id":"{run_id}","iteration":1,"proto":"raw",{scenario_fields},"tcp_ns":11,"handshake_ns":21,"ttlb_ns":31}}"#,
                "\n"
            ),
            run_id = run_id,
            scenario_fields = scenario_fields
        )
    }

    fn valid_meta(status: &str, error: Option<&str>, profile: Option<&str>) -> String {
        valid_meta_with_benchmarks(
            status,
            error,
            profile,
            &[BenchmarkSpec {
                proto: "raw",
                mode: "x25519",
                payload: 1024,
                iters: 2,
                warmup: 1,
                concurrency: 1,
            }],
        )
    }

    fn valid_meta_with_benchmarks(
        status: &str,
        error: Option<&str>,
        profile: Option<&str>,
        benchmarks: &[BenchmarkSpec],
    ) -> String {
        let error_field = error.map_or_else(|| "null".to_string(), |value| format!(r#""{value}""#));
        let profile_field =
            profile.map_or_else(|| "null".to_string(), |value| format!(r#""{value}""#));
        let benchmarks_json = benchmarks
            .iter()
            .map(BenchmarkSpec::to_json)
            .collect::<Vec<_>>()
            .join(",");

        format!(
            concat!(
                r#"{{"run_id":"00000000-0000-0000-0000-000000000001","#,
                r#""status":"{status}","#,
                r#""error":{error_field},"#,
                r#""started_at_unix_ms":1,"finished_at_unix_ms":2,"#,
                r#""rust_version":"rustc 1.0.0","os":"linux","arch":"x86_64","#,
                r#""command":"runner --config bench.toml","#,
                r#""config_file":"bench.toml","result_path":"results.jsonl","log_path":"run.log","#,
                r#""schedule_profile":{profile_field},"#,
                r#""runner_git_commit":"abc","runner_host":"runner-1","runner_instance_type":null,"#,
                r#""runner_region":null,"runner_availability_zone":null,"#,
                r#""server_git_commit":"def","server_host":"server-1","server_instance_type":null,"#,
                r#""server_region":null,"server_availability_zone":null,"#,
                r#""benchmarks":[{benchmarks_json}]}}"#
            ),
            status = status,
            error_field = error_field,
            profile_field = profile_field,
            benchmarks_json = benchmarks_json
        )
    }

    struct BenchmarkSpec {
        proto: &'static str,
        mode: &'static str,
        payload: u32,
        iters: u32,
        warmup: u32,
        concurrency: u32,
    }

    impl BenchmarkSpec {
        fn to_json(&self) -> String {
            format!(
                concat!(
                    r#"{{"server":"127.0.0.1:4433","server_name":"localhost","#,
                    r#""proto":"{proto}","mode":"{mode}","verification":{{"kind":"insecure"}},"#,
                    r#""payload":{payload},"iters":{iters},"warmup":{warmup},"concurrency":{concurrency},"timeout_secs":30}}"#
                ),
                proto = self.proto,
                mode = self.mode,
                payload = self.payload,
                iters = self.iters,
                warmup = self.warmup,
                concurrency = self.concurrency,
            )
        }
    }
}
