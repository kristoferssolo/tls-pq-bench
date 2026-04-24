use crate::{
    error::{Error, Result},
    load::{load_bench_records, load_run_metadata},
    model::{
        BenchmarkMetadata, DiscoveredRun, RunMetadata, SkipReason, SkippedRun, ValidRun,
        ValidationReport,
        ordering::{mode_order, proto_order},
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

    let record_run_id = records[0].run_id;
    if metadata.run_id != record_run_id {
        return non_strict_skip_or_error(
            strict,
            SkipReason::MetadataRunIdMismatch {
                metadata_run_id: metadata.run_id,
                record_run_id,
            },
            format!(
                "metadata {} run_id {} does not match result file {} run_id {}",
                discovered.meta_path.display(),
                metadata.run_id,
                discovered.result_path.display(),
                record_run_id
            ),
        );
    }

    if let Some(detail) = scenario_mismatch_detail(metadata, records) {
        return non_strict_skip_or_error(
            strict,
            SkipReason::ScenarioMismatch {
                detail: detail.clone(),
            },
            format!(
                "result file {} contains records that do not match metadata benchmarks: {detail}",
                discovered.result_path.display()
            ),
        );
    }

    Ok(None)
}

fn scenario_mismatch_detail(metadata: &RunMetadata, records: &[BenchRecord]) -> Option<String> {
    let benchmarks = metadata
        .benchmarks
        .iter()
        .map(BenchmarkRecordKey::from)
        .collect::<BTreeSet<_>>();
    if benchmarks.is_empty() {
        return Some("metadata contains no benchmarks".to_string());
    }

    let scenario_keys = records
        .iter()
        .map(ScenarioIdentity::from)
        .collect::<BTreeSet<_>>();

    for scenario in scenario_keys {
        let scenario_records = records
            .iter()
            .filter(|record| ScenarioIdentity::from(*record) == scenario)
            .collect::<Vec<_>>();

        let mut provenance_pairs = BTreeSet::new();
        for record in &scenario_records {
            provenance_pairs.insert((record.iters, record.warmup));
            let key = BenchmarkRecordKey::from(*record);
            if !benchmarks.contains(&key) {
                return Some(format!(
                    "scenario proto={} mode={} payload_bytes={} concurrency={} record iters/warmup {}/{} missing from metadata",
                    record.proto,
                    record.mode,
                    record.payload_bytes,
                    record.concurrency,
                    record.iters,
                    record.warmup
                ));
            }
        }

        if provenance_pairs.is_empty() {
            return Some(format!(
                "scenario proto={} mode={} payload_bytes={} concurrency={} has no records",
                scenario.proto, scenario.mode, scenario.payload_bytes, scenario.concurrency
            ));
        }
    }

    None
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScenarioIdentity {
    proto: ProtocolMode,
    mode: KeyExchangeMode,
    payload_bytes: u32,
    concurrency: u32,
}

impl From<&BenchRecord> for ScenarioIdentity {
    fn from(record: &BenchRecord) -> Self {
        Self {
            proto: record.proto,
            mode: record.mode,
            payload_bytes: record.payload_bytes,
            concurrency: record.concurrency,
        }
    }
}

impl Ord for ScenarioIdentity {
    fn cmp(&self, other: &Self) -> Ordering {
        (
            proto_order(self.proto),
            mode_order(self.mode),
            self.payload_bytes,
            self.concurrency,
        )
            .cmp(&(
                proto_order(other.proto),
                mode_order(other.mode),
                other.payload_bytes,
                other.concurrency,
            ))
    }
}

impl PartialOrd for ScenarioIdentity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BenchmarkRecordKey {
    proto: ProtocolMode,
    mode: KeyExchangeMode,
    payload_bytes: u32,
    concurrency: u32,
    iters: u32,
    warmup: u32,
}

impl From<&BenchRecord> for BenchmarkRecordKey {
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

impl From<&BenchmarkMetadata> for BenchmarkRecordKey {
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

impl Ord for BenchmarkRecordKey {
    fn cmp(&self, other: &Self) -> Ordering {
        (
            proto_order(self.proto),
            mode_order(self.mode),
            self.payload_bytes,
            self.concurrency,
            self.iters,
            self.warmup,
        )
            .cmp(&(
                proto_order(other.proto),
                mode_order(other.mode),
                other.payload_bytes,
                other.concurrency,
                other.iters,
                other.warmup,
            ))
    }
}

impl PartialOrd for BenchmarkRecordKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
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
            &valid_meta(
                "00000000-0000-0000-0000-000000000001",
                "ok",
                None,
                Some("lite"),
            ),
        );

        let report = assert_ok!(validate_runs(vec![discovered], false));

        assert_eq!(report.valid_runs.len(), 1);
        assert!(report.skipped_runs.is_empty());
    }

    #[test]
    fn allows_multiple_record_batches_for_one_weekly_scenario() {
        let dir = TempDir::new().expect("temp dir");
        let discovered = write_discovered_run(
            &dir,
            "lite-iters-mixed",
            concat!(
                r#"{"run_id":"00000000-0000-0000-0000-000000000001","iteration":0,"proto":"raw","mode":"x25519","payload_bytes":1024,"concurrency":1,"iters":2,"warmup":1,"tcp_ns":10,"handshake_ns":20,"ttlb_ns":30}"#,
                "\n",
                r#"{"run_id":"00000000-0000-0000-0000-000000000001","iteration":1,"proto":"raw","mode":"x25519","payload_bytes":1024,"concurrency":1,"iters":4,"warmup":2,"tcp_ns":11,"handshake_ns":21,"ttlb_ns":31}"#,
                "\n"
            ),
            &valid_meta_with_benchmarks(
                "00000000-0000-0000-0000-000000000001",
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
                        proto: "raw",
                        mode: "x25519",
                        payload: 1024,
                        iters: 4,
                        warmup: 2,
                        concurrency: 1,
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
            &valid_meta(
                "00000000-0000-0000-0000-000000000001",
                "error",
                Some("runner failed"),
                Some("lite"),
            ),
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
            &valid_meta(
                "00000000-0000-0000-0000-000000000001",
                "ok",
                None,
                Some("lite"),
            ),
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
            &valid_meta(
                "00000000-0000-0000-0000-000000000001",
                "ok",
                None,
                Some("lite"),
            ),
        );

        let report = assert_ok!(validate_runs(vec![discovered], false));

        assert!(report.valid_runs.is_empty());
        assert!(matches!(
            report.skipped_runs[0].reason,
            SkipReason::RunIdMismatch
        ));
    }

    #[test]
    fn skips_metadata_record_run_id_mismatch_in_non_strict_mode() {
        let dir = TempDir::new().expect("temp dir");
        let discovered = write_discovered_run(
            &dir,
            "lite-meta-run-id-mismatch",
            &valid_jsonl(
                "00000000-0000-0000-0000-000000000001",
                r#""mode":"x25519","payload_bytes":1024,"concurrency":1,"iters":2,"warmup":1"#,
            ),
            &valid_meta(
                "00000000-0000-0000-0000-000000000002",
                "ok",
                None,
                Some("lite"),
            ),
        );

        let report = assert_ok!(validate_runs(vec![discovered], false));

        assert!(report.valid_runs.is_empty());
        assert!(matches!(
            report.skipped_runs[0].reason,
            SkipReason::MetadataRunIdMismatch { .. }
        ));
    }

    #[test]
    fn skips_scenarios_missing_from_metadata_in_non_strict_mode() {
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
            &valid_meta(
                "00000000-0000-0000-0000-000000000001",
                "ok",
                None,
                Some("lite"),
            ),
        );

        let report = assert_ok!(validate_runs(vec![discovered], false));

        assert!(report.valid_runs.is_empty());
        assert!(matches!(
            report.skipped_runs[0].reason,
            SkipReason::ScenarioMismatch { .. }
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

    fn valid_meta(
        run_id: &str,
        status: &str,
        error: Option<&str>,
        profile: Option<&str>,
    ) -> String {
        valid_meta_with_benchmarks(
            run_id,
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
        run_id: &str,
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
                r#"{{"run_id":"{run_id}","#,
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
            run_id = run_id,
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
                    r#""payload":{payload},"iters":{iters},"warmup":{warmup},"#,
                    r#""concurrency":{concurrency},"timeout_secs":30}}"#
                ),
                proto = self.proto,
                mode = self.mode,
                payload = self.payload,
                iters = self.iters,
                warmup = self.warmup,
                concurrency = self.concurrency
            )
        }
    }
}
