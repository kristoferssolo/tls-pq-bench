use crate::{
    load::{load_bench_records, load_run_metadata},
    model::{DiscoveredRun, SkipReason, SkippedRun, ValidRun, ValidationReport},
};
use common::BenchRecord;

pub fn validate_runs(
    discovered_runs: Vec<DiscoveredRun>,
    strict: bool,
) -> miette::Result<ValidationReport> {
    let mut report = ValidationReport::default();

    for discovered in discovered_runs {
        let metadata = match load_run_metadata(&discovered.meta_path) {
            Ok(metadata) => metadata,
            Err(error) => {
                if strict {
                    return Err(error);
                }
                report.skipped_runs.push(SkippedRun {
                    discovered,
                    reason: SkipReason::MetadataParseError {
                        message: error.to_string(),
                    },
                });
                continue;
            }
        };

        let records = match load_bench_records(&discovered.result_path) {
            Ok(records) => records,
            Err(error) => {
                if strict {
                    return Err(error);
                }
                report.skipped_runs.push(SkippedRun {
                    discovered,
                    reason: SkipReason::ResultParseError {
                        message: error.to_string(),
                    },
                });
                continue;
            }
        };

        if metadata.status != "ok" {
            if strict {
                return Err(miette::miette!(
                    "run {} is not successful: status={}",
                    discovered.meta_path.display(),
                    metadata.status
                ));
            }
            report.skipped_runs.push(SkippedRun {
                discovered,
                reason: SkipReason::MetadataStatusError {
                    status: metadata.status,
                    error: metadata.error,
                },
            });
            continue;
        }

        if records.is_empty() {
            if strict {
                return Err(miette::miette!(
                    "result file {} contains no benchmark records",
                    discovered.result_path.display()
                ));
            }
            report.skipped_runs.push(SkippedRun {
                discovered,
                reason: SkipReason::EmptyResultFile,
            });
            continue;
        }

        if !all_records_share_run_id(&records) {
            if strict {
                return Err(miette::miette!(
                    "result file {} contains multiple run_id values",
                    discovered.result_path.display()
                ));
            }
            report.skipped_runs.push(SkippedRun {
                discovered,
                reason: SkipReason::RunIdMismatch,
            });
            continue;
        }

        if !records_have_consistent_scenarios(&records) {
            if strict {
                return Err(miette::miette!(
                    "result file {} contains inconsistent scenario rows",
                    discovered.result_path.display()
                ));
            }
            report.skipped_runs.push(SkippedRun {
                discovered,
                reason: SkipReason::ScenarioMismatch,
            });
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

fn all_records_share_run_id(records: &[BenchRecord]) -> bool {
    let Some(first) = records.first() else {
        return true;
    };
    records.iter().all(|record| record.run_id == first.run_id)
}

fn records_have_consistent_scenarios(records: &[BenchRecord]) -> bool {
    let Some(first) = records.first() else {
        return true;
    };

    records.iter().all(|record| {
        record.proto == first.proto
            && record.mode == first.mode
            && record.payload_bytes == first.payload_bytes
            && record.concurrency == first.concurrency
            && record.iters == first.iters
            && record.warmup == first.warmup
    })
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

        assert!(format!("{error:?}").contains("failed to parse metadata file"));
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
        let error_field = error.map_or_else(|| "null".to_string(), |value| format!(r#""{value}""#));
        let profile_field =
            profile.map_or_else(|| "null".to_string(), |value| format!(r#""{value}""#));

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
                r#""benchmarks":[{{"server":"127.0.0.1:4433","server_name":"localhost","#,
                r#""proto":"raw","mode":"x25519","verification":{{"kind":"insecure"}},"#,
                r#""payload":1024,"iters":100,"warmup":10,"concurrency":1,"timeout_secs":30}}]}}"#
            ),
            status = status,
            error_field = error_field,
            profile_field = profile_field
        )
    }
}
