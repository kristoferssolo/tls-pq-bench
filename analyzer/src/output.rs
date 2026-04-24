use crate::{
    error::{Error, Result},
    model::{
        AggregateReport, ComparisonReport, ComparisonWarning, DiscoveryReport, MetricComparison,
        MetricSummary, PairwiseComparison, ScenarioAggregate, ScenarioProvenance, SkipReason,
        SkippedRun, ValidationReport,
    },
};
use serde::Serialize;
use std::{
    collections::BTreeSet,
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

const MANIFEST_FILE: &str = "manifest.json";
const WEEKLY_AGGREGATES_FILE: &str = "weekly_aggregates.json";
const PQ_DELTAS_FILE: &str = "pq_deltas.json";
const DIAGNOSTICS_FILE: &str = "diagnostics.json";

pub fn ensure_out_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|source| Error::CreateOutDir {
        path: path.to_path_buf(),
        source,
    })
}

pub fn write_artifacts(
    out_dir: &Path,
    results_dir: &Path,
    discovery: &DiscoveryReport,
    validation: &ValidationReport,
    aggregates: &AggregateReport,
    comparisons: &ComparisonReport,
    pretty: bool,
) -> Result<()> {
    let weekly = map_weekly_aggregates(aggregates);
    let deltas = map_pq_deltas(comparisons);
    let diagnostics = map_diagnostics(discovery, validation, comparisons);
    let manifest = map_manifest(results_dir, validation, &weekly, &deltas, &diagnostics);

    write_json(
        &out_dir.join(WEEKLY_AGGREGATES_FILE),
        WEEKLY_AGGREGATES_FILE,
        &weekly,
        pretty,
    )?;
    write_json(
        &out_dir.join(PQ_DELTAS_FILE),
        PQ_DELTAS_FILE,
        &deltas,
        pretty,
    )?;
    write_json(
        &out_dir.join(DIAGNOSTICS_FILE),
        DIAGNOSTICS_FILE,
        &diagnostics,
        pretty,
    )?;
    write_json(
        &out_dir.join(MANIFEST_FILE),
        MANIFEST_FILE,
        &manifest,
        pretty,
    )?;

    Ok(())
}

fn write_json<T: Serialize>(
    path: &Path,
    name: &'static str,
    value: &T,
    pretty: bool,
) -> Result<()> {
    let bytes = if pretty {
        serde_json::to_vec_pretty(value)
    } else {
        serde_json::to_vec(value)
    }
    .map_err(|source| Error::SerializeArtifact { name, source })?;

    fs::write(path, bytes).map_err(|source| Error::WriteArtifact {
        path: path.to_path_buf(),
        source,
    })
}

fn map_manifest(
    results_dir: &Path,
    validation: &ValidationReport,
    weekly: &WeeklyAggregatesFile,
    deltas: &PqDeltasFile,
    diagnostics: &DiagnosticsFile,
) -> ManifestFile {
    ManifestFile {
        results_dir: results_dir.display().to_string(),
        generated_at_unix_ms: unix_time_ms(),
        profiles_found: weekly.profiles.clone(),
        valid_run_count: validation.valid_runs.len(),
        skipped_run_count: diagnostics.skipped_runs.len(),
        scenario_count: weekly.scenarios.len(),
        comparison_count: deltas.comparisons.len(),
        weekly_aggregates: WEEKLY_AGGREGATES_FILE.to_string(),
        pq_deltas: PQ_DELTAS_FILE.to_string(),
        diagnostics: DIAGNOSTICS_FILE.to_string(),
    }
}

fn map_weekly_aggregates(aggregates: &AggregateReport) -> WeeklyAggregatesFile {
    let profiles = aggregates
        .scenarios
        .iter()
        .map(|scenario| scenario.key.schedule_profile.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    WeeklyAggregatesFile {
        profiles,
        scenarios: aggregates
            .scenarios
            .iter()
            .map(map_scenario_aggregate)
            .collect(),
    }
}

fn map_pq_deltas(comparisons: &ComparisonReport) -> PqDeltasFile {
    let profiles = comparisons
        .comparisons
        .iter()
        .map(|comparison| comparison.context.schedule_profile.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    PqDeltasFile {
        profiles,
        comparisons: comparisons
            .comparisons
            .iter()
            .map(map_pairwise_comparison)
            .collect(),
    }
}

fn map_diagnostics(
    discovery: &DiscoveryReport,
    validation: &ValidationReport,
    comparisons: &ComparisonReport,
) -> DiagnosticsFile {
    DiagnosticsFile {
        skipped_runs: validation
            .skipped_runs
            .iter()
            .map(map_skipped_run)
            .collect(),
        unmatched_results: discovery
            .diagnostics
            .unmatched_results
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        unmatched_meta: discovery
            .diagnostics
            .unmatched_meta
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        parse_errors: discovery
            .diagnostics
            .invalid_pairings
            .iter()
            .map(|invalid| ParseErrorDto {
                kind: "invalid_pairing".to_string(),
                path: invalid.stem.clone(),
                message: format!(
                    "ambiguous pairing with {} result file(s) and {} metadata file(s)",
                    invalid.result_paths.len(),
                    invalid.meta_paths.len()
                ),
            })
            .chain(
                validation
                    .skipped_runs
                    .iter()
                    .filter_map(map_parse_error_from_skipped_run),
            )
            .collect(),
        comparison_warnings: comparisons
            .warnings
            .iter()
            .map(map_comparison_warning)
            .collect(),
    }
}

fn map_scenario_aggregate(scenario: &ScenarioAggregate) -> ScenarioAggregateDto {
    ScenarioAggregateDto {
        schedule_profile: scenario.key.schedule_profile.clone(),
        proto: scenario.key.proto.to_string(),
        mode: scenario.key.mode.to_string(),
        payload_bytes: scenario.key.payload_bytes,
        concurrency: scenario.key.concurrency,
        tcp: map_metric_summary(&scenario.tcp),
        handshake: map_metric_summary(&scenario.handshake),
        ttlb: map_metric_summary(&scenario.ttlb),
        provenance: map_scenario_provenance(&scenario.provenance),
        warnings: scenario.warnings.clone(),
    }
}

fn map_scenario_provenance(provenance: &ScenarioProvenance) -> ScenarioProvenanceDto {
    ScenarioProvenanceDto {
        run_ids: provenance.run_ids.iter().map(ToString::to_string).collect(),
        result_paths: provenance
            .result_paths
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        started_at_unix_ms: provenance.started_at_unix_ms.clone(),
        finished_at_unix_ms: provenance.finished_at_unix_ms.clone(),
        runner_hosts: provenance.runner_hosts.clone(),
        runner_git_commits: provenance.runner_git_commits.clone(),
        server_hosts: provenance.server_hosts.clone(),
        server_git_commits: provenance.server_git_commits.clone(),
        iters: provenance.iters.clone(),
        warmup: provenance.warmup.clone(),
    }
}

fn map_pairwise_comparison(comparison: &PairwiseComparison) -> PairwiseComparisonDto {
    PairwiseComparisonDto {
        family: comparison_family_name(comparison.family).to_string(),
        schedule_profile: comparison.context.schedule_profile.clone(),
        proto: comparison.context.proto.to_string(),
        payload_bytes: comparison.context.payload_bytes,
        concurrency: comparison.context.concurrency,
        classical_mode: comparison.classical_mode.to_string(),
        pq_mode: comparison.pq_mode.to_string(),
        tcp: map_metric_comparison(&comparison.tcp),
        handshake: map_metric_comparison(&comparison.handshake),
        ttlb: map_metric_comparison(&comparison.ttlb),
    }
}

const fn map_metric_summary(summary: &MetricSummary) -> MetricSummaryDto {
    MetricSummaryDto {
        sample_count: summary.sample_count,
        run_count: summary.run_count,
        mean: summary.mean,
        min: summary.min,
        max: summary.max,
        p50: summary.p50,
        p90: summary.p90,
        p99: summary.p99,
    }
}

const fn map_metric_comparison(comparison: &MetricComparison) -> MetricComparisonDto {
    MetricComparisonDto {
        classical: map_metric_summary(&comparison.classical),
        pq: map_metric_summary(&comparison.pq),
        mean: FloatDeltaDto {
            absolute: comparison.mean.absolute,
            relative: comparison.mean.relative,
        },
        p50: IntegerDeltaDto {
            absolute: comparison.p50.absolute,
            relative: comparison.p50.relative,
        },
        p90: IntegerDeltaDto {
            absolute: comparison.p90.absolute,
            relative: comparison.p90.relative,
        },
        p99: IntegerDeltaDto {
            absolute: comparison.p99.absolute,
            relative: comparison.p99.relative,
        },
    }
}

fn map_skipped_run(skipped: &SkippedRun) -> SkippedRunDto {
    SkippedRunDto {
        stem: skipped.discovered.stem.clone(),
        result_path: skipped.discovered.result_path.display().to_string(),
        meta_path: skipped.discovered.meta_path.display().to_string(),
        reason: skipped_reason_name(&skipped.reason).to_string(),
        detail: skipped_reason_detail(&skipped.reason),
    }
}

fn map_parse_error_from_skipped_run(skipped: &SkippedRun) -> Option<ParseErrorDto> {
    match &skipped.reason {
        SkipReason::MetadataParseError { message } => Some(ParseErrorDto {
            kind: "metadata_parse".to_string(),
            path: skipped.discovered.meta_path.display().to_string(),
            message: message.clone(),
        }),
        SkipReason::ResultParseError { message } => Some(ParseErrorDto {
            kind: "result_parse".to_string(),
            path: skipped.discovered.result_path.display().to_string(),
            message: message.clone(),
        }),
        _ => None,
    }
}

fn map_comparison_warning(warning: &ComparisonWarning) -> ComparisonWarningDto {
    ComparisonWarningDto {
        family: comparison_family_name(warning.family).to_string(),
        schedule_profile: warning.context.schedule_profile.clone(),
        proto: warning.context.proto.to_string(),
        payload_bytes: warning.context.payload_bytes,
        concurrency: warning.context.concurrency,
        metric: warning.metric.to_string(),
        field: warning.field.to_string(),
        message: warning.message.clone(),
    }
}

const fn comparison_family_name(family: crate::model::ComparisonFamily) -> &'static str {
    match family {
        crate::model::ComparisonFamily::X25519 => "x25519_family",
        crate::model::ComparisonFamily::Secp256r1 => "secp256r1_family",
    }
}

const fn skipped_reason_name(reason: &SkipReason) -> &'static str {
    match reason {
        SkipReason::MetadataParseError { .. } => "metadata_parse_error",
        SkipReason::ResultParseError { .. } => "result_parse_error",
        SkipReason::MetadataStatusError { .. } => "metadata_status_error",
        SkipReason::EmptyResultFile => "empty_result_file",
        SkipReason::RunIdMismatch => "run_id_mismatch",
        SkipReason::MetadataRunIdMismatch { .. } => "metadata_run_id_mismatch",
        SkipReason::ScenarioMismatch { .. } => "scenario_mismatch",
    }
}

fn skipped_reason_detail(reason: &SkipReason) -> Option<String> {
    match reason {
        SkipReason::MetadataParseError { message } | SkipReason::ResultParseError { message } => {
            Some(message.clone())
        }
        SkipReason::MetadataStatusError { status, error } => Some(error.as_ref().map_or_else(
            || format!("status={status}"),
            |error| format!("status={status}: {error}"),
        )),
        SkipReason::MetadataRunIdMismatch {
            metadata_run_id,
            record_run_id,
        } => Some(format!(
            "metadata run_id {metadata_run_id} does not match record run_id {record_run_id}"
        )),
        SkipReason::ScenarioMismatch { detail } => Some(detail.clone()),
        SkipReason::EmptyResultFile | SkipReason::RunIdMismatch => None,
    }
}

fn unix_time_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_millis()
}

#[derive(Debug, Serialize)]
struct ManifestFile {
    results_dir: String,
    generated_at_unix_ms: u128,
    profiles_found: Vec<String>,
    valid_run_count: usize,
    skipped_run_count: usize,
    scenario_count: usize,
    comparison_count: usize,
    weekly_aggregates: String,
    pq_deltas: String,
    diagnostics: String,
}

#[derive(Debug, Serialize)]
struct WeeklyAggregatesFile {
    profiles: Vec<String>,
    scenarios: Vec<ScenarioAggregateDto>,
}

#[derive(Debug, Serialize)]
struct PqDeltasFile {
    profiles: Vec<String>,
    comparisons: Vec<PairwiseComparisonDto>,
}

#[derive(Debug, Serialize)]
struct DiagnosticsFile {
    skipped_runs: Vec<SkippedRunDto>,
    unmatched_results: Vec<String>,
    unmatched_meta: Vec<String>,
    parse_errors: Vec<ParseErrorDto>,
    comparison_warnings: Vec<ComparisonWarningDto>,
}

#[derive(Debug, Serialize)]
struct ScenarioAggregateDto {
    schedule_profile: String,
    proto: String,
    mode: String,
    payload_bytes: u32,
    concurrency: u32,
    tcp: MetricSummaryDto,
    handshake: MetricSummaryDto,
    ttlb: MetricSummaryDto,
    provenance: ScenarioProvenanceDto,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ScenarioProvenanceDto {
    run_ids: Vec<String>,
    result_paths: Vec<String>,
    started_at_unix_ms: Vec<u128>,
    finished_at_unix_ms: Vec<u128>,
    runner_hosts: Vec<String>,
    runner_git_commits: Vec<String>,
    server_hosts: Vec<String>,
    server_git_commits: Vec<String>,
    iters: Vec<u32>,
    warmup: Vec<u32>,
}

#[derive(Debug, Serialize)]
struct MetricSummaryDto {
    sample_count: usize,
    run_count: usize,
    mean: f64,
    min: u128,
    max: u128,
    p50: u128,
    p90: u128,
    p99: u128,
}

#[derive(Debug, Serialize)]
struct PairwiseComparisonDto {
    family: String,
    schedule_profile: String,
    proto: String,
    payload_bytes: u32,
    concurrency: u32,
    classical_mode: String,
    pq_mode: String,
    tcp: MetricComparisonDto,
    handshake: MetricComparisonDto,
    ttlb: MetricComparisonDto,
}

#[derive(Debug, Serialize)]
struct MetricComparisonDto {
    classical: MetricSummaryDto,
    pq: MetricSummaryDto,
    mean: FloatDeltaDto,
    p50: IntegerDeltaDto,
    p90: IntegerDeltaDto,
    p99: IntegerDeltaDto,
}

#[derive(Debug, Serialize)]
struct FloatDeltaDto {
    absolute: f64,
    relative: Option<f64>,
}

#[derive(Debug, Serialize)]
struct IntegerDeltaDto {
    absolute: i128,
    relative: Option<f64>,
}

#[derive(Debug, Serialize)]
struct SkippedRunDto {
    stem: String,
    result_path: String,
    meta_path: String,
    reason: String,
    detail: Option<String>,
}

#[derive(Debug, Serialize)]
struct ParseErrorDto {
    kind: String,
    path: String,
    message: String,
}

#[derive(Debug, Serialize)]
struct ComparisonWarningDto {
    family: String,
    schedule_profile: String,
    proto: String,
    payload_bytes: u32,
    concurrency: u32,
    metric: String,
    field: String,
    message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        ComparisonContext, ComparisonFamily, Delta, DiscoveredRun, DiscoveryDiagnostics,
        InvalidPairing, MetricSummary, PairwiseComparison, RunMetadata, ScenarioKey,
        ScenarioProvenance, ValidRun,
    };
    use common::{BenchRecord, KeyExchangeMode, ProtocolMode};
    use std::path::PathBuf;
    use tempfile::TempDir;
    use uuid::Uuid;

    #[test]
    fn writes_all_artifacts() {
        let dir = TempDir::new().expect("temp dir");
        let out_dir = dir.path().join("analysis");
        ensure_out_dir(&out_dir).expect("out dir");

        let discovery = discovery_report();
        let validation = validation_report();
        let aggregates = aggregate_report();
        let comparisons = comparison_report();

        write_artifacts(
            &out_dir,
            dir.path(),
            &discovery,
            &validation,
            &aggregates,
            &comparisons,
            true,
        )
        .expect("artifacts should be written");

        let manifest = fs::read_to_string(out_dir.join(MANIFEST_FILE)).expect("manifest");
        let weekly = fs::read_to_string(out_dir.join(WEEKLY_AGGREGATES_FILE)).expect("weekly");
        let deltas = fs::read_to_string(out_dir.join(PQ_DELTAS_FILE)).expect("deltas");
        let diagnostics = fs::read_to_string(out_dir.join(DIAGNOSTICS_FILE)).expect("diagnostics");

        assert!(manifest.contains(r#""profiles_found": ["#));
        assert!(weekly.contains(r#""run_ids": ["#));
        assert!(weekly.contains(r#""warnings": ["#));
        assert!(deltas.contains(r#""family": "x25519_family""#));
        assert!(diagnostics.contains(r#""kind": "invalid_pairing""#));
        assert!(diagnostics.contains(r#""message": "relative delta omitted""#));
    }

    fn discovery_report() -> DiscoveryReport {
        DiscoveryReport {
            runs: vec![],
            diagnostics: DiscoveryDiagnostics {
                unmatched_results: vec![PathBuf::from("/tmp/orphan.jsonl")],
                unmatched_meta: vec![PathBuf::from("/tmp/orphan.meta")],
                invalid_pairings: vec![InvalidPairing {
                    stem: "dup-run".to_string(),
                    result_paths: vec![PathBuf::from("/tmp/dup-run.jsonl")],
                    meta_paths: vec![
                        PathBuf::from("/tmp/dup-run.meta"),
                        PathBuf::from("/tmp/nested/dup-run.meta"),
                    ],
                }],
            },
        }
    }

    fn validation_report() -> ValidationReport {
        ValidationReport {
            valid_runs: vec![valid_run()],
            skipped_runs: vec![SkippedRun {
                discovered: DiscoveredRun {
                    stem: "bad-run".to_string(),
                    result_path: "/tmp/bad-run.jsonl".into(),
                    meta_path: "/tmp/bad-run.meta".into(),
                },
                reason: SkipReason::ResultParseError {
                    message: "bad json".to_string(),
                },
            }],
        }
    }

    fn aggregate_report() -> AggregateReport {
        AggregateReport {
            scenarios: vec![ScenarioAggregate {
                key: ScenarioKey {
                    schedule_profile: "lite".to_string(),
                    proto: ProtocolMode::Raw,
                    mode: KeyExchangeMode::X25519,
                    payload_bytes: 1024,
                    concurrency: 1,
                },
                tcp: metric_summary(),
                handshake: metric_summary(),
                ttlb: metric_summary(),
                provenance: ScenarioProvenance::from_runs(vec![crate::model::RunProvenance {
                    run_id: Uuid::nil(),
                    result_path: "/tmp/result.jsonl".into(),
                    started_at_unix_ms: 1,
                    finished_at_unix_ms: 2,
                    runner_git_commit: Some("runner".to_string()),
                    runner_host: Some("runner-host".to_string()),
                    server_git_commit: Some("server".to_string()),
                    server_host: Some("server-host".to_string()),
                    iters: 100,
                    warmup: 10,
                }]),
                warnings: vec![
                    "heterogeneous iters across contributing runs: 100, 200".to_string(),
                ],
            }],
        }
    }

    fn comparison_report() -> ComparisonReport {
        ComparisonReport {
            comparisons: vec![PairwiseComparison {
                family: ComparisonFamily::X25519,
                context: ComparisonContext {
                    schedule_profile: "lite".to_string(),
                    proto: ProtocolMode::Raw,
                    payload_bytes: 1024,
                    concurrency: 1,
                },
                classical_mode: KeyExchangeMode::X25519,
                pq_mode: KeyExchangeMode::X25519Mlkem768,
                tcp: metric_comparison(),
                handshake: metric_comparison(),
                ttlb: metric_comparison(),
            }],
            warnings: vec![ComparisonWarning {
                family: ComparisonFamily::X25519,
                context: ComparisonContext {
                    schedule_profile: "lite".to_string(),
                    proto: ProtocolMode::Raw,
                    payload_bytes: 1024,
                    concurrency: 1,
                },
                metric: "tcp",
                field: "mean",
                message: "relative delta omitted".to_string(),
            }],
        }
    }

    fn valid_run() -> ValidRun {
        let run_id = Uuid::nil();
        ValidRun {
            discovered: DiscoveredRun {
                stem: "lite-ok".to_string(),
                result_path: "/tmp/result.jsonl".into(),
                meta_path: "/tmp/result.meta".into(),
            },
            metadata: RunMetadata {
                run_id,
                status: "ok".to_string(),
                error: None,
                started_at_unix_ms: 1,
                finished_at_unix_ms: 2,
                rust_version: "rustc".to_string(),
                os: "linux".to_string(),
                arch: "x86_64".to_string(),
                command: "runner".to_string(),
                config_file: None,
                result_path: None,
                log_path: None,
                schedule_profile: Some("lite".to_string()),
                runner_git_commit: None,
                runner_host: None,
                runner_instance_type: None,
                runner_region: None,
                runner_availability_zone: None,
                server_git_commit: None,
                server_host: None,
                server_instance_type: None,
                server_region: None,
                server_availability_zone: None,
                benchmarks: vec![],
            },
            records: vec![BenchRecord {
                run_id,
                iteration: 0,
                proto: ProtocolMode::Raw,
                mode: KeyExchangeMode::X25519,
                payload_bytes: 1024,
                concurrency: 1,
                iters: 100,
                warmup: 10,
                tcp_ns: 10,
                handshake_ns: 20,
                ttlb_ns: 30,
            }],
        }
    }

    fn metric_summary() -> MetricSummary {
        MetricSummary {
            sample_count: 10,
            run_count: 2,
            mean: 12.5,
            min: 10,
            max: 15,
            p50: 11,
            p90: 14,
            p99: 15,
        }
    }

    fn metric_comparison() -> MetricComparison {
        MetricComparison {
            classical: metric_summary(),
            pq: metric_summary(),
            mean: Delta {
                absolute: 1.0,
                relative: Some(0.1),
            },
            p50: Delta {
                absolute: 1,
                relative: Some(0.1),
            },
            p90: Delta {
                absolute: 1,
                relative: Some(0.1),
            },
            p99: Delta {
                absolute: 1,
                relative: Some(0.1),
            },
        }
    }
}
