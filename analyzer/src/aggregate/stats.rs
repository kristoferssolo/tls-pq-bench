use crate::model::{
    AggregateReport, BenchmarkMetadata, MetricSummary, RunProvenance, ScenarioAggregate,
    ScenarioKey, ScenarioProvenance, ValidRun,
    ordering::{mode_order, proto_order},
};
use common::BenchRecord;
use std::{cmp::Ordering, collections::BTreeMap};

pub fn aggregate_runs(valid_runs: &[ValidRun], profile_filter: Option<&str>) -> AggregateReport {
    let mut buckets: BTreeMap<ScenarioKey, Vec<ScenarioRun<'_>>> = BTreeMap::new();

    for run in valid_runs {
        let schedule_profile = run
            .metadata
            .schedule_profile
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        if profile_filter.is_some_and(|filter| filter != schedule_profile) {
            continue;
        }

        let benchmark_lookup = benchmark_lookup(&run.metadata.benchmarks);
        let mut run_buckets: BTreeMap<ScenarioKey, Vec<&BenchRecord>> = BTreeMap::new();
        for record in &run.records {
            let key = ScenarioKey::from_record(schedule_profile.clone(), record);
            run_buckets.entry(key).or_default().push(record);
        }

        for (key, records) in run_buckets {
            let provenance_record = records[0];
            let benchmark = benchmark_lookup
                .get(&RecordScenarioKey::from(provenance_record))
                .copied();
            buckets.entry(key).or_default().push(ScenarioRun {
                records,
                benchmark,
                provenance: RunProvenance::from_run(run, provenance_record),
            });
        }
    }

    let scenarios = buckets
        .into_iter()
        .map(|(key, runs)| aggregate_bucket(key, &runs))
        .collect();

    AggregateReport { scenarios }
}

struct ScenarioRun<'a> {
    records: Vec<&'a BenchRecord>,
    benchmark: Option<&'a BenchmarkMetadata>,
    provenance: RunProvenance,
}

fn aggregate_bucket(key: ScenarioKey, runs: &[ScenarioRun]) -> ScenarioAggregate {
    let tcp_values = collect_metric(runs, |record| record.tcp_ns);
    let handshake_values = collect_metric(runs, |record| record.handshake_ns);
    let ttlb_values = collect_metric(runs, |record| record.ttlb_ns);
    let provenance_runs = runs
        .iter()
        .map(|scenario_run| scenario_run.provenance.clone())
        .collect::<Vec<_>>();
    let warnings = aggregate_warnings(runs);

    ScenarioAggregate {
        key,
        tcp: summarize_metric(&tcp_values, runs.len()),
        handshake: summarize_metric(&handshake_values, runs.len()),
        ttlb: summarize_metric(&ttlb_values, runs.len()),
        provenance: ScenarioProvenance::from_runs(provenance_runs),
        warnings,
    }
}

fn collect_metric(runs: &[ScenarioRun], selector: impl Fn(&BenchRecord) -> u128) -> Vec<u128> {
    let mut values = runs
        .iter()
        .flat_map(|run| run.records.iter().copied().map(&selector))
        .collect::<Vec<_>>();
    values.sort_unstable();
    values
}

fn aggregate_warnings(runs: &[ScenarioRun<'_>]) -> Vec<String> {
    let mut warnings = Vec::new();
    let iters = runs
        .iter()
        .map(|run| run.provenance.iters)
        .collect::<std::collections::BTreeSet<_>>();
    if iters.len() > 1 {
        warnings.push(format!(
            "heterogeneous iters across contributing runs: {}",
            iters
                .into_iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    let warmup = runs
        .iter()
        .map(|run| run.provenance.warmup)
        .collect::<std::collections::BTreeSet<_>>();
    if warmup.len() > 1 {
        warnings.push(format!(
            "heterogeneous warmup across contributing runs: {}",
            warmup
                .into_iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    let benchmark_iters = runs
        .iter()
        .filter_map(|run| run.benchmark.map(|benchmark| benchmark.iters))
        .collect::<std::collections::BTreeSet<_>>();
    if benchmark_iters.len() > 1 {
        warnings.push(format!(
            "heterogeneous metadata iters across contributing runs: {}",
            benchmark_iters
                .into_iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    let benchmark_warmup = runs
        .iter()
        .filter_map(|run| run.benchmark.map(|benchmark| benchmark.warmup))
        .collect::<std::collections::BTreeSet<_>>();
    if benchmark_warmup.len() > 1 {
        warnings.push(format!(
            "heterogeneous metadata warmup across contributing runs: {}",
            benchmark_warmup
                .into_iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    warnings
}

fn summarize_metric(values: &[u128], run_count: usize) -> MetricSummary {
    let sample_count = values.len();
    let total = values.iter().sum::<u128>();
    MetricSummary {
        sample_count,
        run_count,
        mean: parse_f64(&total) / parse_f64(&sample_count),
        min: *values.first().expect("metric buckets should not be empty"),
        max: *values.last().expect("metric buckets should not be empty"),
        p50: nearest_rank(values, 50, 100),
        p90: nearest_rank(values, 90, 100),
        p99: nearest_rank(values, 99, 100),
    }
}

fn nearest_rank(sorted_values: &[u128], numerator: usize, denominator: usize) -> u128 {
    let n = sorted_values.len();
    let rank = n
        .saturating_mul(numerator)
        .div_ceil(denominator)
        .clamp(1, n);
    sorted_values[rank - 1]
}

fn parse_f64(value: &impl ToString) -> f64 {
    value
        .to_string()
        .parse::<f64>()
        .expect("numeric values should parse as f64")
}

fn benchmark_lookup(
    benchmarks: &[BenchmarkMetadata],
) -> BTreeMap<RecordScenarioKey, &BenchmarkMetadata> {
    benchmarks
        .iter()
        .map(|benchmark| (RecordScenarioKey::from(benchmark), benchmark))
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecordScenarioKey {
    proto: common::ProtocolMode,
    mode: common::KeyExchangeMode,
    payload_bytes: u32,
    concurrency: u32,
}

impl From<&BenchRecord> for RecordScenarioKey {
    fn from(record: &BenchRecord) -> Self {
        Self {
            proto: record.proto,
            mode: record.mode,
            payload_bytes: record.payload_bytes,
            concurrency: record.concurrency,
        }
    }
}

impl From<&BenchmarkMetadata> for RecordScenarioKey {
    fn from(benchmark: &BenchmarkMetadata) -> Self {
        Self {
            proto: benchmark.proto,
            mode: benchmark.mode,
            payload_bytes: benchmark.payload,
            concurrency: benchmark.concurrency,
        }
    }
}

impl Ord for RecordScenarioKey {
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

impl PartialOrd for RecordScenarioKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DiscoveredRun, RunMetadata};
    use common::{KeyExchangeMode, ProtocolMode, VerificationMode};
    use std::collections::BTreeSet;
    use uuid::Uuid;

    #[test]
    fn aggregates_multiple_runs_into_one_scenario_bucket() {
        let runs = vec![
            valid_run(
                "00000000-0000-0000-0000-000000000001",
                "lite",
                &[
                    (
                        ProtocolMode::Raw,
                        KeyExchangeMode::X25519,
                        1024,
                        1,
                        2,
                        1,
                        10,
                        20,
                        30,
                    ),
                    (
                        ProtocolMode::Raw,
                        KeyExchangeMode::X25519,
                        1024,
                        1,
                        2,
                        1,
                        11,
                        21,
                        31,
                    ),
                ],
                "/tmp/lite-a.jsonl",
            ),
            valid_run(
                "00000000-0000-0000-0000-000000000002",
                "lite",
                &[
                    (
                        ProtocolMode::Raw,
                        KeyExchangeMode::X25519,
                        1024,
                        1,
                        2,
                        1,
                        12,
                        22,
                        32,
                    ),
                    (
                        ProtocolMode::Raw,
                        KeyExchangeMode::X25519,
                        1024,
                        1,
                        2,
                        1,
                        13,
                        23,
                        33,
                    ),
                ],
                "/tmp/lite-b.jsonl",
            ),
        ];

        let report = aggregate_runs(&runs, None);

        assert_eq!(report.scenarios.len(), 1);
        let scenario = &report.scenarios[0];
        assert_eq!(scenario.key.schedule_profile, "lite");
        assert_eq!(scenario.tcp.sample_count, 4);
        assert_eq!(scenario.tcp.run_count, 2);
        assert_eq!(scenario.tcp.min, 10);
        assert_eq!(scenario.tcp.max, 13);
        assert_eq!(scenario.provenance.run_ids.len(), 2);
        assert!(scenario.warnings.is_empty());
    }

    #[test]
    fn keeps_lite_and_full_in_separate_buckets() {
        let runs = vec![
            valid_run(
                "00000000-0000-0000-0000-000000000001",
                "lite",
                &[(
                    ProtocolMode::Raw,
                    KeyExchangeMode::X25519,
                    1024,
                    1,
                    2,
                    1,
                    10,
                    20,
                    30,
                )],
                "/tmp/lite.jsonl",
            ),
            valid_run(
                "00000000-0000-0000-0000-000000000002",
                "full",
                &[(
                    ProtocolMode::Raw,
                    KeyExchangeMode::X25519,
                    1024,
                    1,
                    2,
                    1,
                    11,
                    21,
                    31,
                )],
                "/tmp/full.jsonl",
            ),
        ];

        let report = aggregate_runs(&runs, None);
        let profiles = report
            .scenarios
            .iter()
            .map(|scenario| scenario.key.schedule_profile.clone())
            .collect::<BTreeSet<_>>();

        assert_eq!(report.scenarios.len(), 2);
        assert_eq!(
            profiles,
            BTreeSet::from(["full".to_string(), "lite".to_string()])
        );
    }

    #[test]
    fn filters_to_one_profile_when_requested() {
        let runs = vec![
            valid_run(
                "00000000-0000-0000-0000-000000000001",
                "lite",
                &[(
                    ProtocolMode::Raw,
                    KeyExchangeMode::X25519,
                    1024,
                    1,
                    2,
                    1,
                    10,
                    20,
                    30,
                )],
                "/tmp/lite.jsonl",
            ),
            valid_run(
                "00000000-0000-0000-0000-000000000002",
                "full",
                &[(
                    ProtocolMode::Raw,
                    KeyExchangeMode::X25519,
                    1024,
                    1,
                    2,
                    1,
                    11,
                    21,
                    31,
                )],
                "/tmp/full.jsonl",
            ),
        ];

        let report = aggregate_runs(&runs, Some("lite"));

        assert_eq!(report.scenarios.len(), 1);
        assert_eq!(report.scenarios[0].key.schedule_profile, "lite");
    }

    #[test]
    fn computes_nearest_rank_percentiles() {
        let runs = vec![valid_run(
            "00000000-0000-0000-0000-000000000001",
            "lite",
            &[
                (
                    ProtocolMode::Raw,
                    KeyExchangeMode::X25519,
                    1024,
                    1,
                    5,
                    1,
                    1,
                    10,
                    100,
                ),
                (
                    ProtocolMode::Raw,
                    KeyExchangeMode::X25519,
                    1024,
                    1,
                    5,
                    1,
                    2,
                    20,
                    200,
                ),
                (
                    ProtocolMode::Raw,
                    KeyExchangeMode::X25519,
                    1024,
                    1,
                    5,
                    1,
                    3,
                    30,
                    300,
                ),
                (
                    ProtocolMode::Raw,
                    KeyExchangeMode::X25519,
                    1024,
                    1,
                    5,
                    1,
                    4,
                    40,
                    400,
                ),
                (
                    ProtocolMode::Raw,
                    KeyExchangeMode::X25519,
                    1024,
                    1,
                    5,
                    1,
                    5,
                    50,
                    500,
                ),
            ],
            "/tmp/lite.jsonl",
        )];

        let report = aggregate_runs(&runs, None);
        let scenario = &report.scenarios[0];

        assert_eq!(scenario.tcp.p50, 3);
        assert_eq!(scenario.tcp.p90, 5);
        assert_eq!(scenario.tcp.p99, 5);
    }

    #[test]
    fn mixed_iters_and_warmup_do_not_split_weekly_bucket() {
        let runs = vec![
            valid_run(
                "00000000-0000-0000-0000-000000000001",
                "lite",
                &[(
                    ProtocolMode::Raw,
                    KeyExchangeMode::X25519,
                    1024,
                    1,
                    2,
                    1,
                    10,
                    20,
                    30,
                )],
                "/tmp/lite-a.jsonl",
            ),
            valid_run(
                "00000000-0000-0000-0000-000000000002",
                "lite",
                &[(
                    ProtocolMode::Raw,
                    KeyExchangeMode::X25519,
                    1024,
                    1,
                    4,
                    2,
                    11,
                    21,
                    31,
                )],
                "/tmp/lite-b.jsonl",
            ),
        ];

        let report = aggregate_runs(&runs, None);

        assert_eq!(report.scenarios.len(), 1);
        let scenario = &report.scenarios[0];
        assert_eq!(scenario.provenance.iters, vec![2, 4]);
        assert_eq!(scenario.provenance.warmup, vec![1, 2]);
        assert_eq!(scenario.warnings.len(), 4);
    }

    type Samples = [(
        ProtocolMode,
        KeyExchangeMode,
        u32,
        u32,
        u32,
        u32,
        u128,
        u128,
        u128,
    )];

    fn valid_run(
        run_id: &str,
        schedule_profile: &str,
        samples: &Samples,
        result_path: &str,
    ) -> ValidRun {
        let run_id = Uuid::parse_str(run_id).expect("valid uuid");
        ValidRun {
            discovered: DiscoveredRun {
                stem: format!("{schedule_profile}-{run_id}"),
                result_path: result_path.into(),
                meta_path: "/tmp/run.meta".into(),
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
                result_path: Some(result_path.into()),
                log_path: None,
                schedule_profile: Some(schedule_profile.to_string()),
                runner_git_commit: Some("runner-commit".to_string()),
                runner_host: Some("runner-host".to_string()),
                runner_instance_type: None,
                runner_region: None,
                runner_availability_zone: None,
                server_git_commit: Some("server-commit".to_string()),
                server_host: Some("server-host".to_string()),
                server_instance_type: None,
                server_region: None,
                server_availability_zone: None,
                benchmarks: samples
                    .iter()
                    .map(|&(proto, mode, payload, concurrency, iters, warmup, ..)| {
                        BenchmarkMetadata {
                            server: "127.0.0.1:4433".to_string(),
                            server_name: "localhost".to_string(),
                            proto,
                            mode,
                            verification: VerificationMode::Insecure,
                            payload,
                            iters,
                            warmup,
                            concurrency,
                            timeout_secs: 30,
                        }
                    })
                    .collect(),
            },
            records: samples
                .iter()
                .enumerate()
                .map(
                    |(
                        iteration,
                        &(
                            proto,
                            mode,
                            payload_bytes,
                            concurrency,
                            iters,
                            warmup,
                            tcp_ns,
                            handshake_ns,
                            ttlb_ns,
                        ),
                    )| BenchRecord {
                        run_id,
                        iteration: u32::try_from(iteration).expect("iteration should fit in u32"),
                        proto,
                        mode,
                        payload_bytes,
                        concurrency,
                        iters,
                        warmup,
                        tcp_ns,
                        handshake_ns,
                        ttlb_ns,
                    },
                )
                .collect(),
        }
    }
}
