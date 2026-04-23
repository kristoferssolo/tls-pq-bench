use crate::model::{
    AggregateReport, MetricSummary, RunProvenance, ScenarioAggregate, ScenarioKey, ValidRun,
};
use common::BenchRecord;
use std::collections::BTreeMap;

pub fn aggregate_runs(valid_runs: &[ValidRun], profile_filter: Option<&str>) -> AggregateReport {
    let mut buckets: BTreeMap<ScenarioKey, Vec<&ValidRun>> = BTreeMap::new();

    for run in valid_runs {
        let Some(first) = run.records.first() else {
            continue;
        };

        let schedule_profile = run
            .metadata
            .schedule_profile
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        if profile_filter.is_some_and(|filter| filter != schedule_profile) {
            continue;
        }

        let key = ScenarioKey {
            schedule_profile,
            proto: first.proto,
            mode: first.mode,
            payload_bytes: first.payload_bytes,
            concurrency: first.concurrency,
        };
        buckets.entry(key).or_default().push(run);
    }

    let scenarios = buckets
        .into_iter()
        .map(|(key, runs)| aggregate_bucket(key, &runs))
        .collect();

    AggregateReport { scenarios }
}

fn aggregate_bucket(key: ScenarioKey, runs: &[&ValidRun]) -> ScenarioAggregate {
    let tcp_values = collect_metric(runs, |record| record.tcp_ns);
    let handshake_values = collect_metric(runs, |record| record.handshake_ns);
    let ttlb_values = collect_metric(runs, |record| record.ttlb_ns);

    ScenarioAggregate {
        key,
        tcp: summarize_metric(&tcp_values, runs.len()),
        handshake: summarize_metric(&handshake_values, runs.len()),
        ttlb: summarize_metric(&ttlb_values, runs.len()),
        provenance: runs.iter().map(|run| run_provenance(run)).collect(),
    }
}

fn collect_metric(runs: &[&ValidRun], selector: impl Fn(&BenchRecord) -> u128) -> Vec<u128> {
    let mut values = runs
        .iter()
        .flat_map(|run| run.records.iter().map(&selector))
        .collect::<Vec<_>>();
    values.sort_unstable();
    values
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

fn run_provenance(run: &ValidRun) -> RunProvenance {
    RunProvenance {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{BenchmarkMetadata, DiscoveredRun, RunMetadata};
    use common::{KeyExchangeMode, ProtocolMode, VerificationMode};
    use std::collections::BTreeSet;
    use uuid::Uuid;

    #[test]
    fn aggregates_multiple_runs_into_one_scenario_bucket() {
        let runs = vec![
            valid_run(
                "00000000-0000-0000-0000-000000000001",
                "lite",
                KeyExchangeMode::X25519,
                &[(10, 20, 30), (11, 21, 31)],
                "/tmp/lite-a.jsonl",
            ),
            valid_run(
                "00000000-0000-0000-0000-000000000002",
                "lite",
                KeyExchangeMode::X25519,
                &[(12, 22, 32), (13, 23, 33)],
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
        assert_eq!(scenario.provenance.len(), 2);
    }

    #[test]
    fn keeps_lite_and_full_in_separate_buckets() {
        let runs = vec![
            valid_run(
                "00000000-0000-0000-0000-000000000001",
                "lite",
                KeyExchangeMode::X25519,
                &[(10, 20, 30)],
                "/tmp/lite.jsonl",
            ),
            valid_run(
                "00000000-0000-0000-0000-000000000002",
                "full",
                KeyExchangeMode::X25519,
                &[(11, 21, 31)],
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
                KeyExchangeMode::X25519,
                &[(10, 20, 30)],
                "/tmp/lite.jsonl",
            ),
            valid_run(
                "00000000-0000-0000-0000-000000000002",
                "full",
                KeyExchangeMode::X25519,
                &[(11, 21, 31)],
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
            KeyExchangeMode::X25519,
            &[
                (1, 10, 100),
                (2, 20, 200),
                (3, 30, 300),
                (4, 40, 400),
                (5, 50, 500),
            ],
            "/tmp/lite.jsonl",
        )];

        let report = aggregate_runs(&runs, None);
        let scenario = &report.scenarios[0];

        assert_eq!(scenario.tcp.p50, 3);
        assert_eq!(scenario.tcp.p90, 5);
        assert_eq!(scenario.tcp.p99, 5);
    }

    fn valid_run(
        run_id: &str,
        schedule_profile: &str,
        mode: KeyExchangeMode,
        samples: &[(u128, u128, u128)],
        result_path: &str,
    ) -> ValidRun {
        let run_id = Uuid::parse_str(run_id).expect("valid uuid");
        let sample_count = u32::try_from(samples.len()).expect("sample count should fit in u32");
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
                benchmarks: vec![BenchmarkMetadata {
                    server: "127.0.0.1:4433".to_string(),
                    server_name: "localhost".to_string(),
                    proto: ProtocolMode::Raw,
                    mode,
                    verification: VerificationMode::Insecure,
                    payload: 1024,
                    iters: sample_count,
                    warmup: 1,
                    concurrency: 1,
                    timeout_secs: 30,
                }],
            },
            records: samples
                .iter()
                .enumerate()
                .map(
                    |(iteration, &(tcp_ns, handshake_ns, ttlb_ns))| BenchRecord {
                        run_id,
                        iteration: u32::try_from(iteration).expect("iteration should fit in u32"),
                        proto: ProtocolMode::Raw,
                        mode,
                        payload_bytes: 1024,
                        concurrency: 1,
                        iters: sample_count,
                        warmup: 1,
                        tcp_ns,
                        handshake_ns,
                        ttlb_ns,
                    },
                )
                .collect(),
        }
    }
}
