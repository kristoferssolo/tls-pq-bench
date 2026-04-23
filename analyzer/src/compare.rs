use crate::model::{
    AggregateReport, ComparisonContext, ComparisonFamily, ComparisonReport, ComparisonWarning,
    Delta, MetricComparison, MetricSummary, PairwiseComparison, ScenarioAggregate,
};
use common::KeyExchangeMode;
use std::collections::BTreeMap;

pub fn compare_aggregates(aggregates: &AggregateReport) -> ComparisonReport {
    let mut grouped =
        BTreeMap::<(ComparisonFamily, ComparisonContext), Vec<&ScenarioAggregate>>::new();

    for scenario in &aggregates.scenarios {
        let family = comparison_family(scenario.key.mode);
        let context = ComparisonContext {
            schedule_profile: scenario.key.schedule_profile.clone(),
            proto: scenario.key.proto,
            payload_bytes: scenario.key.payload_bytes,
            concurrency: scenario.key.concurrency,
        };
        grouped.entry((family, context)).or_default().push(scenario);
    }

    let mut report = ComparisonReport::default();
    for ((family, context), scenarios) in grouped {
        let (classical_mode, pq_mode) = family_modes(family);
        let classical = scenarios
            .iter()
            .find(|scenario| scenario.key.mode == classical_mode);
        let pq = scenarios
            .iter()
            .find(|scenario| scenario.key.mode == pq_mode);
        let (Some(classical), Some(pq)) = (classical, pq) else {
            continue;
        };

        let mut warnings = Vec::new();
        let comparison = PairwiseComparison {
            family,
            context: context.clone(),
            classical_mode,
            pq_mode,
            tcp: compare_metric(
                &classical.tcp,
                &pq.tcp,
                family,
                &context,
                "tcp",
                &mut warnings,
            ),
            handshake: compare_metric(
                &classical.handshake,
                &pq.handshake,
                family,
                &context,
                "handshake",
                &mut warnings,
            ),
            ttlb: compare_metric(
                &classical.ttlb,
                &pq.ttlb,
                family,
                &context,
                "ttlb",
                &mut warnings,
            ),
        };
        report.comparisons.push(comparison);
        report.warnings.extend(warnings);
    }

    report
}

const fn comparison_family(mode: KeyExchangeMode) -> ComparisonFamily {
    match mode {
        KeyExchangeMode::X25519 | KeyExchangeMode::X25519Mlkem768 => ComparisonFamily::X25519,
        KeyExchangeMode::Secp256r1 | KeyExchangeMode::Secp256r1Mlkem768 => {
            ComparisonFamily::Secp256r1
        }
    }
}

const fn family_modes(family: ComparisonFamily) -> (KeyExchangeMode, KeyExchangeMode) {
    match family {
        ComparisonFamily::X25519 => (KeyExchangeMode::X25519, KeyExchangeMode::X25519Mlkem768),
        ComparisonFamily::Secp256r1 => (
            KeyExchangeMode::Secp256r1,
            KeyExchangeMode::Secp256r1Mlkem768,
        ),
    }
}

fn compare_metric(
    classical: &MetricSummary,
    pq: &MetricSummary,
    family: ComparisonFamily,
    context: &ComparisonContext,
    metric: &'static str,
    warnings: &mut Vec<ComparisonWarning>,
) -> MetricComparison {
    MetricComparison {
        classical: classical.clone(),
        pq: pq.clone(),
        mean: float_delta(
            classical.mean,
            pq.mean,
            family,
            context,
            metric,
            "mean",
            warnings,
        ),
        p50: integer_delta(
            classical.p50,
            pq.p50,
            family,
            context,
            metric,
            "p50",
            warnings,
        ),
        p90: integer_delta(
            classical.p90,
            pq.p90,
            family,
            context,
            metric,
            "p90",
            warnings,
        ),
        p99: integer_delta(
            classical.p99,
            pq.p99,
            family,
            context,
            metric,
            "p99",
            warnings,
        ),
    }
}

fn float_delta(
    classical: f64,
    pq: f64,
    family: ComparisonFamily,
    context: &ComparisonContext,
    metric: &'static str,
    field: &'static str,
    warnings: &mut Vec<ComparisonWarning>,
) -> Delta<f64> {
    Delta {
        absolute: pq - classical,
        relative: relative_delta(classical, pq, family, context, metric, field, warnings),
    }
}

fn integer_delta(
    classical: u128,
    pq: u128,
    family: ComparisonFamily,
    context: &ComparisonContext,
    metric: &'static str,
    field: &'static str,
    warnings: &mut Vec<ComparisonWarning>,
) -> Delta<i128> {
    let classical_i128 = i128::try_from(classical).expect("metric values should fit in i128");
    let pq_i128 = i128::try_from(pq).expect("metric values should fit in i128");
    Delta {
        absolute: pq_i128 - classical_i128,
        relative: relative_delta(
            parse_f64(&classical),
            parse_f64(&pq),
            family,
            context,
            metric,
            field,
            warnings,
        ),
    }
}

fn relative_delta(
    classical: f64,
    pq: f64,
    family: ComparisonFamily,
    context: &ComparisonContext,
    metric: &'static str,
    field: &'static str,
    warnings: &mut Vec<ComparisonWarning>,
) -> Option<f64> {
    if classical == 0.0 {
        warnings.push(ComparisonWarning {
            family,
            context: context.clone(),
            metric,
            field,
        });
        return None;
    }

    Some((pq - classical) / classical)
}

fn parse_f64(value: &impl ToString) -> f64 {
    value
        .to_string()
        .parse::<f64>()
        .expect("numeric values should parse as f64")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        ComparisonFamily, MetricSummary, RunProvenance, ScenarioAggregate, ScenarioKey,
    };
    use common::ProtocolMode;
    use uuid::Uuid;

    #[test]
    fn computes_pq_deltas_for_x25519_family() {
        let aggregates = AggregateReport {
            scenarios: vec![
                scenario(KeyExchangeMode::X25519, "lite", 10.0, 10, 20, 30),
                scenario(KeyExchangeMode::X25519Mlkem768, "lite", 15.0, 15, 25, 35),
            ],
        };

        let report = compare_aggregates(&aggregates);

        assert_eq!(report.comparisons.len(), 1);
        assert!(report.warnings.is_empty());
        let comparison = &report.comparisons[0];
        assert_eq!(comparison.family, ComparisonFamily::X25519);
        assert!((comparison.tcp.mean.absolute - 5.0).abs() < f64::EPSILON);
        assert_eq!(comparison.tcp.p50.absolute, 5);
        assert_eq!(comparison.tcp.mean.relative, Some(0.5));
    }

    #[test]
    fn skips_missing_pair_members() {
        let aggregates = AggregateReport {
            scenarios: vec![scenario(KeyExchangeMode::X25519, "lite", 10.0, 10, 20, 30)],
        };

        let report = compare_aggregates(&aggregates);

        assert!(report.comparisons.is_empty());
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn records_zero_denominator_warnings() {
        let aggregates = AggregateReport {
            scenarios: vec![
                scenario(KeyExchangeMode::X25519, "lite", 0.0, 0, 0, 0),
                scenario(KeyExchangeMode::X25519Mlkem768, "lite", 15.0, 15, 25, 35),
            ],
        };

        let report = compare_aggregates(&aggregates);

        assert_eq!(report.comparisons.len(), 1);
        assert_eq!(report.warnings.len(), 4);
        assert_eq!(report.comparisons[0].tcp.mean.relative, None);
        assert_eq!(report.comparisons[0].tcp.p50.relative, None);
    }

    fn scenario(
        mode: KeyExchangeMode,
        profile: &str,
        mean: f64,
        p50: u128,
        p90: u128,
        p99: u128,
    ) -> ScenarioAggregate {
        ScenarioAggregate {
            key: ScenarioKey {
                schedule_profile: profile.to_string(),
                proto: ProtocolMode::Raw,
                mode,
                payload_bytes: 1024,
                concurrency: 1,
            },
            tcp: metric(mean, p50, p90, p99),
            handshake: metric(mean + 1.0, p50 + 1, p90 + 1, p99 + 1),
            ttlb: metric(mean + 2.0, p50 + 2, p90 + 2, p99 + 2),
            provenance: vec![RunProvenance {
                run_id: Uuid::nil(),
                result_path: "/tmp/result.jsonl".into(),
                started_at_unix_ms: 1,
                finished_at_unix_ms: 2,
                runner_git_commit: None,
                runner_host: None,
                server_git_commit: None,
                server_host: None,
            }],
        }
    }

    fn metric(mean: f64, p50: u128, p90: u128, p99: u128) -> MetricSummary {
        MetricSummary {
            sample_count: 10,
            run_count: 2,
            mean,
            min: p50,
            max: p99,
            p50,
            p90,
            p99,
        }
    }
}
