use crate::model::{
    AggregateReport, ComparisonContext, ComparisonFamily, ComparisonReport, ComparisonWarning,
    Delta, MetricComparison, MetricSummary, PairwiseComparison, ScenarioAggregate,
};
use std::collections::BTreeMap;

pub fn compare_aggregates(aggregates: &AggregateReport) -> ComparisonReport {
    let mut grouped =
        BTreeMap::<(ComparisonFamily, ComparisonContext), Vec<&ScenarioAggregate>>::new();

    for scenario in &aggregates.scenarios {
        let family = ComparisonFamily::from_mode(scenario.key.mode);
        let context = ComparisonContext::from(&scenario.key);
        grouped.entry((family, context)).or_default().push(scenario);
    }

    let mut report = ComparisonReport::default();
    for ((family, context), scenarios) in grouped {
        let (classical_mode, pq_mode) = family.modes();
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
        mean: delta_for(
            classical.mean,
            pq.mean,
            family,
            context,
            metric,
            "mean",
            warnings,
        ),
        p50: delta_for(
            classical.p50,
            pq.p50,
            family,
            context,
            metric,
            "p50",
            warnings,
        ),
        p90: delta_for(
            classical.p90,
            pq.p90,
            family,
            context,
            metric,
            "p90",
            warnings,
        ),
        p99: delta_for(
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

fn delta_for<T>(
    classical: T,
    pq: T,
    family: ComparisonFamily,
    context: &ComparisonContext,
    metric: &'static str,
    field: &'static str,
    warnings: &mut Vec<ComparisonWarning>,
) -> Delta<T::Absolute>
where
    T: DeltaValue,
{
    Delta {
        absolute: classical.absolute_delta(pq),
        relative: relative_delta(
            classical.as_f64(),
            pq.as_f64(),
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
            message: format!(
                "relative delta omitted for {metric}.{field} because classical value is zero"
            ),
        });
        return None;
    }

    Some((pq - classical) / classical)
}

trait DeltaValue: Copy {
    type Absolute;

    fn absolute_delta(self, other: Self) -> Self::Absolute;
    fn as_f64(self) -> f64;
}

impl DeltaValue for f64 {
    type Absolute = Self;

    fn absolute_delta(self, other: Self) -> Self::Absolute {
        other - self
    }

    fn as_f64(self) -> f64 {
        self
    }
}

impl DeltaValue for u128 {
    type Absolute = i128;

    fn absolute_delta(self, other: Self) -> Self::Absolute {
        let left = i128::try_from(self).expect("metric values should fit in i128");
        let right = i128::try_from(other).expect("metric values should fit in i128");
        right - left
    }

    fn as_f64(self) -> f64 {
        self.to_string()
            .parse::<f64>()
            .expect("numeric values should parse as f64")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        AggregateReport, RunProvenance, ScenarioAggregate, ScenarioKey, ScenarioProvenance,
    };
    use common::{KeyExchangeMode, ProtocolMode};
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
        assert_eq!(
            report.warnings[0].message,
            "relative delta omitted for tcp.mean because classical value is zero"
        );
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
            provenance: ScenarioProvenance::from_runs(vec![RunProvenance {
                run_id: Uuid::nil(),
                result_path: "/tmp/result.jsonl".into(),
                started_at_unix_ms: 1,
                finished_at_unix_ms: 2,
                runner_git_commit: None,
                runner_host: None,
                server_git_commit: None,
                server_host: None,
                iters: 100,
                warmup: 10,
            }]),
            warnings: Vec::new(),
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
