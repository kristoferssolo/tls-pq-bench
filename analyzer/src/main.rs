mod aggregate;
mod args;
mod compare;
mod discovery;
mod error;
mod load;
mod model;
mod output;

use crate::{
    aggregate::aggregate_runs,
    args::{Args, ScheduleProfile},
    compare::compare_aggregates,
    discovery::discover_runs,
    error::Error,
    load::validate_runs,
    model::DiscoveryReport,
    output::{ensure_out_dir, write_artifacts},
};
use clap::Parser;
use miette::Result;
use std::mem;

fn main() -> Result<()> {
    run(&Args::parse())
}

fn run(args: &Args) -> Result<()> {
    ensure_out_dir(&args.out_dir())?;
    let mut discovery = discover_runs(&args.results_dir)?;

    if args.strict && !discovery.diagnostics.is_empty() {
        return Err(first_discovery_error(&discovery).into());
    }

    let validation = validate_runs(mem::take(&mut discovery.runs), args.strict)?;
    if validation.valid_runs.is_empty() {
        return Err(Error::NoValidRuns.into());
    }
    let aggregates = aggregate_runs(
        &validation.valid_runs,
        args.profile.map(ScheduleProfile::as_str),
    );
    let comparisons = compare_aggregates(&aggregates);
    write_artifacts(
        &args.out_dir(),
        &args.results_dir,
        &discovery,
        &validation,
        &aggregates,
        &comparisons,
        args.pretty,
    )
    .map_err(miette::Report::from)?;

    Ok(())
}

fn first_discovery_error(discovery: &DiscoveryReport) -> Error {
    if let Some(path) = discovery.diagnostics.unmatched_results.first() {
        return Error::StrictDiscovery {
            message: format!("missing metadata for result file {}", path.display()),
        };
    }
    if let Some(path) = discovery.diagnostics.unmatched_meta.first() {
        return Error::StrictDiscovery {
            message: format!("missing result file for metadata {}", path.display()),
        };
    }
    if let Some(invalid) = discovery.diagnostics.invalid_pairings.first() {
        return Error::StrictDiscovery {
            message: format!("ambiguous pairing for stem {}", invalid.stem),
        };
    }

    Error::StrictDiscovery {
        message: "unknown discovery failure".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn runs_end_to_end_for_one_valid_lite_run() {
        let dir = TempDir::new().expect("temp dir");
        write_run(
            dir.path(),
            "lite-ok",
            "00000000-0000-0000-0000-000000000001",
            "lite",
            "ok",
            concat!(
                r#"{"run_id":"00000000-0000-0000-0000-000000000001","iteration":0,"proto":"raw","mode":"x25519","payload_bytes":1024,"concurrency":1,"iters":100,"warmup":10,"tcp_ns":10,"handshake_ns":20,"ttlb_ns":30}"#,
                "\n",
                r#"{"run_id":"00000000-0000-0000-0000-000000000001","iteration":1,"proto":"raw","mode":"x25519","payload_bytes":1024,"concurrency":1,"iters":100,"warmup":10,"tcp_ns":11,"handshake_ns":21,"ttlb_ns":31}"#,
                "\n"
            ),
            &[("raw", "x25519", 1024, 100, 10, 1)],
        );

        let args = Args::parse_from(["analyzer", dir.path().to_str().expect("utf8")]);
        assert_ok!(run(&args));

        assert!(dir.path().join("analysis/manifest.json").exists());
        assert!(dir.path().join("analysis/weekly_aggregates.json").exists());
        assert!(dir.path().join("analysis/pq_deltas.json").exists());
        assert!(dir.path().join("analysis/diagnostics.json").exists());
    }

    #[test]
    fn profile_filter_excludes_other_profiles() {
        let dir = TempDir::new().expect("temp dir");
        write_run(
            dir.path(),
            "lite-ok",
            "00000000-0000-0000-0000-000000000001",
            "lite",
            "ok",
            concat!(
                r#"{"run_id":"00000000-0000-0000-0000-000000000001","iteration":0,"proto":"raw","mode":"x25519","payload_bytes":1024,"concurrency":1,"iters":100,"warmup":10,"tcp_ns":10,"handshake_ns":20,"ttlb_ns":30}"#,
                "\n"
            ),
            &[("raw", "x25519", 1024, 100, 10, 1)],
        );
        write_run(
            dir.path(),
            "full-ok",
            "00000000-0000-0000-0000-000000000002",
            "full",
            "ok",
            concat!(
                r#"{"run_id":"00000000-0000-0000-0000-000000000002","iteration":0,"proto":"raw","mode":"x25519","payload_bytes":1024,"concurrency":1,"iters":100,"warmup":10,"tcp_ns":15,"handshake_ns":25,"ttlb_ns":35}"#,
                "\n"
            ),
            &[("raw", "x25519", 1024, 100, 10, 1)],
        );

        let args = Args::parse_from([
            "analyzer",
            dir.path().to_str().expect("utf8"),
            "--profile",
            "lite",
        ]);
        assert_ok!(run(&args));

        let weekly = fs::read_to_string(dir.path().join("analysis/weekly_aggregates.json"))
            .expect("weekly aggregates");
        assert!(weekly.contains(r#""schedule_profile": "lite""#));
        assert!(!weekly.contains(r#""schedule_profile": "full""#));
    }

    #[test]
    fn invalid_inputs_are_skipped_in_default_mode() {
        let dir = TempDir::new().expect("temp dir");
        write_run(
            dir.path(),
            "lite-ok",
            "00000000-0000-0000-0000-000000000001",
            "lite",
            "ok",
            concat!(
                r#"{"run_id":"00000000-0000-0000-0000-000000000001","iteration":0,"proto":"raw","mode":"x25519","payload_bytes":1024,"concurrency":1,"iters":100,"warmup":10,"tcp_ns":10,"handshake_ns":20,"ttlb_ns":30}"#,
                "\n"
            ),
            &[("raw", "x25519", 1024, 100, 10, 1)],
        );
        fs::write(dir.path().join("broken.jsonl"), "{").expect("broken jsonl");
        fs::write(dir.path().join("broken.meta"), "{").expect("broken meta");
        fs::write(dir.path().join("orphan.jsonl"), "").expect("orphan result");

        let args = Args::parse_from(["analyzer", dir.path().to_str().expect("utf8")]);
        assert_ok!(run(&args));

        let diagnostics =
            fs::read_to_string(dir.path().join("analysis/diagnostics.json")).expect("diagnostics");
        assert!(diagnostics.contains(r#""unmatched_results": ["#));
        assert!(diagnostics.contains(r#""kind": "metadata_parse""#));
    }

    #[test]
    fn strict_mode_fails_on_discovery_problem() {
        let dir = TempDir::new().expect("temp dir");
        fs::write(dir.path().join("orphan.jsonl"), "").expect("orphan result");

        let args = Args::parse_from(["analyzer", dir.path().to_str().expect("utf8"), "--strict"]);
        let error = assert_err!(run(&args));

        assert!(
            error
                .to_string()
                .contains("strict mode failed during discovery")
        );
    }

    #[test]
    fn errors_when_no_valid_runs_remain() {
        let dir = TempDir::new().expect("temp dir");
        write_run(
            dir.path(),
            "lite-error",
            "00000000-0000-0000-0000-000000000001",
            "lite",
            "error",
            concat!(
                r#"{"run_id":"00000000-0000-0000-0000-000000000001","iteration":0,"proto":"raw","mode":"x25519","payload_bytes":1024,"concurrency":1,"iters":100,"warmup":10,"tcp_ns":10,"handshake_ns":20,"ttlb_ns":30}"#,
                "\n"
            ),
            &[("raw", "x25519", 1024, 100, 10, 1)],
        );

        let args = Args::parse_from(["analyzer", dir.path().to_str().expect("utf8")]);
        let error = assert_err!(run(&args));

        assert!(error.to_string().contains("no valid benchmark runs remain"));
    }

    fn write_run(
        dir: &std::path::Path,
        stem: &str,
        run_id: &str,
        profile: &str,
        status: &str,
        jsonl: &str,
        benchmarks: &[(&str, &str, u32, u32, u32, u32)],
    ) {
        fs::write(dir.join(format!("{stem}.jsonl")), jsonl).expect("result file");
        fs::write(
            dir.join(format!("{stem}.meta")),
            meta_json(run_id, profile, status, benchmarks),
        )
        .expect("meta file");
    }

    fn meta_json(
        run_id: &str,
        profile: &str,
        status: &str,
        benchmarks: &[(&str, &str, u32, u32, u32, u32)],
    ) -> String {
        let error = if status == "ok" {
            "null".to_string()
        } else {
            r#""runner failed""#.to_string()
        };
        let benchmarks = benchmarks
            .iter()
            .map(|(proto, mode, payload, iters, warmup, concurrency)| {
                format!(
                    concat!(
                        r#"{{"server":"127.0.0.1:4433","server_name":"localhost","#,
                        r#""proto":"{proto}","mode":"{mode}","verification":{{"kind":"insecure"}},"#,
                        r#""payload":{payload},"iters":{iters},"warmup":{warmup},"#,
                        r#""concurrency":{concurrency},"timeout_secs":30}}"#
                    ),
                    proto = proto,
                    mode = mode,
                    payload = payload,
                    iters = iters,
                    warmup = warmup,
                    concurrency = concurrency
                )
            })
            .collect::<Vec<_>>()
            .join(",");

        format!(
            concat!(
                r#"{{"run_id":"{run_id}","status":"{status}","error":{error},"#,
                r#""started_at_unix_ms":1,"finished_at_unix_ms":2,"#,
                r#""rust_version":"rustc 1.0.0","os":"linux","arch":"x86_64","command":"runner","#,
                r#""config_file":"bench.toml","result_path":"results.jsonl","log_path":"run.log","#,
                r#""schedule_profile":"{profile}","runner_git_commit":"abc","runner_host":"runner-1","#,
                r#""runner_instance_type":null,"runner_region":null,"runner_availability_zone":null,"#,
                r#""server_git_commit":"def","server_host":"server-1","server_instance_type":null,"#,
                r#""server_region":null,"server_availability_zone":null,"benchmarks":[{benchmarks}]}}"#
            ),
            run_id = run_id,
            status = status,
            error = error,
            profile = profile,
            benchmarks = benchmarks
        )
    }
}
