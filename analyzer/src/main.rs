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
    error::{Error, Result},
    load::validate_runs,
    model::DiscoveryReport,
    output::{ensure_out_dir, write_artifacts},
};
use clap::Parser;
use std::mem;

fn main() -> Result<()> {
    let args = Args::parse();
    ensure_out_dir(&args.out_dir())?;
    let mut discovery = discover_runs(&args.results_dir)?;

    if args.strict && !discovery.diagnostics.is_empty() {
        return Err(first_discovery_error(&discovery));
    }

    let validation = validate_runs(mem::take(&mut discovery.runs), args.strict)?;
    if validation.valid_runs.is_empty() {
        return Err(Error::NoValidRuns);
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
    )?;

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
