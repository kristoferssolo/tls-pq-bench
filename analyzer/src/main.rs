mod aggregate;
mod args;
mod compare;
mod discovery;
mod load;
mod model;
mod output;

use crate::{args::Args, discovery::discover_runs, load::validate_runs, output::ensure_out_dir};
use clap::Parser;
use miette::{IntoDiagnostic, miette};

fn main() -> miette::Result<()> {
    let args = Args::parse();
    ensure_out_dir(&args.out_dir()).into_diagnostic()?;
    let discovery = discover_runs(&args.results_dir)?;

    if args.strict && !discovery.diagnostics.is_empty() {
        return Err(first_discovery_error(&discovery));
    }

    let validation = validate_runs(discovery.runs, args.strict)?;
    if validation.valid_runs.is_empty() {
        return Err(miette!("no valid benchmark runs remain after validation"));
    }

    Ok(())
}

fn first_discovery_error(discovery: &model::DiscoveryReport) -> miette::Error {
    if let Some(path) = discovery.diagnostics.unmatched_results.first() {
        return miette!("missing metadata for result file {}", path.display());
    }
    if let Some(path) = discovery.diagnostics.unmatched_meta.first() {
        return miette!("missing result file for metadata {}", path.display());
    }
    if let Some(invalid) = discovery.diagnostics.invalid_pairings.first() {
        return miette!("ambiguous pairing for stem {}", invalid.stem);
    }

    miette!("unknown discovery failure")
}
