mod aggregate;
mod args;
mod compare;
mod discovery;
mod load;
mod model;
mod output;

use clap::Parser;
use miette::IntoDiagnostic;

fn main() -> miette::Result<()> {
    let args = args::Args::parse();
    output::ensure_out_dir(&args.out_dir()).into_diagnostic()?;

    Ok(())
}
