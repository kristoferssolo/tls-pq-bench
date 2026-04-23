use clap::{ArgAction, Parser, ValueEnum};
use std::path::PathBuf;
use strum::Display;

/// Weekly benchmark analyzer.
#[derive(Debug, Parser)]
#[command(name = "analyzer", version, about)]
pub struct Args {
    /// Directory containing scheduled benchmark artifacts.
    pub results_dir: PathBuf,

    /// Directory for generated JSON artifacts.
    #[arg(short, long)]
    pub out_dir: Option<PathBuf>,

    /// Restrict analysis to a single schedule profile.
    #[arg(short, long)]
    pub profile: Option<ScheduleProfile>,

    /// Abort on the first invalid or missing artifact.
    #[arg(short, long)]
    pub strict: bool,

    /// Pretty-print generated JSON files.
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    pub pretty: bool,
}

impl Args {
    #[must_use]
    pub fn out_dir(&self) -> PathBuf {
        self.out_dir
            .clone()
            .unwrap_or_else(|| self.results_dir.join("analysis"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Display)]
#[strum(serialize_all = "lowercase")]
pub enum ScheduleProfile {
    Lite,
    Full,
}

impl ScheduleProfile {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lite => "lite",
            Self::Full => "full",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_output_directory_under_results_dir() {
        let args = Args::parse_from(["analyzer", "weekly-results"]);

        assert_eq!(args.results_dir, PathBuf::from("weekly-results"));
        assert_eq!(args.out_dir(), PathBuf::from("weekly-results/analysis"));
        assert!(!args.strict);
        assert!(args.pretty);
        assert_eq!(args.profile, None);
    }

    #[test]
    fn accepts_explicit_options() {
        let args = Args::parse_from([
            "analyzer",
            "weekly-results",
            "--out-dir",
            "exports",
            "--profile",
            "lite",
            "--strict",
            "--pretty",
            "false",
        ]);

        assert_eq!(args.out_dir(), PathBuf::from("exports"));
        assert_eq!(args.profile, Some(ScheduleProfile::Lite));
        assert!(args.strict);
        assert!(!args.pretty);
    }
}
