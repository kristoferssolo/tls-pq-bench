use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredRun {
    pub stem: String,
    pub result_path: PathBuf,
    pub meta_path: PathBuf,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DiscoveryDiagnostics {
    pub unmatched_results: Vec<PathBuf>,
    pub unmatched_meta: Vec<PathBuf>,
    pub invalid_pairings: Vec<InvalidPairing>,
}

impl DiscoveryDiagnostics {
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.unmatched_results.is_empty()
            && self.unmatched_meta.is_empty()
            && self.invalid_pairings.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidPairing {
    pub stem: String,
    pub result_paths: Vec<PathBuf>,
    pub meta_paths: Vec<PathBuf>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DiscoveryReport {
    pub runs: Vec<DiscoveredRun>,
    pub diagnostics: DiscoveryDiagnostics,
}
