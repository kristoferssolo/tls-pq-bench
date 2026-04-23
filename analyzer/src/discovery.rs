use crate::{
    error::{Error, Result},
    model::{DiscoveredRun, DiscoveryDiagnostics, DiscoveryReport, InvalidPairing},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};

pub fn discover_runs(results_dir: &Path) -> Result<DiscoveryReport> {
    let mut result_files: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();
    let mut meta_files: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();

    for path in collect_files(results_dir)? {
        let Some(stem) = file_stem_string(&path) else {
            continue;
        };

        match path.extension().and_then(std::ffi::OsStr::to_str) {
            Some("jsonl") => result_files.entry(stem).or_default().push(path),
            Some("meta") => meta_files.entry(stem).or_default().push(path),
            _ => {}
        }
    }

    let mut report = DiscoveryReport::default();
    let stems = result_files
        .keys()
        .chain(meta_files.keys())
        .cloned()
        .collect::<BTreeSet<_>>();

    for stem in stems {
        let result_paths = result_files.remove(&stem).unwrap_or_default();
        let meta_paths = meta_files.remove(&stem).unwrap_or_default();

        match (result_paths.len(), meta_paths.len()) {
            (1, 1) => {
                report.runs.push(DiscoveredRun {
                    stem,
                    result_path: result_paths[0].clone(),
                    meta_path: meta_paths[0].clone(),
                });
            }
            (0, 1) => report.diagnostics.unmatched_meta.extend(meta_paths),
            (1, 0) => report.diagnostics.unmatched_results.extend(result_paths),
            _ => report.diagnostics.invalid_pairings.push(InvalidPairing {
                stem,
                result_paths,
                meta_paths,
            }),
        }
    }

    report
        .runs
        .sort_by(|left, right| left.stem.cmp(&right.stem));
    sort_diagnostics(&mut report.diagnostics);

    Ok(report)
}

fn collect_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir).map_err(|source| Error::ReadDir {
            path: dir.clone(),
            source,
        })?;

        for entry in entries {
            let entry = entry.map_err(|source| Error::ReadDirEntry {
                path: dir.clone(),
                source,
            })?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                files.push(path);
            }
        }
    }

    Ok(files)
}

fn sort_diagnostics(diagnostics: &mut DiscoveryDiagnostics) {
    diagnostics.unmatched_results.sort();
    diagnostics.unmatched_meta.sort();
    diagnostics
        .invalid_pairings
        .sort_by(|left, right| left.stem.cmp(&right.stem));
}

fn file_stem_string(path: &Path) -> Option<String> {
    path.file_stem()
        .and_then(OsStr::to_str)
        .map(ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::assert_ok;
    use std::{
        fs,
        path::{Path, PathBuf},
    };
    use tempfile::TempDir;

    #[test]
    fn pairs_result_and_meta_by_stem() {
        let dir = TestDir::new();
        dir.write("lite-20260424T010000Z.jsonl", "");
        dir.write("lite-20260424T010000Z.meta", "{}");
        dir.write("ignore.txt", "ignored");

        let report = assert_ok!(discover_runs(dir.path()), "discovery should succeed");

        assert_eq!(report.runs.len(), 1);
        assert_eq!(report.runs[0].stem, "lite-20260424T010000Z");
        assert!(report.diagnostics.is_empty());
    }

    #[test]
    fn reports_unmatched_result_and_meta() {
        let dir = TestDir::new();
        let result_path = dir.write("lite-run.jsonl", "");
        let meta_path = dir.write("full-run.meta", "{}");

        let report = assert_ok!(discover_runs(dir.path()), "discovery should succeed");

        assert!(report.runs.is_empty());
        assert_eq!(report.diagnostics.unmatched_results, vec![result_path]);
        assert_eq!(report.diagnostics.unmatched_meta, vec![meta_path]);
        assert!(report.diagnostics.invalid_pairings.is_empty());
    }

    #[test]
    fn rejects_duplicate_pairings_for_same_stem() {
        let dir = TestDir::new();
        dir.write("lite-run.jsonl", "");
        let nested = dir.mkdir("extra");
        fs::write(nested.join("lite-run.meta"), "{}").expect("nested meta should be written");
        fs::write(dir.path().join("lite-run.meta"), "{}").expect("root meta should be written");

        let report = assert_ok!(discover_runs(dir.path()), "discovery should succeed");

        assert!(report.runs.is_empty());
        assert_eq!(report.diagnostics.invalid_pairings.len(), 1);
        assert_eq!(report.diagnostics.invalid_pairings[0].stem, "lite-run");
    }

    struct TestDir {
        dir: TempDir,
    }

    impl TestDir {
        fn new() -> Self {
            Self {
                dir: TempDir::new().expect("test dir should be created"),
            }
        }

        fn path(&self) -> &Path {
            self.dir.path()
        }

        fn write(&self, name: &str, contents: &str) -> PathBuf {
            let path = self.path().join(name);
            fs::write(&path, contents).expect("fixture file should be written");
            path
        }

        fn mkdir(&self, name: &str) -> PathBuf {
            let path = self.path().join(name);
            fs::create_dir_all(&path).expect("fixture directory should be created");
            path
        }
    }
}
