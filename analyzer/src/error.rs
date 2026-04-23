use miette::Diagnostic;
use std::path::PathBuf;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error("failed to create output directory {path}")]
    CreateOutDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to read results directory {path}")]
    ReadDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to read entry in {path}")]
    ReadDirEntry {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to open result file {path}")]
    OpenResultFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to read result file {path}")]
    ReadResultFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse JSONL record at {path}:{line}")]
    ParseJsonlRecord {
        path: PathBuf,
        line: usize,
        #[source]
        source: serde_json::Error,
    },

    #[error("failed to open metadata file {path}")]
    OpenMetadataFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse metadata file {path}")]
    ParseMetadataFile {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("failed to serialize artifact {name}")]
    SerializeArtifact {
        name: &'static str,
        #[source]
        source: serde_json::Error,
    },

    #[error("failed to write artifact {path}")]
    WriteArtifact {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("strict mode failed during discovery: {message}")]
    StrictDiscovery { message: String },

    #[error("strict mode failed during validation: {message}")]
    StrictValidation { message: String },

    #[error("no valid benchmark runs remain after validation")]
    NoValidRuns,
}
