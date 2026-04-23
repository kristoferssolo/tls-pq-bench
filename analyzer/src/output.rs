use crate::error::{Error, Result};
use std::{fs, path::Path};

pub fn ensure_out_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|source| Error::CreateOutDir {
        path: path.to_path_buf(),
        source,
    })
}
