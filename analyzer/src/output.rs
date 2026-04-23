use std::{fs, path::Path};

pub fn ensure_out_dir(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)
}
