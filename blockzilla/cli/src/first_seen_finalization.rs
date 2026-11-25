//! Durable publication helpers shared by the native block builder.
use anyhow::{Context, Result};
use std::{
    fs::File,
    path::{Path, PathBuf},
};

pub(crate) fn first_seen_temp_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("first-seen");
    path.with_file_name(format!("{name}.prehot.tmp"))
}

pub(crate) fn sync_candidate_files(output_dir: &Path) -> Result<()> {
    for entry in std::fs::read_dir(output_dir)
        .with_context(|| format!("read scan output dir {}", output_dir.display()))?
    {
        let entry = entry.with_context(|| format!("read entry in {}", output_dir.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("stat scan output {}", entry.path().display()))?;
        if !file_type.is_file() {
            continue;
        }
        File::open(entry.path())
            .with_context(|| format!("open scan output {} for sync", entry.path().display()))?
            .sync_all()
            .with_context(|| format!("sync scan output {}", entry.path().display()))?;
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("open output directory {} for sync", path.display()))?
        .sync_all()
        .with_context(|| format!("sync output directory {}", path.display()))
}

#[cfg(not(unix))]
pub(crate) fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}
