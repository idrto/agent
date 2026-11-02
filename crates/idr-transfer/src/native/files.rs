//! Sender file contents from the local filesystem.
//!
//! Manifest paths resolve inside a sandboxed root (`cap-std`) — or, for loose
//! files, inside each file's own parent — and the file itself is opened without
//! following a symlink, so a selected path can't read outside the selection.
//! [`super::enumerate`] builds the selection; this opens what the manifest names.

use std::collections::HashMap;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use async_trait::async_trait;
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, File, OpenOptions};
use idr_protocol::transfer::{ManifestEntry, TransferErrorKind};

use crate::manifest::Selected;
use crate::storage::{EntryReader, Result, SourceFiles};

use TransferErrorKind::{ChangedDuringTransfer, SourceReadFailed};

pub struct NativeFiles {
    root: Option<Dir>,
    /// Loose files by manifest name: the parent directory and the file's name in it.
    loose: HashMap<String, (Dir, String)>,
}

impl NativeFiles {
    /// Manifest paths are relative to `root` (for a folder, its parent).
    pub fn new(root: &Path) -> io::Result<Self> {
        Ok(Self {
            root: Some(Dir::open_ambient_dir(root, ambient_authority())?),
            loose: HashMap::new(),
        })
    }

    /// Loose files from any directories. Each opens inside its own parent; the
    /// manifest names them by file name, which must be unique.
    pub fn loose(paths: &[PathBuf]) -> io::Result<(Self, Vec<Selected>)> {
        let invalid = |m: &str| io::Error::new(io::ErrorKind::InvalidInput, m.to_string());
        let mut loose = HashMap::new();
        let mut selected = Vec::new();
        for p in paths {
            let name = p
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| invalid("file name is not valid UTF-8"))?
                .to_string();
            let parent = p.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
            let dir = Dir::open_ambient_dir(parent, ambient_authority())?;
            let meta = dir.symlink_metadata(&name)?;
            if !meta.file_type().is_file() {
                return Err(invalid("not a regular file"));
            }
            if loose.contains_key(&name) {
                return Err(invalid("two selected files have the same name"));
            }
            selected.push(Selected {
                path: vec![name.clone()],
                mtime: mtime_secs(&meta),
                ..Selected::file(&[], meta.len())
            });
            loose.insert(name.clone(), (dir, name));
        }
        Ok((Self { root: None, loose }, selected))
    }
}

/// Seconds since the epoch, as manifests carry it.
pub fn mtime_secs(m: &cap_std::fs::Metadata) -> Option<i64> {
    let t = m.modified().ok()?.into_std();
    Some(t.duration_since(UNIX_EPOCH).ok()?.as_secs() as i64)
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl SourceFiles for NativeFiles {
    async fn open(&mut self, entry: &ManifestEntry) -> Result<Box<dyn EntryReader>> {
        let mut opts = OpenOptions::new();
        opts.read(true).follow(FollowSymlinks::No);
        let file = match (&self.root, entry.path.as_slice()) {
            (_, [name]) if self.loose.contains_key(name) => {
                let (dir, file) = &self.loose[name];
                dir.open_with(file, &opts)
            }
            (Some(root), path) => root.open_with(path.iter().collect::<PathBuf>(), &opts),
            (None, _) => return Err(SourceReadFailed),
        }
        .map_err(|_| SourceReadFailed)?;
        let meta = file.metadata().map_err(|_| SourceReadFailed)?;
        if !meta.is_file() {
            return Err(SourceReadFailed);
        }
        Ok(Box::new(NativeReader {
            file,
            size: entry.size,
            mtime: entry.mtime,
        }))
    }
}

struct NativeReader {
    file: File,
    size: u64,
    mtime: Option<i64>,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl EntryReader for NativeReader {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.file.read(buf).map_err(|_| SourceReadFailed)
    }

    async fn verify_unchanged(&mut self) -> Result<()> {
        let meta = self.file.metadata().map_err(|_| SourceReadFailed)?;
        let mtime_ok = self.mtime.is_none() || mtime_secs(&meta) == self.mtime;
        if meta.len() == self.size && mtime_ok {
            Ok(())
        } else {
            Err(ChangedDuringTransfer)
        }
    }
}
