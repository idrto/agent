//! Receiver storage on the local filesystem.
//!
//! Everything goes through `cap-std` directory handles opened under the
//! receiver-chosen destination, with no-follow opens, so neither a manifest
//! path nor a symlink swapped in during the transfer can reach outside it.
//!
//! Layout, all inside the destination (so the same volume):
//!
//! ```text
//! <dest>/.idr-partial-<transfer id hex>/   private staging, one per transfer
//!     journal.db                            resume journal (block-hash checkpoints)
//!     p/<entry id>                          partial files, named by id until commit
//!     t/<Root>/...                          folder transfers: verified tree
//! ```
//!
//! Loose files are renamed into `<dest>` as each one verifies. A folder is
//! renamed into `<dest>` once, after every entry verified. Both renames never
//! replace: a taken name becomes `name (2)`, `name (3)`, ... No remote
//! permission bits or extended attributes are applied; only mtime.

use std::collections::HashMap;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, DirBuilder, File, OpenOptions};
use idr_protocol::transfer::{
    EntryKind, Manifest, ManifestKind, ResumePoint, Sha256Digest, TransferErrorKind, TransferId,
};
use sha2::{Digest, Sha256};

use super::journal::{self, Journal};
use super::rename::{rename_noreplace, RenameError};
use crate::names::{map_manifest, numbered, NamePolicy};
use crate::storage::{Result, Sink};

use TransferErrorKind::{ConflictingManifest, StorageFailed};

pub const STAGING_PREFIX: &str = ".idr-partial-";
/// Give up numbering a taken name after this many tries.
const MAX_NUMBERED: u32 = 1000;

fn storage(e: impl std::fmt::Display) -> TransferErrorKind {
    tracing::warn!(error = %e, "transfer storage failure");
    StorageFailed
}

fn hex(id: &TransferId) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

fn open_rw() -> OpenOptions {
    let mut o = OpenOptions::new();
    o.read(true).write(true).follow(FollowSymlinks::No);
    o
}

fn private_dir(parent: &Dir, name: &str) -> io::Result<()> {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut b = DirBuilder::new();
    #[cfg(unix)]
    {
        use cap_std::fs::DirBuilderExt;
        b.mode(0o700);
    }
    parent.create_dir_with(name, &b)
}

struct Writer {
    entry: u32,
    file: File,
    /// Hash of the bytes since the last checkpoint.
    block: Sha256,
}

struct Open {
    manifest: Manifest,
    mapped: Vec<Vec<String>>,
    staging_name: String,
    staging_path: PathBuf,
    parts: Dir,
    tree: Option<Dir>,
    journal: Journal,
    writer: Option<Writer>,
    /// Staged folder directories already created, by relative path (bounded).
    dirs: HashMap<PathBuf, Dir>,
}

/// Directory handles kept per transfer; past this the cache starts over.
const DIR_CACHE: usize = 256;

pub struct NativeSink {
    root: Dir,
    root_path: PathBuf,
    policy: NamePolicy,
    cur: Option<Open>,
    renamed: Vec<(u32, String)>,
}

impl NativeSink {
    /// Receive into `dest`, an existing directory the receiver chose and policy allows.
    pub fn new(dest: &Path) -> io::Result<Self> {
        Self::with_policy(dest, NamePolicy::native())
    }

    /// Storage in `rel` under `root`, opened relative to a handle on `root`:
    /// a link anywhere in `rel` that leads out of `root` is refused, even one
    /// swapped in after the destination was checked.
    pub fn open_in(root: &Path, rel: &Path) -> io::Result<Self> {
        let base = Dir::open_ambient_dir(root, ambient_authority())?;
        let dir = if rel.as_os_str().is_empty() { base } else { base.open_dir(rel)? };
        Ok(Self {
            root: dir,
            root_path: root.join(rel),
            policy: NamePolicy::native(),
            cur: None,
            renamed: Vec::new(),
        })
    }

    pub fn with_policy(dest: &Path, policy: NamePolicy) -> io::Result<Self> {
        Ok(Self {
            root: Dir::open_ambient_dir(dest, ambient_authority())?,
            root_path: dest.to_path_buf(),
            policy,
            cur: None,
            renamed: Vec::new(),
        })
    }

    fn cur(&mut self) -> Result<&mut Open> {
        self.cur.as_mut().ok_or(StorageFailed)
    }

    /// Remove staging of transfers idle longer than `max_age`. Returns how many.
    pub fn sweep(&self, max_age: Duration) -> io::Result<u32> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
        let mut removed = 0;
        for entry in self.root.entries()? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with(STAGING_PREFIX) || !entry.file_type()?.is_dir() {
                continue;
            }
            let jpath = self.root_path.join(&name).join(journal::FILE);
            let stale = match Journal::updated_at(&jpath) {
                Some(t) => now - t > max_age.as_secs() as i64,
                None => true, // no readable journal: nothing to resume from
            };
            if stale {
                self.root.remove_dir_all(&name)?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    fn open_existing(&mut self, staging_name: &str, digest: &Sha256Digest) -> Result<Journal> {
        let jpath = self.root_path.join(staging_name).join(journal::FILE);
        let (j, stored) = Journal::open(&jpath).map_err(storage)?;
        if stored != digest[..] {
            return Err(ConflictingManifest);
        }
        Ok(j)
    }

    /// Prove a partial file against its block hashes; cut it back to the last
    /// good block. Returns the verified length.
    fn verify_partial(parts: &Dir, journal: &Journal, entry: u32) -> Result<u64> {
        let name = entry.to_string();
        let mut file = match parts.open_with(&name, &open_rw()) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                journal.reset(entry).map_err(storage)?;
                return Ok(0);
            }
            Err(e) => return Err(storage(e)),
        };
        let mut good = 0u64;
        let mut buf = vec![0u8; 64 * 1024];
        for (end, sha) in journal.blocks(entry).map_err(storage)? {
            let mut h = Sha256::new();
            let mut left = end - good;
            file.seek(SeekFrom::Start(good)).map_err(storage)?;
            while left > 0 {
                let want = left.min(buf.len() as u64) as usize;
                let n = file.read(&mut buf[..want]).map_err(storage)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
                left -= n as u64;
            }
            if left > 0 || <[u8; 32]>::from(h.finalize()) != sha {
                break;
            }
            good = end;
        }
        // Anything past the last proven block is unverified: drop it.
        file.set_len(good).map_err(storage)?;
        file.sync_all().map_err(storage)?;
        journal.truncate(entry, good).map_err(storage)?;
        Ok(good)
    }

    /// Rename `from` (in `from_dir`) into `to_dir` as `name`, or `name (n)` if taken.
    fn place(from_dir: &Dir, from: &str, to_dir: &Dir, name: &str) -> Result<String> {
        for n in 1..=MAX_NUMBERED {
            let candidate = if n == 1 { name.to_string() } else { numbered(name, n) };
            match rename_noreplace(from_dir, from, to_dir, &candidate) {
                Ok(()) => return Ok(candidate),
                Err(RenameError::Exists) => continue,
                Err(RenameError::NotSupported) => {
                    return Err(storage("no atomic no-replace rename on this filesystem"))
                }
                Err(RenameError::Io(e)) => return Err(storage(e)),
            }
        }
        Err(storage("no free name"))
    }

    fn close_writer(open: &mut Open) -> Result<()> {
        if let Some(w) = open.writer.take() {
            w.file.sync_all().map_err(storage)?;
        }
        Ok(())
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Sink for NativeSink {
    async fn prepare(
        &mut self,
        id: &TransferId,
        digest: &Sha256Digest,
        manifest: &Manifest,
    ) -> Result<Vec<ResumePoint>> {
        let staging_name = format!("{STAGING_PREFIX}{}", hex(id));
        let staging_path = self.root_path.join(&staging_name);
        let existed = self.root.is_dir(&staging_name);
        let journal = if existed {
            self.open_existing(&staging_name, digest)?
        } else {
            private_dir(&self.root, &staging_name).map_err(storage)?;
            Journal::create(&staging_path.join(journal::FILE), digest, &manifest.encode())
                .map_err(storage)?
        };
        let staging = self.root.open_dir(&staging_name).map_err(storage)?;
        for sub in ["p", "t"] {
            if !staging.is_dir(sub) {
                private_dir(&staging, sub).map_err(storage)?;
            }
        }
        let parts = staging.open_dir("p").map_err(storage)?;
        let tree = match manifest.kind {
            ManifestKind::Folder => Some(staging.open_dir("t").map_err(storage)?),
            ManifestKind::Files => None,
        };

        let mut points = Vec::new();
        for row in journal.entries().map_err(storage)? {
            let size = manifest.entries.get(row.id as usize).ok_or(StorageFailed)?.size;
            if row.verified {
                points.push(ResumePoint { entry: row.id, verified: size, complete: true });
            } else {
                let good = Self::verify_partial(&parts, &journal, row.id)?;
                if good > 0 {
                    points.push(ResumePoint { entry: row.id, verified: good, complete: false });
                }
            }
        }
        // Partial files with no journal row hold nothing proven.
        for e in manifest.entries.iter().filter(|e| e.kind == EntryKind::File) {
            if !points.iter().any(|p| p.entry == e.id) {
                let _ = parts.remove_file(e.id.to_string());
            }
        }

        let (mapped, renamed) = map_manifest(manifest, self.policy);
        self.renamed = renamed
            .into_iter()
            .map(|i| (i, mapped[i as usize].join("/")))
            .collect();
        self.cur = Some(Open {
            manifest: manifest.clone(),
            mapped,
            staging_name,
            staging_path,
            parts,
            tree,
            journal,
            writer: None,
            dirs: HashMap::new(),
        });
        Ok(points)
    }

    async fn create_dir(&mut self, entry: u32) -> Result<()> {
        let o = self.cur()?;
        let tree = o.tree.as_ref().ok_or(StorageFailed)?;
        let rel: PathBuf = o.mapped[entry as usize].iter().collect();
        tree.create_dir_all(rel).map_err(storage)
    }

    async fn read_partial(&mut self, entry: u32, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let o = self.cur()?;
        let mut f = o
            .parts
            .open_with(entry.to_string(), &open_rw())
            .map_err(storage)?;
        f.seek(SeekFrom::Start(offset)).map_err(storage)?;
        f.read(buf).map_err(storage)
    }

    async fn write(&mut self, entry: u32, offset: u64, bytes: &[u8]) -> Result<()> {
        let o = self.cur()?;
        if o.writer.as_ref().map(|w| w.entry) != Some(entry) {
            Self::close_writer(o)?;
            let mut opts = open_rw();
            opts.create(true);
            let file = o.parts.open_with(entry.to_string(), &opts).map_err(storage)?;
            o.writer = Some(Writer { entry, file, block: Sha256::new() });
        }
        let w = o.writer.as_mut().unwrap();
        let len = w.file.metadata().map_err(storage)?.len();
        if len != offset {
            return Err(storage(format!("write at {offset}, partial holds {len}")));
        }
        w.file.seek(SeekFrom::End(0)).map_err(storage)?;
        w.file.write_all(bytes).map_err(storage)?;
        w.block.update(bytes);
        Ok(())
    }

    async fn checkpoint(&mut self, entry: u32, len: u64) -> Result<()> {
        let o = self.cur()?;
        let Some(w) = o.writer.as_mut().filter(|w| w.entry == entry) else {
            return Err(storage("checkpoint without writer"));
        };
        // Data first, then the record that advertises it.
        w.file.sync_data().map_err(storage)?;
        let sha: [u8; 32] = std::mem::take(&mut w.block).finalize().into();
        o.journal.checkpoint(entry, len, &sha).map_err(storage)
    }

    async fn commit(&mut self, entry: u32) -> Result<()> {
        let o = self.cur.as_mut().ok_or(StorageFailed)?;
        let name = entry.to_string();
        let mtime = o
            .manifest
            .entries
            .get(entry as usize)
            .ok_or(StorageFailed)?
            .mtime
            .map(|secs| UNIX_EPOCH + Duration::from_secs(secs.max(0) as u64));
        match o.writer.take() {
            // Set the time on the open handle, then make data and metadata durable.
            Some(w) if w.entry == entry => {
                let f = w.file.into_std();
                if let Some(t) = mtime {
                    let _ = f.set_modified(t);
                }
                f.sync_all().map_err(storage)?;
            }
            other => {
                o.writer = other;
                Self::close_writer(o)?;
                if !o.parts.exists(&name) {
                    // Empty file: no bytes were written.
                    o.parts.create(&name).map_err(storage)?;
                }
                if let Some(t) = mtime {
                    let f = o.parts.open_with(&name, &open_rw()).map_err(storage)?;
                    let _ = f.into_std().set_modified(t);
                }
            }
        }
        let path = &o.mapped[entry as usize];
        match &o.tree {
            None => {
                let placed = Self::place(&o.parts, &name, &self.root, &path[0])?;
                if placed != path[0] {
                    self.renamed.push((entry, placed));
                }
            }
            Some(tree) => {
                let parent: PathBuf = path[..path.len() - 1].iter().collect();
                if !o.dirs.contains_key(&parent) {
                    tree.create_dir_all(&parent).map_err(storage)?;
                    let d = tree.open_dir(&parent).map_err(storage)?;
                    if o.dirs.len() >= DIR_CACHE {
                        o.dirs.clear();
                    }
                    o.dirs.insert(parent.clone(), d);
                }
                let dir = &o.dirs[&parent];
                match rename_noreplace(&o.parts, &name, dir, path.last().unwrap()) {
                    Ok(()) => {}
                    Err(RenameError::Exists) => return Err(storage("mapped name collision")),
                    Err(RenameError::NotSupported) => return Err(storage("rename unsupported")),
                    Err(RenameError::Io(e)) => return Err(storage(e)),
                }
            }
        }
        let o = self.cur.as_mut().unwrap();
        o.journal.verified(entry).map_err(storage)
    }

    async fn fail(&mut self, entry: u32) -> Result<()> {
        let o = self.cur()?;
        if o.writer.as_ref().is_some_and(|w| w.entry == entry) {
            o.writer = None;
        }
        match o.parts.remove_file(entry.to_string()) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(storage(e)),
        }
        o.journal.reset(entry).map_err(storage)
    }

    async fn finish(&mut self) -> Result<()> {
        let mut o = self.cur.take().ok_or(StorageFailed)?;
        Self::close_writer(&mut o)?;
        // Windows won't move or delete a tree with open handles inside it.
        o.dirs.clear();
        if let Some(tree) = &o.tree {
            let root_name = o.mapped.first().ok_or(StorageFailed)?[0].clone();
            let finishing = o.journal.meta("finishing").map_err(storage)?.is_some();
            if tree.is_dir(&root_name) {
                o.journal.set_meta("finishing", b"1").map_err(storage)?;
                let placed = Self::place(tree, &root_name, &self.root, &root_name)?;
                if placed != root_name {
                    self.renamed.push((0, placed));
                }
            } else if !finishing {
                return Err(storage("staged folder missing"));
            }
            // else: an earlier finish moved it and stopped before cleanup.
        }
        let Open { staging_name, journal, parts, tree, .. } = o;
        drop((journal, parts, tree));
        self.root.remove_dir_all(&staging_name).map_err(storage)
    }

    async fn discard(&mut self) -> Result<()> {
        let Some(o) = self.cur.take() else {
            return Ok(());
        };
        let Open { staging_name, journal, parts, tree, writer, dirs, .. } = o;
        drop((journal, parts, tree, writer, dirs));
        match self.root.remove_dir_all(&staging_name) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(storage(e)),
            _ => Ok(()),
        }
    }

    fn take_renamed(&mut self) -> Vec<(u32, String)> {
        std::mem::take(&mut self.renamed)
    }
}

impl NativeSink {
    /// Where this transfer stages (for diagnostics and tests).
    pub fn staging_path(&self) -> Option<&Path> {
        self.cur.as_ref().map(|o| o.staging_path.as_path())
    }
}
