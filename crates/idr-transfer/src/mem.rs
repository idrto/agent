//! In-memory storage and consent: tests, examples, and hosts without a filesystem.
//! State is shared (`Clone`), so it survives a simulated reconnect or restart.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use idr_protocol::transfer::{
    EntryKind, Manifest, ManifestEntry, ManifestKind, ResumePoint, Sha256Digest,
    TransferErrorKind, TransferId,
};

use crate::storage::{Approval, Consent, EntryReader, OfferInfo, Result, Sink, SourceFiles};
use TransferErrorKind::{ChangedDuringTransfer, ConflictingManifest, SourceReadFailed, StorageFailed};

#[derive(Debug, Clone, Default)]
pub struct MemFile {
    pub data: Vec<u8>,
    pub mtime: Option<i64>,
}

type SharedFile = Arc<Mutex<MemFile>>;

/// Sender files keyed by path. Tests may change a file while it is being sent.
#[derive(Clone, Default)]
pub struct MemFiles {
    files: Arc<Mutex<HashMap<Vec<String>, SharedFile>>>,
}

impl MemFiles {
    pub fn insert(&self, path: &[&str], data: Vec<u8>) {
        self.files.lock().unwrap().insert(
            path.iter().map(|s| s.to_string()).collect(),
            Arc::new(Mutex::new(MemFile { data, mtime: None })),
        );
    }

    pub fn file(&self, path: &[&str]) -> SharedFile {
        let key: Vec<String> = path.iter().map(|s| s.to_string()).collect();
        self.files.lock().unwrap()[&key].clone()
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl SourceFiles for MemFiles {
    async fn open(&mut self, entry: &ManifestEntry) -> Result<Box<dyn EntryReader>> {
        let file = self
            .files
            .lock()
            .unwrap()
            .get(&entry.path)
            .cloned()
            .ok_or(SourceReadFailed)?;
        Ok(Box::new(MemReader {
            file,
            pos: 0,
            size: entry.size,
            mtime: entry.mtime,
        }))
    }
}

struct MemReader {
    file: SharedFile,
    pos: usize,
    size: u64,
    mtime: Option<i64>,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl EntryReader for MemReader {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let f = self.file.lock().unwrap();
        let n = f.data.len().saturating_sub(self.pos).min(buf.len());
        buf[..n].copy_from_slice(&f.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }

    async fn verify_unchanged(&mut self) -> Result<()> {
        let f = self.file.lock().unwrap();
        if f.data.len() as u64 == self.size && f.mtime == self.mtime {
            Ok(())
        } else {
            Err(ChangedDuringTransfer)
        }
    }
}

#[derive(Debug, Clone)]
struct Held {
    digest: Sha256Digest,
    manifest: Manifest,
    partial: HashMap<u32, Vec<u8>>,
    checkpoint: HashMap<u32, u64>,
    verified: HashSet<u32>,
}

#[derive(Debug, Default)]
struct SinkState {
    held: HashMap<TransferId, Held>,
    /// What a user would see at the destination: path → contents (`None` = directory).
    visible: BTreeMap<Vec<String>, Option<Vec<u8>>>,
    /// Writes to this entry fail (disk full).
    write_fault: Option<u32>,
    discarded: u32,
}

/// Receiver storage. Loose files become visible on commit; a folder only on finish.
#[derive(Clone, Default)]
pub struct MemSink {
    state: Arc<Mutex<SinkState>>,
    current: Arc<Mutex<Option<TransferId>>>,
}

impl MemSink {
    /// Another handle on the same storage (e.g. after a simulated restart).
    pub fn reopen(&self) -> Self {
        Self {
            state: self.state.clone(),
            current: Arc::new(Mutex::new(None)),
        }
    }

    pub fn visible(&self) -> BTreeMap<String, Option<Vec<u8>>> {
        self.state
            .lock()
            .unwrap()
            .visible
            .iter()
            .map(|(k, v)| (k.join("/"), v.clone()))
            .collect()
    }

    /// Staged / partial state held for `id`, if any.
    pub fn holds(&self, id: &TransferId) -> bool {
        self.state.lock().unwrap().held.contains_key(id)
    }

    pub fn discarded(&self) -> u32 {
        self.state.lock().unwrap().discarded
    }

    pub fn partial_len(&self, id: &TransferId, entry: u32) -> u64 {
        let st = self.state.lock().unwrap();
        st.held[id].partial.get(&entry).map_or(0, |p| p.len() as u64)
    }

    /// Flip one persisted byte of a partial entry.
    pub fn tamper(&self, id: &TransferId, entry: u32, at: usize) {
        let mut st = self.state.lock().unwrap();
        st.held.get_mut(id).unwrap().partial.get_mut(&entry).unwrap()[at] ^= 0xff;
    }

    pub fn fail_writes_to(&self, entry: Option<u32>) {
        self.state.lock().unwrap().write_fault = entry;
    }

    fn with_held<T>(&self, f: impl FnOnce(&mut Held, &mut SinkState) -> Result<T>) -> Result<T> {
        let id = self.current.lock().unwrap().ok_or(StorageFailed)?;
        let mut st = self.state.lock().unwrap();
        let mut held = st.held.remove(&id).ok_or(StorageFailed)?;
        let r = f(&mut held, &mut st);
        st.held.insert(id, held);
        r
    }
}

fn path_of(m: &Manifest, entry: u32) -> Result<&ManifestEntry> {
    m.entries.get(entry as usize).ok_or(StorageFailed)
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Sink for MemSink {
    async fn prepare(
        &mut self,
        id: &TransferId,
        digest: &Sha256Digest,
        manifest: &Manifest,
    ) -> Result<Vec<ResumePoint>> {
        let mut st = self.state.lock().unwrap();
        let held = st.held.entry(*id).or_insert_with(|| Held {
            digest: *digest,
            manifest: manifest.clone(),
            partial: HashMap::new(),
            checkpoint: HashMap::new(),
            verified: HashSet::new(),
        });
        if held.digest != *digest {
            return Err(ConflictingManifest);
        }
        // Unpersisted bytes past the last checkpoint are gone after a restart.
        let Held {
            partial, checkpoint, ..
        } = held;
        for (entry, data) in partial.iter_mut() {
            data.truncate(checkpoint.get(entry).copied().unwrap_or(0) as usize);
        }
        let points = held
            .manifest
            .entries
            .iter()
            .filter_map(|e| {
                if held.verified.contains(&e.id) {
                    Some(ResumePoint {
                        entry: e.id,
                        verified: e.size,
                        complete: true,
                    })
                } else {
                    let len = held.partial.get(&e.id).map_or(0, |p| p.len() as u64);
                    (len > 0).then_some(ResumePoint {
                        entry: e.id,
                        verified: len,
                        complete: false,
                    })
                }
            })
            .collect();
        *self.current.lock().unwrap() = Some(*id);
        Ok(points)
    }

    async fn create_dir(&mut self, entry: u32) -> Result<()> {
        self.with_held(|h, _| {
            h.verified.insert(entry);
            Ok(())
        })
    }

    async fn read_partial(&mut self, entry: u32, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.with_held(|h, _| {
            let p = h.partial.get(&entry).map(Vec::as_slice).unwrap_or(&[]);
            let start = (offset as usize).min(p.len());
            let n = (p.len() - start).min(buf.len());
            buf[..n].copy_from_slice(&p[start..start + n]);
            Ok(n)
        })
    }

    async fn write(&mut self, entry: u32, offset: u64, bytes: &[u8]) -> Result<()> {
        self.with_held(|h, st| {
            if st.write_fault == Some(entry) {
                return Err(StorageFailed);
            }
            let p = h.partial.entry(entry).or_default();
            if p.len() as u64 != offset {
                return Err(StorageFailed);
            }
            p.extend_from_slice(bytes);
            Ok(())
        })
    }

    async fn checkpoint(&mut self, entry: u32, len: u64) -> Result<()> {
        self.with_held(|h, _| {
            h.checkpoint.insert(entry, len);
            Ok(())
        })
    }

    async fn commit(&mut self, entry: u32) -> Result<()> {
        self.with_held(|h, st| {
            h.verified.insert(entry);
            if h.manifest.kind == ManifestKind::Files {
                let e = path_of(&h.manifest, entry)?;
                let data = h.partial.remove(&entry).unwrap_or_default();
                st.visible.insert(e.path.clone(), Some(data));
            }
            Ok(())
        })
    }

    async fn fail(&mut self, entry: u32) -> Result<()> {
        self.with_held(|h, _| {
            h.partial.remove(&entry);
            h.checkpoint.remove(&entry);
            Ok(())
        })
    }

    async fn finish(&mut self) -> Result<()> {
        let id = self.current.lock().unwrap().take().ok_or(StorageFailed)?;
        let mut st = self.state.lock().unwrap();
        let mut held = st.held.remove(&id).ok_or(StorageFailed)?;
        if held.manifest.kind == ManifestKind::Folder {
            for e in &held.manifest.entries {
                let v = match e.kind {
                    EntryKind::Dir => None,
                    EntryKind::File => Some(held.partial.remove(&e.id).unwrap_or_default()),
                };
                st.visible.insert(e.path.clone(), v);
            }
        }
        Ok(())
    }

    async fn discard(&mut self) -> Result<()> {
        if let Some(id) = self.current.lock().unwrap().take() {
            let mut st = self.state.lock().unwrap();
            st.held.remove(&id);
            st.discarded += 1;
        }
        Ok(())
    }
}

/// Accepts every offer.
pub struct AcceptAll(pub Approval);

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Consent for AcceptAll {
    async fn decide(&mut self, _: &OfferInfo<'_>) -> Result<Approval> {
        Ok(self.0)
    }
}

/// Refuses every offer with `code` (e.g. a headless endpoint with no policy).
pub struct DenyAll(pub TransferErrorKind);

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Consent for DenyAll {
    async fn decide(&mut self, _: &OfferInfo<'_>) -> Result<Approval> {
        Err(self.0)
    }
}
