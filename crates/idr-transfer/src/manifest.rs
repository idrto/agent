//! Manifest building (sender), validation (receiver) and the consent summary.
//!
//! One model for all three modes: loose files ([`ManifestKind::Files`]), a
//! complete folder, and a selection from a folder (both [`ManifestKind::Folder`]).
//! Selection is sender-side: the manifest holds exactly the selected entries plus
//! their parent directories.
//!
//! Validation is platform-independent: structure, limits, and collisions after
//! case-folding and Unicode NFC normalization (a manifest that would collide on
//! any receiver is refused). Platform-specific renames happen in storage.

use std::collections::{HashMap, HashSet};

use unicode_normalization::UnicodeNormalization;

use idr_protocol::transfer::{EntryKind, Manifest, ManifestEntry, ManifestKind, TransferErrorKind};

use crate::limits::Limits;

/// One item an enumerator selected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selected {
    pub path: Vec<String>,
    pub kind: EntryKind,
    pub size: u64,
    pub mtime: Option<i64>,
    pub mime: Option<String>,
}

impl Selected {
    pub fn file(path: &[&str], size: u64) -> Self {
        Self {
            path: path.iter().map(|s| s.to_string()).collect(),
            kind: EntryKind::File,
            size,
            mtime: None,
            mime: None,
        }
    }

    pub fn dir(path: &[&str]) -> Self {
        Self {
            kind: EntryKind::Dir,
            size: 0,
            ..Self::file(path, 0)
        }
    }
}

/// Build a manifest from selected items. Duplicates collapse; folder manifests
/// gain every missing parent directory. Entry ids are positions, parents first.
pub fn build(
    kind: ManifestKind,
    selected: Vec<Selected>,
    limits: &Limits,
) -> Result<Manifest, TransferErrorKind> {
    if selected.is_empty() {
        return Err(TransferErrorKind::ManifestInvalid);
    }
    let mut items: Vec<Selected> = Vec::with_capacity(selected.len());
    let mut kinds: HashMap<Vec<String>, EntryKind> = HashMap::with_capacity(selected.len());
    let mut add = |s: Selected| match kinds.get(&s.path) {
        Some(k) if *k != s.kind => Err(TransferErrorKind::ManifestInvalid),
        Some(_) => Ok(()),
        None => {
            kinds.insert(s.path.clone(), s.kind);
            items.push(s);
            Ok(())
        }
    };
    for s in selected {
        if kind == ManifestKind::Folder {
            for depth in 1..s.path.len() {
                add(Selected {
                    path: s.path[..depth].to_vec(),
                    kind: EntryKind::Dir,
                    size: 0,
                    mtime: None,
                    mime: None,
                })?;
            }
        }
        add(s)?;
    }
    // Lexicographic by components: every parent sorts before its children.
    items.sort_by(|a, b| a.path.cmp(&b.path));
    let manifest = Manifest {
        kind,
        entries: items
            .into_iter()
            .enumerate()
            .map(|(i, s)| ManifestEntry {
                id: i as u32,
                kind: s.kind,
                path: s.path,
                size: if s.kind == EntryKind::File { s.size } else { 0 },
                mtime: s.mtime,
                mime: s.mime,
            })
            .collect(),
    };
    validate(&manifest, limits)?;
    Ok(manifest)
}

fn component_ok(c: &str, limits: &Limits) -> bool {
    !c.is_empty()
        && c != "."
        && c != ".."
        && c.len() <= limits.max_component_bytes
        && !c.chars().any(|ch| ch == '/' || ch == '\\' || ch.is_control())
}

/// The key two names collide under on case-insensitive or normalizing filesystems.
pub fn fold(name: &str) -> String {
    name.nfc().flat_map(char::to_lowercase).nfc().collect()
}

fn fold_path(path: &[String]) -> Vec<String> {
    path.iter().map(|c| fold(c)).collect()
}

/// Reject a malformed or hostile manifest before anything is shown or stored.
pub fn validate(m: &Manifest, limits: &Limits) -> Result<(), TransferErrorKind> {
    use TransferErrorKind::{LimitExceeded, ManifestInvalid};
    if m.entries.is_empty() {
        return Err(ManifestInvalid);
    }
    if m.entries.len() as u64 > limits.max_entries as u64 {
        return Err(LimitExceeded);
    }
    let mut paths: HashSet<&[String]> = HashSet::with_capacity(m.entries.len());
    let mut folded: HashSet<Vec<String>> = HashSet::with_capacity(m.entries.len());
    let mut files: HashSet<&[String]> = HashSet::new();
    let mut total: u64 = 0;
    let root = &m.entries[0].path.first();
    for (i, e) in m.entries.iter().enumerate() {
        if e.id as usize != i || e.path.is_empty() {
            return Err(ManifestInvalid);
        }
        if e.path.len() > limits.max_depth {
            return Err(LimitExceeded);
        }
        if !e.path.iter().all(|c| component_ok(c, limits)) {
            return Err(ManifestInvalid);
        }
        let path_bytes = e.path.iter().map(|c| c.len() + 1).sum::<usize>() - 1;
        if path_bytes > limits.max_path_bytes {
            return Err(LimitExceeded);
        }
        if e.mime.as_ref().is_some_and(|m| m.len() > 255) {
            return Err(ManifestInvalid);
        }
        match (m.kind, e.kind) {
            (ManifestKind::Files, EntryKind::Dir) => return Err(ManifestInvalid),
            (ManifestKind::Files, EntryKind::File) if e.path.len() != 1 => {
                return Err(ManifestInvalid)
            }
            (ManifestKind::Folder, _) if e.path.first() != *root => return Err(ManifestInvalid),
            _ => {}
        }
        match e.kind {
            EntryKind::Dir if e.size != 0 => return Err(ManifestInvalid),
            EntryKind::File if e.size > limits.max_file_bytes => return Err(LimitExceeded),
            _ => {}
        }
        total = total.checked_add(e.size).ok_or(LimitExceeded)?;
        if !paths.insert(&e.path) || !folded.insert(fold_path(&e.path)) {
            return Err(ManifestInvalid);
        }
        if e.kind == EntryKind::File {
            files.insert(&e.path);
        }
    }
    if total > limits.max_total_bytes {
        return Err(LimitExceeded);
    }
    // A file can't also be a directory on the way to another entry.
    for e in &m.entries {
        if (1..e.path.len()).any(|d| files.contains(&e.path[..d])) {
            return Err(ManifestInvalid);
        }
    }
    Ok(())
}

/// What consent shows: counts, size and a few top-level names, never the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferSummary {
    pub kind: ManifestKind,
    pub files: u32,
    pub dirs: u32,
    pub total_bytes: u64,
    /// Size of the largest file (admin per-file limits apply before consent).
    pub largest_file: u64,
    /// At most [`SUMMARY_NAMES`] distinct first components.
    pub top_level: Vec<String>,
    /// Further top-level names not listed.
    pub more_top_level: u32,
}

pub const SUMMARY_NAMES: usize = 5;

impl OfferSummary {
    pub fn of(m: &Manifest) -> Self {
        let mut top: Vec<&String> = Vec::new();
        let mut seen = HashSet::new();
        let (mut files, mut dirs, mut total_bytes, mut largest_file) = (0, 0, 0u64, 0u64);
        for e in &m.entries {
            match e.kind {
                EntryKind::File => files += 1,
                EntryKind::Dir => dirs += 1,
            }
            total_bytes += e.size;
            largest_file = largest_file.max(e.size);
            if seen.insert(&e.path[0]) {
                top.push(&e.path[0]);
            }
        }
        Self {
            kind: m.kind,
            files,
            dirs,
            total_bytes,
            largest_file,
            top_level: top.iter().take(SUMMARY_NAMES).map(|s| s.to_string()).collect(),
            more_top_level: top.len().saturating_sub(SUMMARY_NAMES) as u32,
        }
    }

    /// A single loose file: show one name and one size, nothing else.
    pub fn is_single_file(&self) -> bool {
        self.kind == ManifestKind::Files && self.files == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(m: &Manifest) -> Vec<String> {
        m.entries.iter().map(|e| e.path.join("/")).collect()
    }

    fn lim() -> Limits {
        Limits::default()
    }

    #[test]
    fn single_file_is_a_one_entry_manifest() {
        let m = build(ManifestKind::Files, vec![Selected::file(&["report.pdf"], 12)], &lim())
            .unwrap();
        assert_eq!(paths(&m), ["report.pdf"]);
        let s = OfferSummary::of(&m);
        assert!(s.is_single_file());
        assert_eq!((s.top_level.clone(), s.total_bytes), (vec!["report.pdf".into()], 12));
    }

    #[test]
    fn selective_folder_reconstructs_parents_only() {
        // FS-005 / FS-006: exactly the selection plus required parents.
        let sel = vec![
            Selected::file(&["Project", "src", "main.dart"], 3),
            Selected::file(&["Project", "src", "network", "client.dart"], 4),
            Selected::file(&["Project", "docs", "guide.pdf"], 5),
        ];
        let m = build(ManifestKind::Folder, sel, &lim()).unwrap();
        assert_eq!(
            paths(&m),
            [
                "Project",
                "Project/docs",
                "Project/docs/guide.pdf",
                "Project/src",
                "Project/src/main.dart",
                "Project/src/network",
                "Project/src/network/client.dart",
            ]
        );
        assert!(m.entries.iter().enumerate().all(|(i, e)| e.id as usize == i));
        let s = OfferSummary::of(&m);
        assert_eq!((s.files, s.dirs, s.total_bytes), (3, 4, 12));
        assert_eq!(s.top_level, ["Project"]);
    }

    #[test]
    fn empty_and_duplicate_selection() {
        // FS-008: empty is refused; FS-009: duplicates collapse; kind clash is refused.
        assert!(build(ManifestKind::Files, vec![], &lim()).is_err());
        let dup = vec![Selected::file(&["a"], 1), Selected::file(&["a"], 1)];
        assert_eq!(build(ManifestKind::Files, dup, &lim()).unwrap().entries.len(), 1);
        let clash = vec![Selected::file(&["P", "x"], 1), Selected::dir(&["P", "x"])];
        assert!(build(ManifestKind::Folder, clash, &lim()).is_err());
    }

    fn entry(id: u32, kind: EntryKind, path: &[&str], size: u64) -> ManifestEntry {
        ManifestEntry {
            id,
            kind,
            path: path.iter().map(|s| s.to_string()).collect(),
            size,
            mtime: None,
            mime: None,
        }
    }

    fn folder(entries: Vec<ManifestEntry>) -> Manifest {
        Manifest {
            kind: ManifestKind::Folder,
            entries,
        }
    }

    #[test]
    fn hostile_paths_are_rejected() {
        // SEC-FS-001..007: traversal, absolute, separators, empty, dot, NUL, control.
        for bad in [
            vec!["P", ".."],
            vec!["P", "."],
            vec!["P", ""],
            vec!["P", "a/b"],
            vec!["P", "a\\b"],
            vec!["P", "C:\\Windows"],
            vec!["P", "nul\0x"],
            vec!["P", "bell\x07"],
            vec!["/etc"],
        ] {
            let m = folder(vec![entry(0, EntryKind::File, &bad, 1)]);
            assert_eq!(validate(&m, &lim()), Err(TransferErrorKind::ManifestInvalid), "{bad:?}");
        }
    }

    #[test]
    fn duplicates_conflicts_and_roots() {
        // SEC-FS-015 / 016 and a second root in a folder manifest.
        let dup = folder(vec![
            entry(0, EntryKind::File, &["P", "a"], 1),
            entry(1, EntryKind::File, &["P", "a"], 1),
        ]);
        assert!(validate(&dup, &lim()).is_err());
        let file_as_dir = folder(vec![
            entry(0, EntryKind::File, &["P", "a"], 1),
            entry(1, EntryKind::File, &["P", "a", "b"], 1),
        ]);
        assert!(validate(&file_as_dir, &lim()).is_err());
        let two_roots = folder(vec![
            entry(0, EntryKind::File, &["P", "a"], 1),
            entry(1, EntryKind::File, &["Q", "b"], 1),
        ]);
        assert!(validate(&two_roots, &lim()).is_err());
        let bad_ids = folder(vec![entry(5, EntryKind::File, &["P", "a"], 1)]);
        assert!(validate(&bad_ids, &lim()).is_err());
        let loose_dir = Manifest {
            kind: ManifestKind::Files,
            entries: vec![entry(0, EntryKind::Dir, &["d"], 0)],
        };
        assert!(validate(&loose_dir, &lim()).is_err());
    }

    #[test]
    fn case_and_normalization_collisions_are_rejected() {
        // SEC-FS-013 / SEC-FS-014: collide on Windows/macOS even if not on Linux.
        let case = folder(vec![
            entry(0, EntryKind::File, &["P", "Readme.md"], 1),
            entry(1, EntryKind::File, &["P", "README.md"], 1),
        ]);
        assert_eq!(validate(&case, &lim()), Err(TransferErrorKind::ManifestInvalid));
        let norm = folder(vec![
            entry(0, EntryKind::File, &["P", "caf\u{e9}"], 1),
            entry(1, EntryKind::File, &["P", "cafe\u{301}"], 1),
        ]);
        assert_eq!(validate(&norm, &lim()), Err(TransferErrorKind::ManifestInvalid));
        let built = build(
            ManifestKind::Folder,
            vec![Selected::file(&["P", "src", "a"], 1), Selected::file(&["P", "SRC", "b"], 1)],
            &lim(),
        );
        assert_eq!(built, Err(TransferErrorKind::ManifestInvalid), "src/ and SRC/ collide");
    }

    #[test]
    fn limits_are_enforced() {
        // PERF-001/002/004/005, SEC-FS-008/009.
        let l = Limits {
            max_entries: 2,
            max_depth: 3,
            max_component_bytes: 8,
            max_path_bytes: 12,
            max_file_bytes: 100,
            max_total_bytes: 150,
            ..Limits::default()
        };
        let too_many = folder(
            (0..3)
                .map(|i| entry(i, EntryKind::File, &["P", &format!("{i}")], 1))
                .collect(),
        );
        assert_eq!(validate(&too_many, &l), Err(TransferErrorKind::LimitExceeded));
        let deep = folder(vec![entry(0, EntryKind::File, &["P", "a", "b", "c"], 1)]);
        assert_eq!(validate(&deep, &l), Err(TransferErrorKind::LimitExceeded));
        let long_comp = folder(vec![entry(0, EntryKind::File, &["P", "123456789"], 1)]);
        assert_eq!(validate(&long_comp, &l), Err(TransferErrorKind::ManifestInvalid));
        let long_path = folder(vec![entry(0, EntryKind::File, &["P", "12345", "1234567"], 1)]);
        assert_eq!(validate(&long_path, &l), Err(TransferErrorKind::LimitExceeded));
        let big = folder(vec![entry(0, EntryKind::File, &["P", "a"], 101)]);
        assert_eq!(validate(&big, &l), Err(TransferErrorKind::LimitExceeded));
        let total = folder(vec![
            entry(0, EntryKind::File, &["P", "a"], 100),
            entry(1, EntryKind::File, &["P", "b"], 100),
        ]);
        assert_eq!(validate(&total, &l), Err(TransferErrorKind::LimitExceeded));
    }
}
