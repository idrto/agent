//! Receiver-side mapping of names the destination platform can't hold.
//!
//! Hostile names (traversal, separators, control characters, collisions) are
//! already refused by [`crate::manifest::validate`]. What's left are names that
//! are fine elsewhere but not here, e.g. `a:b` or `CON.txt` on Windows. Those are
//! renamed deterministically (same manifest, same names, on every retry) and
//! reported, never silently dropped.

use std::collections::{HashMap, HashSet};

use idr_protocol::transfer::Manifest;

use crate::manifest::fold;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamePolicy {
    /// Apply Windows rules: `< > : " | ? *`, reserved device names, trailing dot/space.
    pub windows: bool,
}

impl NamePolicy {
    /// Rules for the platform this binary runs on.
    pub fn native() -> Self {
        Self {
            windows: cfg!(windows),
        }
    }
}

const RESERVED: &[&str] = &[
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "com¹", "com²", "com³", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7",
    "lpt8", "lpt9", "lpt¹", "lpt²", "lpt³", "conin$", "conout$",
];

/// The platform-safe form of one component.
pub fn map_component(name: &str, policy: NamePolicy) -> String {
    if !policy.windows {
        return name.to_string();
    }
    let mut out: String = name
        .chars()
        .map(|c| if "<>:\"|?*".contains(c) { '_' } else { c })
        .collect();
    // Trailing dots and spaces are stripped by Windows; keep the name distinct.
    let trimmed = out.trim_end_matches(['.', ' ']).len();
    if trimmed < out.len() {
        let tail = "_".repeat(out[trimmed..].chars().count());
        out.truncate(trimmed);
        out.push_str(&tail);
    }
    // `CON`, `con.txt`, `COM1.tar.gz` are devices whatever the extension.
    let stem_end = out.find('.').unwrap_or(out.len());
    if RESERVED.contains(&out[..stem_end].trim_end().to_lowercase().as_str()) {
        out.insert(stem_end, '_');
    }
    out
}

/// `name (n).ext` — keeps the extension so the file still opens.
pub fn numbered(name: &str, n: u32) -> String {
    match name.rfind('.') {
        Some(i) if i > 0 => format!("{} ({n}){}", &name[..i], &name[i..]),
        _ => format!("{name} ({n})"),
    }
}

/// Mapped path of every entry (same order as the manifest) and the entries
/// whose name changed. Names that need no change keep them; a mapped name that
/// collides gets ` (n)`. Order is fixed (depth, unchanged first, id), so retries
/// map identically.
pub fn map_manifest(m: &Manifest, policy: NamePolicy) -> (Vec<Vec<String>>, Vec<u32>) {
    let mut by_path: HashMap<&[String], Vec<String>> = HashMap::new();
    let mut taken: HashSet<(Vec<String>, String)> = HashSet::new();
    let mut out = vec![Vec::new(); m.entries.len()];
    let mut renamed = Vec::new();
    let mut order: Vec<&idr_protocol::transfer::ManifestEntry> = m.entries.iter().collect();
    order.sort_by_key(|e| {
        let leaf = e.path.last().unwrap();
        (e.path.len(), map_component(leaf, policy) != *leaf, e.id)
    });
    for e in order {
        let parent_orig = &e.path[..e.path.len() - 1];
        // Parents precede children in a valid manifest; implicit parents map name by name.
        let parent: Vec<String> = match by_path.get(parent_orig) {
            Some(p) => p.clone(),
            None => parent_orig.iter().map(|c| map_component(c, policy)).collect(),
        };
        let leaf = e.path.last().unwrap();
        let base = map_component(leaf, policy);
        let mut name = base.clone();
        let mut n = 2;
        while !taken.insert((parent.clone(), fold(&name))) {
            name = numbered(&base, n);
            n += 1;
        }
        if &name != leaf || parent.as_slice() != parent_orig {
            renamed.push(e.id);
        }
        let mut full = parent;
        full.push(name);
        by_path.insert(&e.path, full.clone());
        out[e.id as usize] = full;
    }
    renamed.sort_unstable();
    (out, renamed)
}

#[cfg(test)]
mod tests {
    use idr_protocol::transfer::{EntryKind, ManifestKind};

    use super::*;
    use crate::manifest::{build, Selected};
    use crate::Limits;

    const WIN: NamePolicy = NamePolicy { windows: true };
    const UNIX: NamePolicy = NamePolicy { windows: false };

    #[test]
    fn windows_incompatible_names_are_mapped() {
        // SEC-FS-011 / SEC-FS-012 / SEC-FS-010 (trailing dot/space).
        for (from, to) in [
            ("a:b.txt", "a_b.txt"),
            ("what?.md", "what_.md"),
            ("CON", "CON_"),
            ("con.txt", "con_.txt"),
            ("Com1.tar.gz", "Com1_.tar.gz"),
            ("LPT9", "LPT9_"),
            ("lpt¹", "lpt¹_"),
            ("name.", "name_"),
            ("name ..", "name___"),
            ("console.txt", "console.txt"),
            ("regular.txt", "regular.txt"),
        ] {
            assert_eq!(map_component(from, WIN), to, "{from}");
            assert_eq!(map_component(from, UNIX), from);
        }
    }

    #[test]
    fn mapping_is_deterministic_and_collision_free() {
        // SEC-FS-017 / SEC-FS-018: `a:b` and `a_b` both want `a_b`.
        let m = build(
            ManifestKind::Folder,
            vec![
                Selected::file(&["P", "a:b"], 1),
                Selected::file(&["P", "a_b"], 1),
                Selected::file(&["P", "dir:x", "f"], 1),
            ],
            &Limits::default(),
        )
        .unwrap();
        let (paths, renamed) = map_manifest(&m, WIN);
        let again = map_manifest(&m, WIN);
        assert_eq!((paths.clone(), renamed.clone()), again);
        let shown: Vec<String> = paths.iter().map(|p| p.join("/")).collect();
        assert_eq!(
            shown,
            ["P", "P/a_b (2)", "P/a_b", "P/dir_x", "P/dir_x/f"],
            "the real `a_b` keeps its name; `a:b` (sorted first) is numbered"
        );
        let ids: Vec<u32> = m
            .entries
            .iter()
            .filter(|e| e.kind == EntryKind::File && e.path.join("/").contains(':'))
            .map(|e| e.id)
            .collect();
        assert!(ids.iter().all(|id| renamed.contains(id)));
        assert_eq!(map_manifest(&m, UNIX).1, Vec::<u32>::new());
    }

    #[test]
    fn numbering_keeps_extensions() {
        assert_eq!(numbered("report.pdf", 2), "report (2).pdf");
        assert_eq!(numbered("Project", 3), "Project (3)");
        assert_eq!(numbered(".env", 2), ".env (2)");
    }
}
