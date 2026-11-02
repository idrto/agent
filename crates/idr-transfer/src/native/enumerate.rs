//! Sender-side enumeration of a selection, without following links.
//!
//! Symlinks, Windows junctions/reparse points and special files (FIFOs,
//! sockets, devices) are skipped and counted, never read, so nothing outside
//! the selection can leak in. Names that aren't valid UTF-8 are skipped too.

use std::io;
use std::path::PathBuf;

use cap_fs_ext::DirExt;
use cap_std::fs::Dir;
use idr_protocol::transfer::EntryKind;

use super::files::mtime_secs;
use crate::manifest::Selected;

#[derive(Debug, Default)]
pub struct Enumerated {
    pub selected: Vec<Selected>,
    /// Links and special files left out; report this count, don't fail.
    pub skipped: u32,
}

/// Enumerate `selections` (paths relative to `root`, as components). A file
/// selects itself; a directory selects itself and everything under it.
pub fn enumerate(root: &Dir, selections: &[Vec<String>]) -> io::Result<Enumerated> {
    let mut out = Enumerated::default();
    for sel in selections {
        let rel: PathBuf = sel.iter().collect();
        let meta = root.symlink_metadata(&rel)?;
        let ft = meta.file_type();
        if ft.is_symlink() {
            out.skipped += 1;
        } else if ft.is_file() {
            out.selected.push(Selected {
                path: sel.clone(),
                kind: EntryKind::File,
                size: meta.len(),
                mtime: mtime_secs(&meta),
                mime: None,
            });
        } else if ft.is_dir() {
            walk(&root.open_dir_nofollow(&rel)?, sel.clone(), &mut out)?;
        } else {
            out.skipped += 1;
        }
    }
    Ok(out)
}

fn walk(dir: &Dir, path: Vec<String>, out: &mut Enumerated) -> io::Result<()> {
    out.selected.push(Selected {
        path: path.clone(),
        kind: EntryKind::Dir,
        size: 0,
        mtime: None,
        mime: None,
    });
    for entry in dir.entries()? {
        let entry = entry?;
        let Ok(name) = entry.file_name().into_string() else {
            out.skipped += 1;
            continue;
        };
        let ft = entry.file_type()?;
        let mut child = path.clone();
        child.push(name.clone());
        if ft.is_symlink() {
            out.skipped += 1;
        } else if ft.is_dir() {
            walk(&dir.open_dir_nofollow(&name)?, child, out)?;
        } else if ft.is_file() {
            let meta = dir.symlink_metadata(&name)?;
            out.selected.push(Selected {
                path: child,
                kind: EntryKind::File,
                size: meta.len(),
                mtime: mtime_secs(&meta),
                mime: None,
            });
        } else {
            out.skipped += 1;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use cap_std::ambient_authority;

    use super::*;

    fn link_dir(link: &std::path::Path, target: &std::path::Path) -> bool {
        #[cfg(windows)]
        {
            std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(link)
                .arg(target)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link).is_ok()
        }
    }

    fn paths(e: &Enumerated) -> Vec<String> {
        let mut v: Vec<String> = e.selected.iter().map(|s| s.path.join("/")).collect();
        v.sort();
        v
    }

    /// FD-012 / FD-013 / SEC-FS-019 / SEC-FS-023: links are skipped and
    /// counted, their targets never listed.
    #[test]
    fn links_are_skipped_and_counted() {
        let (t, outside) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        std::fs::write(outside.path().join("secret.txt"), b"s").unwrap();
        let p = t.path().join("Project");
        std::fs::create_dir_all(p.join("src")).unwrap();
        std::fs::write(p.join("src").join("main.rs"), b"fn main(){}").unwrap();
        std::fs::write(p.join("README.md"), b"hi").unwrap();
        assert!(link_dir(&p.join("escape"), outside.path()));
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(outside.path().join("secret.txt"), p.join("s.txt")).unwrap();
            nix_fifo(&p.join("pipe"));
        }

        let root = Dir::open_ambient_dir(t.path(), ambient_authority()).unwrap();
        let e = enumerate(&root, &[vec!["Project".into()]]).unwrap();
        assert_eq!(paths(&e), ["Project", "Project/README.md", "Project/src", "Project/src/main.rs"]);
        let expected_skips = if cfg!(unix) { 3 } else { 1 };
        assert_eq!(e.skipped, expected_skips);
        assert_eq!(e.selected.iter().find(|s| s.path.last().unwrap() == "README.md").unwrap().size, 2);

        // Selecting the link itself is skipped, not followed.
        let e = enumerate(&root, &[vec!["Project".into(), "escape".into()]]).unwrap();
        assert!(e.selected.is_empty());
        assert_eq!(e.skipped, 1);
    }

    #[cfg(unix)]
    fn nix_fifo(path: &std::path::Path) {
        assert!(std::process::Command::new("mkfifo").arg(path).status().unwrap().success());
    }

    /// FS-002 / FS-004: selecting subfolders and single files.
    #[test]
    fn selections_combine() {
        let t = tempfile::tempdir().unwrap();
        for f in ["P/a/1.txt", "P/a/2.txt", "P/b/3.txt", "P/c.txt"] {
            let p = t.path().join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, f).unwrap();
        }
        let root = Dir::open_ambient_dir(t.path(), ambient_authority()).unwrap();
        let sel = |s: &str| s.split('/').map(String::from).collect::<Vec<_>>();
        let e = enumerate(&root, &[sel("P/a"), sel("P/c.txt")]).unwrap();
        assert_eq!(paths(&e), ["P/a", "P/a/1.txt", "P/a/2.txt", "P/c.txt"]);
    }
}
