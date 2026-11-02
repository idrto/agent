//! Disk space and destination checks for receive policy.

use std::path::{Path, PathBuf};

use idr_protocol::transfer::TransferErrorKind;

/// Bytes available to this user on the volume holding `path`.
pub fn free_space(path: &Path) -> Option<u64> {
    imp::free_space(path)
}

/// An accepted destination: a canonical permitted root and the path under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub root: PathBuf,
    pub rel: PathBuf,
}

impl Destination {
    pub fn path(&self) -> PathBuf {
        self.root.join(&self.rel)
    }
}

/// `dest` if it is one of `permitted` or inside one; otherwise `Unauthorized`.
/// Both are canonicalized first (symlinks, junctions and other reparse points,
/// and `..` resolved), so a link can't make an outside directory look inside.
/// Storage later opens `rel` *relative to a handle on `root`*
/// ([`super::NativeSink::open_in`]), so a component swapped for a link after
/// this check is refused rather than followed.
pub fn resolve_destination(permitted: &[PathBuf], dest: &Path) -> Result<Destination, TransferErrorKind> {
    let dest = std::fs::canonicalize(dest).map_err(|_| TransferErrorKind::Unauthorized)?;
    permitted
        .iter()
        .filter_map(|p| std::fs::canonicalize(p).ok())
        .find_map(|root| {
            let rel = dest.strip_prefix(&root).ok()?.to_path_buf();
            Some(Destination { root, rel })
        })
        .ok_or(TransferErrorKind::Unauthorized)
}

/// The canonical `dest` if permitted (see [`resolve_destination`]).
pub fn permitted_destination(permitted: &[PathBuf], dest: &Path) -> Result<PathBuf, TransferErrorKind> {
    resolve_destination(permitted, dest).map(|d| d.path())
}

#[cfg(unix)]
mod imp {
    use super::*;

    pub fn free_space(path: &Path) -> Option<u64> {
        let s = rustix::fs::statvfs(path).ok()?;
        Some(s.f_bavail.saturating_mul(s.f_frsize))
    }
}

#[cfg(windows)]
mod imp {
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

    use super::*;

    pub fn free_space(path: &Path) -> Option<u64> {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut avail = 0u64;
        // SAFETY: `wide` is NUL-terminated; out-pointers are valid or null.
        let ok = unsafe {
            GetDiskFreeSpaceExW(wide.as_ptr(), &mut avail, std::ptr::null_mut(), std::ptr::null_mut())
        };
        (ok != 0).then_some(avail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_space_is_reported() {
        let d = tempfile::tempdir().unwrap();
        assert!(free_space(d.path()).unwrap() > 0);
    }

    #[test]
    fn destinations_must_be_inside_permitted_dirs() {
        // CLI-016 / AUTH-017.
        let root = tempfile::tempdir().unwrap();
        let ok = root.path().join("inbox");
        let other = root.path().join("elsewhere");
        std::fs::create_dir_all(ok.join("sub")).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        let permitted = vec![ok.clone()];
        assert!(permitted_destination(&permitted, &ok).is_ok());
        assert!(permitted_destination(&permitted, &ok.join("sub")).is_ok());
        assert_eq!(
            permitted_destination(&permitted, &other),
            Err(TransferErrorKind::Unauthorized)
        );
        assert_eq!(
            permitted_destination(&permitted, &ok.join("sub").join("..").join("..").join("elsewhere")),
            Err(TransferErrorKind::Unauthorized)
        );
        assert!(permitted_destination(&permitted, &root.path().join("missing")).is_err());
    }
}
