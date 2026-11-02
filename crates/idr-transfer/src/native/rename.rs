//! Atomic, directory-relative rename that never replaces an existing name.
//!
//! `std::fs::rename` and `cap_std::fs::Dir::rename` overwrite, so they can't
//! finalize a transfer. Both names here are single components resolved against
//! open directory handles, so a symlink or junction swapped into a path can't
//! redirect the rename.
//!
//! | Platform | Mechanism |
//! |---|---|
//! | Linux, Android, macOS, iOS | `renameat2(RENAME_NOREPLACE)` / `renameatx_np(RENAME_EXCL)` via rustix |
//! | Windows | `SetFileInformationByHandle(FileRenameInfo)` on a no-follow handle, `ReplaceIfExists = FALSE`, target relative to the directory handle |
//! | Fallback (filesystem without NOREPLACE, other Unix) | files: `linkat` + `unlinkat` (link fails if the name exists); directories: [`RenameError::NotSupported`] |

use std::io;

use cap_std::fs::Dir;

#[derive(Debug)]
pub enum RenameError {
    /// The target name exists; nothing was changed.
    Exists,
    /// No atomic no-replace rename here (directories on a filesystem without it).
    NotSupported,
    Io(io::Error),
}

impl From<io::Error> for RenameError {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::AlreadyExists {
            Self::Exists
        } else {
            Self::Io(e)
        }
    }
}

fn single_component(name: &str) -> Result<(), RenameError> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\']) {
        return Err(RenameError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "rename takes one path component",
        )));
    }
    Ok(())
}

/// Move `from` in `from_dir` to `to` in `to_dir` (same volume). Fails with
/// [`RenameError::Exists`] instead of replacing.
pub fn rename_noreplace(from_dir: &Dir, from: &str, to_dir: &Dir, to: &str) -> Result<(), RenameError> {
    single_component(from)?;
    single_component(to)?;
    imp::rename(from_dir, from, to_dir, to)
}

#[cfg(unix)]
mod imp {
    use super::*;
    use rustix::fs::{linkat, unlinkat, AtFlags};

    pub fn rename(from_dir: &Dir, from: &str, to_dir: &Dir, to: &str) -> Result<(), RenameError> {
        #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
        {
            use rustix::fs::{renameat_with, RenameFlags};
            use rustix::io::Errno;
            match renameat_with(from_dir, from, to_dir, to, RenameFlags::NOREPLACE) {
                Ok(()) => return Ok(()),
                Err(Errno::EXIST) => return Err(RenameError::Exists),
                // Filesystem or kernel without NOREPLACE: fall through.
                Err(Errno::INVAL) | Err(Errno::NOSYS) | Err(Errno::OPNOTSUPP) => {}
                Err(e) => return Err(RenameError::Io(e.into())),
            }
        }
        if from_dir.symlink_metadata(from)?.is_dir() {
            return Err(RenameError::NotSupported);
        }
        linkat(from_dir, from, to_dir, to, AtFlags::empty()).map_err(io::Error::from)?;
        unlinkat(from_dir, from, AtFlags::empty()).map_err(io::Error::from)?;
        Ok(())
    }
}

#[cfg(windows)]
mod imp {
    use std::os::windows::io::{AsHandle, AsRawHandle};

    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt, OpenOptionsMaybeDirExt};
    use cap_std::fs::{OpenOptions, OpenOptionsExt};
    use windows_sys::Wdk::Storage::FileSystem::{
        FileRenameInformation, NtSetInformationFile, FILE_RENAME_INFORMATION,
    };
    use windows_sys::Win32::Foundation::{
        RtlNtStatusToDosError, HANDLE, STATUS_OBJECT_NAME_COLLISION,
    };
    use windows_sys::Win32::Storage::FileSystem::{DELETE, FILE_READ_ATTRIBUTES, SYNCHRONIZE};
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    use super::*;

    /// `NtSetInformationFile(FileRenameInformation)`: the Win32 wrapper
    /// (`SetFileInformationByHandle`) refuses a relative name with a root
    /// directory handle; the native call is what makes this handle-relative.
    pub fn rename(from_dir: &Dir, from: &str, to_dir: &Dir, to: &str) -> Result<(), RenameError> {
        // The handle we rename: no reparse-point following, files or directories.
        let src = from_dir.open_with(
            from,
            OpenOptions::new()
                .access_mode(DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
                .follow(FollowSymlinks::No)
                .maybe_dir(true),
        )?;
        let name: Vec<u16> = to.encode_utf16().collect();
        let size = std::mem::size_of::<FILE_RENAME_INFORMATION>() + name.len() * 2;
        // u64 backing keeps the struct's pointer-sized fields aligned.
        let mut buf = vec![0u64; size.div_ceil(8)];
        let info = buf.as_mut_ptr() as *mut FILE_RENAME_INFORMATION;
        let mut iosb: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
        // SAFETY: `buf` is zeroed, aligned and large enough for the header plus
        // `name` (FileName is a trailing flexible array). Every field is written
        // before the call; both handles and `iosb` outlive it.
        let status = unsafe {
            (*info).Anonymous.ReplaceIfExists = false;
            (*info).RootDirectory = to_dir.as_handle().as_raw_handle() as HANDLE;
            (*info).FileNameLength = (name.len() * 2) as u32;
            std::ptr::copy_nonoverlapping(
                name.as_ptr(),
                std::ptr::addr_of_mut!((*info).FileName) as *mut u16,
                name.len(),
            );
            NtSetInformationFile(
                src.as_raw_handle() as HANDLE,
                &mut iosb,
                info as *const _,
                size as u32,
                FileRenameInformation,
            )
        };
        match status {
            0 => Ok(()),
            STATUS_OBJECT_NAME_COLLISION => Err(RenameError::Exists),
            s => Err(RenameError::Io(io::Error::from_raw_os_error(
                // SAFETY: pure status-code translation.
                unsafe { RtlNtStatusToDosError(s) } as i32,
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use cap_std::ambient_authority;

    use super::*;

    fn dirs() -> (tempfile::TempDir, Dir) {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Dir::open_ambient_dir(tmp.path(), ambient_authority()).unwrap();
        (tmp, dir)
    }

    #[test]
    fn renames_files_and_dirs_across_directories() {
        let (_t, d) = dirs();
        d.create_dir("a").unwrap();
        d.create_dir("b").unwrap();
        let (a, b) = (d.open_dir("a").unwrap(), d.open_dir("b").unwrap());
        a.write("f", b"x").unwrap();
        rename_noreplace(&a, "f", &b, "g").unwrap();
        assert_eq!(b.read("g").unwrap(), b"x");
        assert!(!a.exists("f"));

        a.create_dir("sub").unwrap();
        a.write("sub/inner", b"y").unwrap();
        rename_noreplace(&a, "sub", &b, "moved").unwrap();
        assert_eq!(b.read("moved/inner").unwrap(), b"y");
    }

    #[test]
    fn never_replaces_existing_files_or_dirs() {
        // SEC-FS-028 / SEC-FS-032: existing data is preserved.
        let (_t, d) = dirs();
        d.write("new", b"new").unwrap();
        d.write("old", b"old").unwrap();
        assert!(matches!(rename_noreplace(&d, "new", &d, "old"), Err(RenameError::Exists)));
        assert_eq!(d.read("old").unwrap(), b"old");
        assert_eq!(d.read("new").unwrap(), b"new");

        d.create_dir("src").unwrap();
        d.create_dir("empty").unwrap();
        assert!(matches!(rename_noreplace(&d, "src", &d, "empty"), Err(RenameError::Exists)));
        assert!(matches!(rename_noreplace(&d, "src", &d, "old"), Err(RenameError::Exists)));
        assert!(d.is_dir("src"));
    }

    #[test]
    fn rejects_multi_component_names() {
        let (_t, d) = dirs();
        d.write("f", b"").unwrap();
        assert!(matches!(rename_noreplace(&d, "f", &d, "../escape"), Err(RenameError::Io(_))));
        assert!(matches!(rename_noreplace(&d, "f", &d, "a\\b"), Err(RenameError::Io(_))));
    }
}
