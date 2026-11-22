//! One process owns this private listener. A crash leaves a safe stale socket.
use anyhow::{Context, Result, ensure};
use std::{
    fs::{File, OpenOptions},
    os::{
        fd::{AsFd, AsRawFd, OwnedFd},
        unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

pub struct Guard {
    path: PathBuf,
    device: u64,
    inode: u64,
    // Keep the bound inode alive until cleanup checks it. Inode numbers can be
    // reused after the server closes its listener and another socket replaces it.
    _listener: OwnedFd,
    _lock: File,
}
impl Drop for Guard {
    fn drop(&mut self) {
        if let Ok(meta) = std::fs::symlink_metadata(&self.path) {
            if meta.file_type().is_socket() && meta.dev() == self.device && meta.ino() == self.inode
            {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
}
pub fn bind(path: &Path) -> Result<(tokio::net::UnixListener, Guard)> {
    ensure!(
        path.is_absolute() && path.as_os_str().as_encoded_bytes().len() <= 100,
        "invalid_listen_socket_path"
    );
    let uid = unsafe { libc::geteuid() };
    let parent = path.parent().context("socket_parent_missing")?;
    let parent_meta = std::fs::symlink_metadata(parent)?;
    ensure!(
        parent_meta.is_dir()
            && !parent_meta.file_type().is_symlink()
            && parent_meta.uid() == uid
            && parent_meta.mode() & 0o077 == 0,
        "socket_parent_must_be_private_and_owned"
    );
    let lock_path = PathBuf::from(format!("{}.lock", path.display()));
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&lock_path)?;
    let meta = lock.metadata()?;
    ensure!(
        meta.is_file() && meta.uid() == uid && meta.nlink() == 1 && meta.mode() & 0o077 == 0,
        "invalid_socket_lock"
    );
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "socket_already_owned"
    );
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            ensure!(
                meta.file_type().is_socket() && meta.uid() == uid && meta.mode() & 0o077 == 0,
                "existing_socket_not_owned_private_socket"
            );
            match std::os::unix::net::UnixStream::connect(path) {
                Ok(_) => anyhow::bail!("socket_listener_active"),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                    ) => {}
                Err(e) => return Err(e.into()),
            }
            let current = std::fs::symlink_metadata(path)?;
            ensure!(
                current.dev() == meta.dev() && current.ino() == meta.ino(),
                "socket_changed_during_cleanup"
            );
            std::fs::remove_file(path)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let listener = tokio::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    let meta = std::fs::symlink_metadata(path)?;
    let pinned_listener = listener.as_fd().try_clone_to_owned()?;
    Ok((
        listener,
        Guard {
            path: path.into(),
            device: meta.dev(),
            inode: meta.ino(),
            _listener: pinned_listener,
            _lock: lock,
        },
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn stale_socket_is_recovered_but_active_listener_and_symlink_are_not() {
        let t = tempfile::tempdir().unwrap();
        std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = t.path().join("sidecar.sock");
        let stale = std::os::unix::net::UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        drop(stale);
        let (listener, guard) = bind(&path).unwrap();
        assert!(bind(&path).is_err());
        drop(listener);
        drop(guard);
        assert!(!path.exists());
        let target = t.path().join("file");
        std::fs::write(&target, "preserve").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(bind(&path).is_err());
        assert_eq!(std::fs::read_to_string(target).unwrap(), "preserve");
    }
    #[tokio::test]
    async fn cleanup_preserves_a_replaced_inode() {
        let t = tempfile::tempdir().unwrap();
        std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = t.path().join("sidecar.sock");
        let (listener, guard) = bind(&path).unwrap();
        let original = std::fs::symlink_metadata(&path).unwrap();
        drop(listener);
        std::fs::remove_file(&path).unwrap();
        let replacement = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let current = std::fs::symlink_metadata(&path).unwrap();
        assert_ne!(
            (original.dev(), original.ino()),
            (current.dev(), current.ino())
        );
        drop(guard);
        let preserved = std::fs::symlink_metadata(&path).unwrap();
        assert_eq!(
            (preserved.dev(), preserved.ino()),
            (current.dev(), current.ino())
        );
        let connection = std::os::unix::net::UnixStream::connect(&path).unwrap();
        drop(connection);
        drop(replacement);
    }
}
