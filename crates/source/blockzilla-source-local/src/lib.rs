//! Local and pinned immutable byte sources.

use std::{
    borrow::Cow,
    collections::HashMap,
    fs::File,
    io,
    os::unix::fs::{FileExt, MetadataExt},
    path::{Path, PathBuf},
    sync::{
        Arc, OnceLock, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

use rustix::fs::{Mode, OFlags};
use serde::Serialize;

use blockzilla_source::{RangeSource, SourceError, SourceResult, validate_object_name};

#[derive(Debug, Clone)]
pub struct LocalRangeSource {
    root: PathBuf,
}

impl LocalRangeSource {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path(&self, object: &str) -> SourceResult<PathBuf> {
        validate_object_name(object).map_err(|_| SourceError::InvalidName(object.to_owned()))?;
        Ok(self.root.join(object))
    }
}

impl RangeSource for LocalRangeSource {
    fn size(&self, object: &str) -> SourceResult<Option<u64>> {
        let path = self.path(object)?;
        match std::fs::metadata(&path) {
            Ok(metadata) => {
                if !metadata.is_file() {
                    return Err(SourceError::Protocol(format!(
                        "{} is not a regular file",
                        path.display()
                    )));
                }
                Ok(Some(metadata.len()))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(SourceError::Io {
                object: object.to_owned(),
                source,
            }),
        }
    }

    fn read_range(&self, object: &str, offset: u64, length: usize) -> SourceResult<Vec<u8>> {
        let mut bytes = Vec::new();
        self.read_range_into(object, offset, length, &mut bytes)?;
        Ok(bytes)
    }

    fn read_range_into(
        &self,
        object: &str,
        offset: u64,
        length: usize,
        bytes: &mut Vec<u8>,
    ) -> SourceResult<()> {
        // Preserve initialized storage across sequential range reads. Clearing
        // before resizing would zero the entire reused batch even though the
        // following `read_at` loop overwrites every requested byte.
        if bytes.len() < length {
            bytes.resize(length, 0);
        } else {
            bytes.truncate(length);
        }
        self.read_range_into_slice(object, offset, bytes)
    }

    fn read_range_into_slice(
        &self,
        object: &str,
        offset: u64,
        bytes: &mut [u8],
    ) -> SourceResult<()> {
        let path = self.path(object)?;
        let file = File::open(&path).map_err(|source| {
            if source.kind() == io::ErrorKind::NotFound {
                SourceError::NotFound(object.to_owned())
            } else {
                SourceError::Io {
                    object: object.to_owned(),
                    source,
                }
            }
        })?;
        let size = file
            .metadata()
            .map_err(|source| SourceError::Io {
                object: object.to_owned(),
                source,
            })?
            .len();
        let length = bytes.len();
        let length_u64 = u64::try_from(length).map_err(|_| SourceError::OutOfBounds {
            object: object.to_owned(),
            offset,
            length,
            size,
        })?;
        let end = offset
            .checked_add(length_u64)
            .ok_or_else(|| SourceError::OutOfBounds {
                object: object.to_owned(),
                offset,
                length,
                size,
            })?;
        if end > size {
            return Err(SourceError::OutOfBounds {
                object: object.to_owned(),
                offset,
                length,
                size,
            });
        }

        let mut read = 0usize;
        while read < length {
            let read_offset = offset + read as u64;
            let count = file
                .read_at(&mut bytes[read..], read_offset)
                .map_err(|source| SourceError::Io {
                    object: object.to_owned(),
                    source,
                })?;
            if count == 0 {
                return Err(SourceError::ShortRead {
                    object: object.to_owned(),
                    expected: length,
                    actual: read,
                });
            }
            read += count;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UnixFileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

/// Stable local-file identity captured when an anchored source opens an object.
///
/// This is metadata, not a content hash. A durable consumer can store these
/// values and refuse resume after a pathname is replaced, even when the new
/// file has the same length.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PinnedLocalObjectIdentity {
    pub object: String,
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub modified_seconds: i64,
    pub modified_nanoseconds: i64,
    pub changed_seconds: i64,
    pub changed_nanoseconds: i64,
}

impl UnixFileIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

#[derive(Debug, Clone)]
struct PinnedFile {
    file: Arc<File>,
    identity: UnixFileIdentity,
}

/// Successful local range reads performed through a pinned source.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PinnedLocalRangeSourceStats {
    pub read_calls: u64,
    pub read_bytes: u64,
}

#[derive(Debug, Default)]
struct PinnedLocalRangeSourceCounters {
    read_calls: AtomicU64,
    read_bytes: AtomicU64,
}

/// Objects pinned by one source. All clones of the source share them.
#[derive(Debug, Clone)]
enum PinnedFiles {
    /// Path-rooted source: any valid object name can enter the map. A lookup
    /// takes the shared read lock. Only a first open takes the write lock.
    Open(Arc<RwLock<HashMap<String, Option<PinnedFile>>>>),
    /// Anchored source: the allowlist sets the keys and the map does not
    /// change after construction. Each slot is written one time, so a lookup
    /// takes no lock.
    Anchored(Arc<HashMap<String, OnceLock<Option<PinnedFile>>>>),
}

fn file_cache_poisoned() -> SourceError {
    SourceError::Protocol("pinned local source file cache is poisoned".to_owned())
}

/// Random-access source that pins every opened object to one file descriptor.
///
/// This is intended for long-running local archive scans. The first lookup of
/// an object opens it and captures its Unix identity; later size and range
/// reads use that same handle even if the pathname is replaced. Missing
/// objects are cached as missing because a published generation is immutable.
///
/// Clones can read from many threads at the same time. Each range read is a
/// positional read (`pread`) on the pinned descriptor. No lock is held during
/// the read, so concurrent reads run in parallel.
/// [`Self::with_read_concurrency`] tells readers how many concurrent reads
/// are useful. The default is 1.
#[derive(Debug, Clone)]
pub struct PinnedLocalRangeSource {
    root: PathBuf,
    root_directory: Option<Arc<File>>,
    files: PinnedFiles,
    counters: Arc<PinnedLocalRangeSourceCounters>,
    read_concurrency: usize,
}

impl PinnedLocalRangeSource {
    /// Largest hint that [`Self::with_read_concurrency`] keeps.
    pub const MAX_READ_CONCURRENCY: usize = 64;

    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            root_directory: None,
            files: PinnedFiles::Open(Arc::new(RwLock::new(HashMap::new()))),
            counters: Arc::new(PinnedLocalRangeSourceCounters::default()),
            read_concurrency: 1,
        }
    }

    /// Open and pin the source directory before any object lookup.
    ///
    /// Every later object open is relative to this descriptor. Replacing the
    /// pathname cannot make one source instance mix objects from two directory
    /// generations.
    pub fn new_anchored(root: impl Into<PathBuf>, allowed_objects: &[&str]) -> SourceResult<Self> {
        const MAX_ALLOWED_OBJECTS: usize = 64;
        if allowed_objects.is_empty() || allowed_objects.len() > MAX_ALLOWED_OBJECTS {
            return Err(SourceError::Protocol(format!(
                "anchored local source allowlist must contain 1..={MAX_ALLOWED_OBJECTS} objects"
            )));
        }
        let mut slots = HashMap::with_capacity(allowed_objects.len());
        for object in allowed_objects {
            validate_object_name(object)
                .map_err(|_| SourceError::InvalidName((*object).to_owned()))?;
            if slots
                .insert((*object).to_owned(), OnceLock::new())
                .is_some()
            {
                return Err(SourceError::Protocol(format!(
                    "anchored local source allowlist contains duplicate object {object}"
                )));
            }
        }
        let root = root.into();
        let directory = rustix::fs::open(
            &root,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| SourceError::Io {
            object: root.display().to_string(),
            source: io::Error::from(error),
        })?;
        let metadata = directory.metadata().map_err(|source| SourceError::Io {
            object: root.display().to_string(),
            source,
        })?;
        if !metadata.is_dir() {
            return Err(SourceError::Protocol(format!(
                "{} is not a directory",
                root.display()
            )));
        }
        Ok(Self {
            root,
            root_directory: Some(Arc::new(directory)),
            files: PinnedFiles::Anchored(Arc::new(slots)),
            counters: Arc::new(PinnedLocalRangeSourceCounters::default()),
            read_concurrency: 1,
        })
    }

    /// Set the hint that [`RangeSource::recommended_read_concurrency`]
    /// returns. The default is 1: a reader keeps one serial input reader.
    ///
    /// This method clamps the value into `1..=`[`Self::MAX_READ_CONCURRENCY`].
    /// 0 becomes 1. A value above the maximum becomes the maximum. The hint
    /// does not start threads or reserve memory. Each reader applies its own
    /// worker and buffer limits.
    ///
    /// All hint values are safe. Concurrent reads return the same bytes as
    /// serial reads. Clones of the returned source keep the hint. They share
    /// the pinned files and the read counters with this source.
    #[must_use]
    pub fn with_read_concurrency(mut self, readers: usize) -> Self {
        self.read_concurrency = readers.clamp(1, Self::MAX_READ_CONCURRENCY);
        self
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Return successful range-read counters shared by all source clones.
    pub fn stats(&self) -> PinnedLocalRangeSourceStats {
        PinnedLocalRangeSourceStats {
            read_calls: self.counters.read_calls.load(Ordering::Relaxed),
            read_bytes: self.counters.read_bytes.load(Ordering::Relaxed),
        }
    }

    /// Clone the pinned source-directory descriptor, when this source was
    /// created with [`Self::new_anchored`].
    pub fn pinned_root_file_clone(&self) -> SourceResult<Option<File>> {
        self.root_directory
            .as_ref()
            .map(|directory| {
                directory.try_clone().map_err(|source| SourceError::Io {
                    object: self.root.display().to_string(),
                    source,
                })
            })
            .transpose()
    }

    /// Clone the descriptor pinned for one immutable object.
    ///
    /// The returned handle refers to the same inode that range reads and
    /// manifest verification use. A caller can therefore use APIs that accept
    /// `File` without reopening a pathname and creating a replacement race.
    pub fn pinned_file_clone(&self, object: &str) -> SourceResult<Option<File>> {
        self.pinned_file(object)?
            .map(|pinned| {
                pinned.file.try_clone().map_err(|source| SourceError::Io {
                    object: object.to_owned(),
                    source,
                })
            })
            .transpose()
    }

    /// Return the sorted identities of every present object admitted so far.
    pub fn pinned_object_identities(&self) -> SourceResult<Vec<PinnedLocalObjectIdentity>> {
        let mut identities = self
            .present_files()?
            .into_iter()
            .map(|(object, file)| {
                let identity = file.identity;
                PinnedLocalObjectIdentity {
                    object,
                    device: identity.device,
                    inode: identity.inode,
                    size: identity.size,
                    modified_seconds: identity.modified_seconds,
                    modified_nanoseconds: identity.modified_nanoseconds,
                    changed_seconds: identity.changed_seconds,
                    changed_nanoseconds: identity.changed_nanoseconds,
                }
            })
            .collect::<Vec<_>>();
        identities.sort_unstable_by(|left, right| left.object.cmp(&right.object));
        Ok(identities)
    }

    /// Copy every present object pinned so far. The order is not defined.
    fn present_files(&self) -> SourceResult<Vec<(String, PinnedFile)>> {
        Ok(match &self.files {
            PinnedFiles::Open(files) => files
                .read()
                .map_err(|_| file_cache_poisoned())?
                .iter()
                .filter_map(|(object, file)| Some((object.clone(), file.clone()?)))
                .collect(),
            PinnedFiles::Anchored(slots) => slots
                .iter()
                .filter_map(|(object, slot)| Some((object.clone(), slot.get()?.clone()?)))
                .collect(),
        })
    }

    fn pinned_file(&self, object: &str) -> SourceResult<Option<Cow<'_, PinnedFile>>> {
        self.pinned_file_with(object, |path| {
            let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
            let descriptor = match &self.root_directory {
                Some(directory) => {
                    rustix::fs::openat(directory.as_ref(), object, flags, Mode::empty())
                }
                None => rustix::fs::open(path, flags, Mode::empty()),
            };
            descriptor.map(File::from).map_err(io::Error::from)
        })
    }

    /// Return the pinned handle of `object`. On the first lookup, open the
    /// object with `open` and pin it.
    ///
    /// An anchored source checks its allowlist first. A path-rooted source
    /// checks the name first. A cache hit does not allocate. On an anchored
    /// source, a cache hit also takes no lock.
    fn pinned_file_with(
        &self,
        object: &str,
        open: impl FnOnce(&Path) -> io::Result<File>,
    ) -> SourceResult<Option<Cow<'_, PinnedFile>>> {
        match &self.files {
            PinnedFiles::Anchored(slots) => {
                let slot = slots.get(object).ok_or_else(|| {
                    SourceError::Protocol(format!(
                        "object {object} is outside the anchored local source allowlist"
                    ))
                })?;
                let file = match slot.get() {
                    Some(file) => file,
                    None => {
                        // The open is outside the slot, so a slow open does
                        // not block other callers. If another caller fills
                        // the slot first, `get_or_init` drops this result and
                        // returns the stored one.
                        let opened = self.open_pinned(object, open)?;
                        slot.get_or_init(|| opened)
                    }
                };
                Ok(file.as_ref().map(Cow::Borrowed))
            }
            PinnedFiles::Open(files) => {
                validate_object_name(object)
                    .map_err(|_| SourceError::InvalidName(object.to_owned()))?;
                {
                    let files = files.read().map_err(|_| file_cache_poisoned())?;
                    if let Some(file) = files.get(object) {
                        return Ok(file.clone().map(Cow::Owned));
                    }
                }
                // Opening a local/NAS object can involve filesystem I/O, so
                // never hold the source-wide cache lock across it. Whichever
                // first-open result enters the cache first becomes the one
                // pinned identity returned to every caller.
                let opened = self.open_pinned(object, open)?;
                let mut files = files.write().map_err(|_| file_cache_poisoned())?;
                Ok(files
                    .entry(object.to_owned())
                    .or_insert(opened)
                    .clone()
                    .map(Cow::Owned))
            }
        }
    }

    /// Open one object. The caller holds no lock. `None` means that the object
    /// does not exist.
    fn open_pinned(
        &self,
        object: &str,
        open: impl FnOnce(&Path) -> io::Result<File>,
    ) -> SourceResult<Option<PinnedFile>> {
        let path = self.root.join(object);
        let file = match open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(SourceError::Io {
                    object: object.to_owned(),
                    source,
                });
            }
        };
        let metadata = file.metadata().map_err(|source| SourceError::Io {
            object: object.to_owned(),
            source,
        })?;
        if !metadata.is_file() {
            return Err(SourceError::Protocol(format!(
                "{} is not a regular file",
                path.display()
            )));
        }
        Ok(Some(PinnedFile {
            file: Arc::new(file),
            identity: UnixFileIdentity::from_metadata(&metadata),
        }))
    }

    /// Verify that every object opened so far still has its captured file
    /// identity, size, and modification/change timestamps.
    pub fn verify_unchanged(&self) -> SourceResult<()> {
        for (object, file) in self.present_files()? {
            let metadata = file.file.metadata().map_err(|source| SourceError::Io {
                object: object.clone(),
                source,
            })?;
            if !metadata.is_file() || UnixFileIdentity::from_metadata(&metadata) != file.identity {
                return Err(SourceError::Protocol(format!(
                    "object {object} changed after it was opened"
                )));
            }
        }
        Ok(())
    }
}

impl RangeSource for PinnedLocalRangeSource {
    /// Return the hint from [`PinnedLocalRangeSource::with_read_concurrency`].
    /// The default is 1.
    fn recommended_read_concurrency(&self) -> usize {
        self.read_concurrency
    }

    fn prefers_small_ranges(&self) -> bool {
        true
    }

    fn size(&self, object: &str) -> SourceResult<Option<u64>> {
        Ok(self.pinned_file(object)?.map(|file| file.identity.size))
    }

    fn read_range(&self, object: &str, offset: u64, length: usize) -> SourceResult<Vec<u8>> {
        let mut bytes = Vec::new();
        self.read_range_into(object, offset, length, &mut bytes)?;
        Ok(bytes)
    }

    fn read_range_into(
        &self,
        object: &str,
        offset: u64,
        length: usize,
        bytes: &mut Vec<u8>,
    ) -> SourceResult<()> {
        if bytes.len() < length {
            bytes.resize(length, 0);
        } else {
            bytes.truncate(length);
        }
        self.read_range_into_slice(object, offset, bytes)
    }

    fn read_range_into_slice(
        &self,
        object: &str,
        offset: u64,
        bytes: &mut [u8],
    ) -> SourceResult<()> {
        let pinned = self
            .pinned_file(object)?
            .ok_or_else(|| SourceError::NotFound(object.to_owned()))?;
        let size = pinned.identity.size;
        let length = bytes.len();
        let length_u64 = u64::try_from(length).map_err(|_| SourceError::OutOfBounds {
            object: object.to_owned(),
            offset,
            length,
            size,
        })?;
        let end = offset
            .checked_add(length_u64)
            .ok_or_else(|| SourceError::OutOfBounds {
                object: object.to_owned(),
                offset,
                length,
                size,
            })?;
        if end > size {
            return Err(SourceError::OutOfBounds {
                object: object.to_owned(),
                offset,
                length,
                size,
            });
        }

        // `read_at` is pread(2). It uses its own offset and does not change
        // the shared file offset. No lock is held here, so concurrent reads
        // of one descriptor run in parallel.
        let mut read = 0usize;
        while read < length {
            let read_offset = offset + read as u64;
            let count = pinned
                .file
                .read_at(&mut bytes[read..], read_offset)
                .map_err(|source| SourceError::Io {
                    object: object.to_owned(),
                    source,
                })?;
            if count == 0 {
                return Err(SourceError::ShortRead {
                    object: object.to_owned(),
                    expected: length,
                    actual: read,
                });
            }
            read += count;
        }
        self.counters.read_calls.fetch_add(1, Ordering::Relaxed);
        self.counters
            .read_bytes
            .fetch_add(length as u64, Ordering::Relaxed);
        Ok(())
    }
}

/// Route objects found in `primary` there, and all other objects to `fallback`.
///
/// The intended Mac setup uses a local cache as `primary` for manifest,
/// registry, index and metadata, with the gateway HTTP source as `fallback`
/// for blocks and signatures.
///
/// The read concurrency hint is the larger hint of the two sources. Thus this
/// setup keeps the concurrent input window of the HTTP fallback.
#[derive(Debug, Clone)]
pub struct OverlayRangeSource<P, F> {
    primary: P,
    fallback: F,
}

impl<P, F> OverlayRangeSource<P, F> {
    pub fn new(primary: P, fallback: F) -> Self {
        Self { primary, fallback }
    }

    pub fn primary(&self) -> &P {
        &self.primary
    }

    pub fn fallback(&self) -> &F {
        &self.fallback
    }
}

impl<P: RangeSource, F: RangeSource> RangeSource for OverlayRangeSource<P, F> {
    /// Return the larger hint of `primary` and `fallback`. A reader applies
    /// one hint to all objects. Concurrent reads are safe on both sources
    /// because `RangeSource` requires `Sync`.
    fn recommended_read_concurrency(&self) -> usize {
        self.primary
            .recommended_read_concurrency()
            .max(self.fallback.recommended_read_concurrency())
            .max(1)
    }

    fn size(&self, object: &str) -> SourceResult<Option<u64>> {
        match self.primary.size(object)? {
            Some(size) => Ok(Some(size)),
            None => self.fallback.size(object),
        }
    }

    fn read_range(&self, object: &str, offset: u64, length: usize) -> SourceResult<Vec<u8>> {
        if self.primary.size(object)?.is_some() {
            self.primary.read_range(object, offset, length)
        } else {
            self.fallback.read_range(object, offset, length)
        }
    }

    fn read_range_into(
        &self,
        object: &str,
        offset: u64,
        length: usize,
        destination: &mut Vec<u8>,
    ) -> SourceResult<()> {
        if self.primary.size(object)?.is_some() {
            self.primary
                .read_range_into(object, offset, length, destination)
        } else {
            self.fallback
                .read_range_into(object, offset, length, destination)
        }
    }

    fn read_range_into_slice(
        &self,
        object: &str,
        offset: u64,
        destination: &mut [u8],
    ) -> SourceResult<()> {
        if self.primary.size(object)?.is_some() {
            self.primary
                .read_range_into_slice(object, offset, destination)
        } else {
            self.fallback
                .read_range_into_slice(object, offset, destination)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, thread, time::Duration};

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn local_source_reads_exact_ranges_and_rejects_traversal() {
        let directory = tempdir().unwrap();
        fs::write(directory.path().join("object.bin"), b"0123456789").unwrap();
        let source = LocalRangeSource::new(directory.path());
        assert_eq!(source.size("object.bin").unwrap(), Some(10));
        assert_eq!(source.read_range("object.bin", 3, 4).unwrap(), b"3456");
        let mut reusable = Vec::with_capacity(16);
        source
            .read_range_into("object.bin", 1, 6, &mut reusable)
            .unwrap();
        let allocation = reusable.as_ptr();
        assert_eq!(reusable, b"123456");
        source
            .read_range_into("object.bin", 7, 3, &mut reusable)
            .unwrap();
        assert_eq!(reusable.as_ptr(), allocation);
        assert_eq!(reusable, b"789");
        let mut direct = [0_u8; 4];
        source
            .read_range_into_slice("object.bin", 2, &mut direct)
            .unwrap();
        assert_eq!(&direct, b"2345");
        assert!(source.read_range("../object.bin", 0, 1).is_err());
        assert!(source.read_range("object.bin", 9, 2).is_err());
    }

    #[test]
    fn pinned_source_keeps_reading_open_file_after_path_replacement() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("object.bin");
        fs::write(&path, b"original").unwrap();
        let source = PinnedLocalRangeSource::new(directory.path());

        assert_eq!(source.read_range("object.bin", 0, 8).unwrap(), b"original");
        fs::rename(&path, directory.path().join("original.bin")).unwrap();
        fs::write(&path, b"replacement").unwrap();

        assert_eq!(source.size("object.bin").unwrap(), Some(8));
        assert_eq!(source.read_range("object.bin", 0, 8).unwrap(), b"original");
        assert_eq!(
            source.stats(),
            PinnedLocalRangeSourceStats {
                read_calls: 2,
                read_bytes: 16,
            }
        );
    }

    #[test]
    fn anchored_source_keeps_one_directory_generation_and_enforces_allowlist() {
        let parent = tempdir().unwrap();
        let active = parent.path().join("active");
        let replacement = parent.path().join("replacement");
        let held = parent.path().join("held");
        fs::create_dir(&active).unwrap();
        fs::create_dir(&replacement).unwrap();
        fs::write(active.join("object.bin"), b"original").unwrap();
        fs::write(replacement.join("object.bin"), b"different").unwrap();
        fs::write(replacement.join("outside.bin"), b"outside").unwrap();
        let source = PinnedLocalRangeSource::new_anchored(&active, &["object.bin"]).unwrap();

        fs::rename(&active, &held).unwrap();
        fs::rename(&replacement, &active).unwrap();
        assert_eq!(source.read_range("object.bin", 0, 8).unwrap(), b"original");
        assert!(
            source
                .read_range("outside.bin", 0, 7)
                .unwrap_err()
                .to_string()
                .contains("outside the anchored local source allowlist")
        );

        let names = (0..65)
            .map(|index| format!("{index}.bin"))
            .collect::<Vec<_>>();
        let names = names.iter().map(String::as_str).collect::<Vec<_>>();
        assert!(PinnedLocalRangeSource::new_anchored(&held, &names).is_err());
    }

    #[test]
    fn pinned_source_detects_same_length_in_place_mutation() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("object.bin");
        fs::write(&path, b"before").unwrap();
        let source = PinnedLocalRangeSource::new(directory.path());

        assert_eq!(source.read_range("object.bin", 0, 6).unwrap(), b"before");
        thread::sleep(Duration::from_millis(2));
        fs::write(&path, b"after!").unwrap();

        assert!(source.verify_unchanged().is_err());
    }

    #[test]
    fn pinned_source_rejects_fifo_without_blocking() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("object.bin");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        let source = PinnedLocalRangeSource::new(directory.path());
        let (sender, receiver) = std::sync::mpsc::channel();
        let reader = thread::spawn(move || {
            sender.send(source.size("object.bin")).unwrap();
        });
        let error = receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("opening a FIFO blocked before the regular-file check")
            .unwrap_err();
        assert!(
            error.to_string().contains("not a regular file"),
            "unexpected FIFO error: {error}"
        );
        reader.join().unwrap();
    }

    #[test]
    fn pinned_source_does_not_hold_cache_lock_while_opening_and_converges_first_open_racers() {
        let directory = tempdir().unwrap();
        fs::write(directory.path().join("ready.bin"), b"ready").unwrap();
        fs::write(directory.path().join("slow.bin"), b"slow").unwrap();
        fs::write(directory.path().join("raced.bin"), b"raced").unwrap();
        let source = PinnedLocalRangeSource::new(directory.path());
        assert_eq!(source.size("ready.bin").unwrap(), Some(5));

        let (open_started_sender, open_started_receiver) = std::sync::mpsc::channel();
        let (release_open_sender, release_open_receiver) = std::sync::mpsc::channel();
        let slow_source = source.clone();
        let slow_open = thread::spawn(move || {
            slow_source
                .pinned_file_with("slow.bin", |path| {
                    open_started_sender.send(()).unwrap();
                    release_open_receiver.recv().unwrap();
                    File::open(path)
                })
                .unwrap()
                .map(Cow::into_owned)
        });
        open_started_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();

        let cached_source = source.clone();
        let (cached_sender, cached_receiver) = std::sync::mpsc::channel();
        let cached_read = thread::spawn(move || {
            cached_sender.send(cached_source.size("ready.bin")).unwrap();
        });
        assert_eq!(
            cached_receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("a slow filesystem open held the source-wide cache mutex")
                .unwrap(),
            Some(5)
        );
        cached_read.join().unwrap();
        release_open_sender.send(()).unwrap();
        assert!(slow_open.join().unwrap().is_some());

        let source = std::sync::Arc::new(source);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
        let handles = (0..16)
            .map(|_| {
                let source = source.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    source
                        .pinned_file("raced.bin")
                        .unwrap()
                        .unwrap()
                        .into_owned()
                        .file
                })
            })
            .collect::<Vec<_>>();
        let files = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert!(
            files
                .iter()
                .all(|file| std::sync::Arc::ptr_eq(file, &files[0])),
            "concurrent first-open callers did not converge on one cached handle"
        );
    }

    mod allocation_counter {
        use std::{
            alloc::{GlobalAlloc, Layout, System},
            cell::Cell,
        };

        pub struct CountingAllocator;

        thread_local! {
            static TRACKING: Cell<bool> = const { Cell::new(false) };
            static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
        }

        fn record_allocation() {
            TRACKING.with(|tracking| {
                if tracking.get() {
                    ALLOCATIONS.with(|count| count.set(count.get().saturating_add(1)));
                }
            });
        }

        // SAFETY: Every operation delegates to the system allocator with the
        // same pointer and layout contract. The counter is diagnostic only.
        unsafe impl GlobalAlloc for CountingAllocator {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                record_allocation();
                unsafe { System.alloc(layout) }
            }

            unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
                record_allocation();
                unsafe { System.alloc_zeroed(layout) }
            }

            unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
                unsafe { System.dealloc(pointer, layout) }
            }

            unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
                record_allocation();
                unsafe { System.realloc(pointer, layout, new_size) }
            }
        }

        #[global_allocator]
        static TEST_ALLOCATOR: CountingAllocator = CountingAllocator;

        /// Run `operation` and count the heap allocations of this thread.
        pub fn count_current_thread_allocations<T>(operation: impl FnOnce() -> T) -> (T, usize) {
            TRACKING.with(|tracking| assert!(!tracking.replace(true)));
            ALLOCATIONS.with(|count| count.set(0));
            let value = operation();
            let allocations = ALLOCATIONS.with(Cell::get);
            TRACKING.with(|tracking| tracking.set(false));
            (value, allocations)
        }
    }

    #[test]
    fn pinned_source_cached_lookups_and_reads_do_not_allocate() {
        let directory = tempdir().unwrap();
        fs::write(directory.path().join("object.bin"), b"0123456789").unwrap();
        let sources = [
            PinnedLocalRangeSource::new(directory.path()),
            PinnedLocalRangeSource::new_anchored(directory.path(), &["object.bin"]).unwrap(),
        ];
        for source in &sources {
            let mut destination = [0_u8; 4];
            // The first lookup opens and pins the object. It can allocate.
            source
                .read_range_into_slice("object.bin", 0, &mut destination)
                .unwrap();
            let mut reusable = Vec::with_capacity(8);
            let ((), allocations) = allocation_counter::count_current_thread_allocations(|| {
                for offset in 0..=6 {
                    source
                        .read_range_into_slice("object.bin", offset, &mut destination)
                        .unwrap();
                    source
                        .read_range_into("object.bin", offset, 4, &mut reusable)
                        .unwrap();
                    assert_eq!(source.size("object.bin").unwrap(), Some(10));
                }
            });
            assert_eq!(allocations, 0, "a cached pinned lookup or read allocated");
            assert_eq!(&destination, b"6789");
            assert_eq!(reusable, b"6789");
        }
    }

    /// SplitMix64 bytes. The stream has no short period, so a read from a
    /// wrong offset cannot return the expected bytes.
    fn test_bytes(length: usize, seed: u64) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(length + 8);
        let mut word = 0_u64;
        while bytes.len() < length {
            bytes.extend_from_slice(&split_mix_64(seed ^ word).to_le_bytes());
            word += 1;
        }
        bytes.truncate(length);
        bytes
    }

    fn split_mix_64(value: u64) -> u64 {
        let mut z = value.wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    struct FixedHintSource(usize);

    impl RangeSource for FixedHintSource {
        fn recommended_read_concurrency(&self) -> usize {
            self.0
        }

        fn size(&self, _object: &str) -> SourceResult<Option<u64>> {
            Ok(None)
        }

        fn read_range(&self, object: &str, _offset: u64, _length: usize) -> SourceResult<Vec<u8>> {
            Err(SourceError::NotFound(object.to_owned()))
        }
    }

    #[test]
    fn pinned_source_read_concurrency_hint_defaults_to_one_and_clamps() {
        let directory = tempdir().unwrap();
        fs::write(directory.path().join("object.bin"), b"0123456789").unwrap();
        let open = PinnedLocalRangeSource::new(directory.path());
        let anchored =
            PinnedLocalRangeSource::new_anchored(directory.path(), &["object.bin"]).unwrap();
        assert_eq!(open.recommended_read_concurrency(), 1);
        assert_eq!(anchored.recommended_read_concurrency(), 1);
        assert_eq!(PinnedLocalRangeSource::MAX_READ_CONCURRENCY, 64);

        for (requested, expected) in [
            (0, 1),
            (1, 1),
            (6, 6),
            (63, 63),
            (64, 64),
            (65, 64),
            (usize::MAX, 64),
        ] {
            for source in [&open, &anchored] {
                let configured = source.clone().with_read_concurrency(requested);
                assert_eq!(configured.recommended_read_concurrency(), expected);
                assert_eq!(configured.clone().recommended_read_concurrency(), expected);
                assert_eq!(
                    Arc::new(configured).recommended_read_concurrency(),
                    expected
                );
            }
        }

        // The builder changes only the hint. The new source shares the
        // pinned files and the counters, and the old source keeps its hint.
        let concurrent = open.clone().with_read_concurrency(6);
        assert_eq!(concurrent.read_range("object.bin", 2, 3).unwrap(), b"234");
        assert_eq!(
            open.stats(),
            PinnedLocalRangeSourceStats {
                read_calls: 1,
                read_bytes: 3,
            }
        );
        assert_eq!(open.pinned_object_identities().unwrap().len(), 1);
        assert_eq!(open.recommended_read_concurrency(), 1);
    }

    #[test]
    fn overlay_source_reports_the_larger_read_concurrency_hint() {
        for (primary, fallback, expected) in [(1, 1, 1), (1, 8, 8), (6, 1, 6), (6, 8, 8)] {
            let overlay =
                OverlayRangeSource::new(FixedHintSource(primary), FixedHintSource(fallback));
            assert_eq!(overlay.recommended_read_concurrency(), expected);
        }

        let primary = tempdir().unwrap();
        let fallback = tempdir().unwrap();
        fs::write(primary.path().join("index.bin"), b"index").unwrap();
        fs::write(fallback.path().join("blocks.bin"), b"blocks").unwrap();
        // A serial local cache in front of a concurrent source keeps the
        // concurrent hint. Routing does not change.
        let overlay = OverlayRangeSource::new(
            LocalRangeSource::new(primary.path()),
            PinnedLocalRangeSource::new(fallback.path()).with_read_concurrency(6),
        );
        assert_eq!(overlay.recommended_read_concurrency(), 6);
        assert_eq!(overlay.read_range("index.bin", 1, 3).unwrap(), b"nde");
        assert_eq!(overlay.read_range("blocks.bin", 0, 6).unwrap(), b"blocks");
        assert_eq!(
            OverlayRangeSource::new(overlay, FixedHintSource(8)).recommended_read_concurrency(),
            8
        );
    }

    #[test]
    fn pinned_sources_return_exact_bytes_to_concurrent_readers() {
        const SIZE: usize = 1 << 20;
        const THREADS: usize = 8;
        const READS_PER_THREAD: usize = 48;
        let directory = tempdir().unwrap();
        let content = test_bytes(SIZE, 0x0B10_C2D1_11A0);
        fs::write(directory.path().join("object.bin"), &content).unwrap();
        let sources = [
            PinnedLocalRangeSource::new(directory.path()).with_read_concurrency(THREADS),
            PinnedLocalRangeSource::new_anchored(directory.path(), &["object.bin"])
                .unwrap()
                .with_read_concurrency(THREADS),
        ];

        for source in &sources {
            let barrier = std::sync::Barrier::new(THREADS);
            let totals = thread::scope(|scope| {
                let handles = (0..THREADS)
                    .map(|thread_index| {
                        let (source, content, barrier) = (source, &content, &barrier);
                        scope.spawn(move || {
                            let mut reusable = Vec::new();
                            let mut slice = vec![0_u8; SIZE];
                            let mut read_bytes = 0_u64;
                            barrier.wait();
                            for read_index in 0..READS_PER_THREAD {
                                let (offset, length) = match read_index {
                                    0 => (0, SIZE),
                                    1 => (SIZE - 1, 1),
                                    2 => (SIZE, 0),
                                    _ => {
                                        let mix = split_mix_64(
                                            ((thread_index as u64) << 32) | read_index as u64,
                                        );
                                        let length = (mix % (256 * 1024)) as usize + 1;
                                        let offset = ((mix >> 24) as usize) % (SIZE - length + 1);
                                        (offset, length)
                                    }
                                };
                                let expected = &content[offset..offset + length];
                                let offset_u64 = offset as u64;
                                match (thread_index + read_index) % 3 {
                                    0 => assert_eq!(
                                        source
                                            .read_range("object.bin", offset_u64, length)
                                            .unwrap(),
                                        expected
                                    ),
                                    1 => {
                                        source
                                            .read_range_into(
                                                "object.bin",
                                                offset_u64,
                                                length,
                                                &mut reusable,
                                            )
                                            .unwrap();
                                        assert_eq!(reusable, expected);
                                    }
                                    _ => {
                                        let destination = &mut slice[..length];
                                        source
                                            .read_range_into_slice(
                                                "object.bin",
                                                offset_u64,
                                                destination,
                                            )
                                            .unwrap();
                                        assert_eq!(destination, expected);
                                    }
                                }
                                read_bytes += length as u64;
                            }
                            read_bytes
                        })
                    })
                    .collect::<Vec<_>>();
                handles
                    .into_iter()
                    .map(|handle| handle.join().unwrap())
                    .sum::<u64>()
            });
            assert_eq!(
                source.stats(),
                PinnedLocalRangeSourceStats {
                    read_calls: (THREADS * READS_PER_THREAD) as u64,
                    read_bytes: totals,
                }
            );
            let identities = source.pinned_object_identities().unwrap();
            assert_eq!(identities.len(), 1);
            assert_eq!(identities[0].size, SIZE as u64);
            source.verify_unchanged().unwrap();
        }
    }

    #[test]
    fn anchored_source_does_not_lock_while_opening_and_converges_first_open_racers() {
        let directory = tempdir().unwrap();
        fs::write(directory.path().join("ready.bin"), b"ready").unwrap();
        fs::write(directory.path().join("slow.bin"), b"slow").unwrap();
        fs::write(directory.path().join("raced.bin"), b"raced").unwrap();
        let source = PinnedLocalRangeSource::new_anchored(
            directory.path(),
            &["ready.bin", "slow.bin", "raced.bin"],
        )
        .unwrap()
        .with_read_concurrency(4);
        assert_eq!(source.read_range("ready.bin", 0, 5).unwrap(), b"ready");

        let (open_started_sender, open_started_receiver) = std::sync::mpsc::channel();
        let (release_open_sender, release_open_receiver) = std::sync::mpsc::channel();
        let slow_source = source.clone();
        let slow_open = thread::spawn(move || {
            slow_source
                .pinned_file_with("slow.bin", |path| {
                    open_started_sender.send(()).unwrap();
                    release_open_receiver.recv().unwrap();
                    File::open(path)
                })
                .unwrap()
                .map(Cow::into_owned)
        });
        open_started_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();

        // While one open of slow.bin is blocked, reads of a pinned object
        // finish, and a second first open of slow.bin does not wait.
        let (done_sender, done_receiver) = std::sync::mpsc::channel();
        let readers = (0..4)
            .map(|_| {
                let source = source.clone();
                let done_sender = done_sender.clone();
                thread::spawn(move || {
                    done_sender
                        .send(source.read_range("ready.bin", 1, 3))
                        .unwrap();
                })
            })
            .collect::<Vec<_>>();
        for _ in 0..4 {
            assert_eq!(
                done_receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("a slow open blocked reads of another object")
                    .unwrap(),
                b"ead"
            );
        }
        for reader in readers {
            reader.join().unwrap();
        }
        let fast_source = source.clone();
        let (fast_sender, fast_receiver) = std::sync::mpsc::channel();
        let fast_open = thread::spawn(move || {
            fast_sender
                .send(fast_source.read_range("slow.bin", 0, 4))
                .unwrap();
        });
        assert_eq!(
            fast_receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("a slow open blocked another first open of the same object")
                .unwrap(),
            b"slow"
        );
        fast_open.join().unwrap();

        // The first result in the slot wins. The blocked open then gets the
        // stored handle, not its own.
        release_open_sender.send(()).unwrap();
        let slow = slow_open.join().unwrap().unwrap();
        let stored = source.pinned_file("slow.bin").unwrap().unwrap();
        assert!(Arc::ptr_eq(&slow.file, &stored.file));

        let barrier = std::sync::Barrier::new(16);
        let files = thread::scope(|scope| {
            let handles = (0..16)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        source
                            .pinned_file("raced.bin")
                            .unwrap()
                            .unwrap()
                            .into_owned()
                            .file
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert!(
            files.iter().all(|file| Arc::ptr_eq(file, &files[0])),
            "concurrent first-open callers did not converge on one pinned handle"
        );
    }

    #[test]
    fn pinned_sources_keep_lookup_errors_missing_objects_and_identity_checks() {
        let directory = tempdir().unwrap();
        fs::write(directory.path().join("b.bin"), b"bravo").unwrap();
        fs::write(directory.path().join("a.bin"), b"alpha").unwrap();
        let open = PinnedLocalRangeSource::new(directory.path());
        let anchored =
            PinnedLocalRangeSource::new_anchored(directory.path(), &["a.bin", "b.bin", "late.bin"])
                .unwrap();

        // A path-rooted source checks the name first. An anchored source
        // checks its allowlist first.
        assert_eq!(
            open.read_range("../a.bin", 0, 1).unwrap_err().to_string(),
            "invalid object name: ../a.bin"
        );
        assert_eq!(
            anchored.size("../a.bin").unwrap_err().to_string(),
            "remote source protocol error: object ../a.bin is outside the anchored local \
             source allowlist"
        );

        for source in [&open, &anchored] {
            assert_eq!(source.size("late.bin").unwrap(), None);
        }
        // A missing object stays missing after its path appears.
        fs::write(directory.path().join("late.bin"), b"late").unwrap();
        for source in [&open, &anchored] {
            assert_eq!(source.size("late.bin").unwrap(), None);
            assert_eq!(
                source.read_range("late.bin", 0, 1).unwrap_err().to_string(),
                "object late.bin does not exist"
            );
            assert!(source.pinned_file_clone("late.bin").unwrap().is_none());
            assert_eq!(source.read_range("b.bin", 1, 4).unwrap(), b"ravo");
            assert_eq!(source.read_range("a.bin", 0, 5).unwrap(), b"alpha");
            assert_eq!(
                source.read_range("a.bin", 4, 2).unwrap_err().to_string(),
                "range for a.bin is outside the object: offset=4, length=2, size=5"
            );
            let identities = source.pinned_object_identities().unwrap();
            assert_eq!(
                identities
                    .iter()
                    .map(|identity| (identity.object.as_str(), identity.size))
                    .collect::<Vec<_>>(),
                [("a.bin", 5), ("b.bin", 5)]
            );
            let pinned = source.pinned_file_clone("a.bin").unwrap().unwrap();
            assert_eq!(pinned.metadata().unwrap().ino(), identities[0].inode);
            source.verify_unchanged().unwrap();
        }

        // A new length changes the identity even when the file system keeps
        // a coarse modification time.
        fs::write(directory.path().join("a.bin"), b"ALPHA!").unwrap();
        for source in [&open, &anchored] {
            assert_eq!(
                source.verify_unchanged().unwrap_err().to_string(),
                "remote source protocol error: object a.bin changed after it was opened"
            );
        }
    }
}
