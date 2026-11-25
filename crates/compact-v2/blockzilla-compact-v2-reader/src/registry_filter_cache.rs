use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use sha2::{Digest, Sha256};

use crate::{
    ArchiveReader, CompactPubkey, CompiledPubkeyFilter, Error, GenerationBinding,
    PinnedLocalObjectIdentity, PinnedLocalRangeSource, Result, SourceError,
    manifest::{REGISTRY_FILE, hex_lower},
};

const MAGIC: &[u8; 8] = b"BZPKF001";
const HEADER_BYTES: usize = MAGIC.len() + 32;
const ENTRY_BYTES: usize = 32 + 4;
const CHECKSUM_BYTES: usize = 32;
const MAX_CACHED_KEYS: usize = 65_536;
const MAX_REGISTRY_READ_BYTES: usize = 8 * 1024 * 1024;
static TEMP_SERIAL: AtomicU64 = AtomicU64::new(0);

/// Registry range reads issued by one cached filter compilation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RegistryFilterCacheStats {
    /// A complete cache entry supplied the filter after its positive rows were verified.
    pub cache_hit: bool,
    /// Successful registry range reads, including checks of any rejected cache entry.
    pub registry_read_calls: u64,
    /// Successful registry range bytes, excluding cache-file reads.
    pub registry_read_bytes: u64,
}

impl ArchiveReader<PinnedLocalRangeSource> {
    /// Compile an exact pubkey filter using a private local cache.
    ///
    /// `cache_dir` must be an existing, trusted directory with no group or
    /// other access. The caller must keep it and its ancestors under trusted
    /// control. Cache files use a checksum to detect corruption. The caller
    /// must supply the expected SHA-256 of `registry.bin` from a trusted source.
    ///
    /// A miss verifies that SHA-256 and checks every registry row in one
    /// bounded pass before publishing an atomic cache entry. A hit requires the
    /// same pinned registry identity, archive generation, expected SHA-256,
    /// and unique pubkeys. The reader checks each positive registry row and
    /// retains every requested key for inline references. For more than 65,536
    /// distinct pubkeys, it uses the same exact verified scan without caching.
    pub fn compile_pubkey_filter_cached(
        &self,
        pubkeys: impl IntoIterator<Item = [u8; 32]>,
        cache_dir: &Path,
        expected_registry_sha256: [u8; 32],
    ) -> Result<(CompiledPubkeyFilter, RegistryFilterCacheStats)> {
        use std::os::unix::fs::PermissionsExt;

        let metadata = fs::symlink_metadata(cache_dir).map_err(|err| cache_io(cache_dir, err))?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(cache_io(
                cache_dir,
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "expected a private directory",
                ),
            ));
        }

        let raw_pubkeys: HashSet<_> = pubkeys.into_iter().collect();
        let source = self.source();
        source.verify_unchanged()?;
        let cache = if raw_pubkeys.len() <= MAX_CACHED_KEYS {
            let mut sorted_pubkeys: Vec<_> = raw_pubkeys.iter().copied().collect();
            sorted_pubkeys.sort_unstable();
            let registry = source
                .pinned_object_identities()?
                .into_iter()
                .find(|object| object.object == REGISTRY_FILE)
                .ok_or_else(|| Error::InvalidRegistry("registry.bin is not pinned".into()))?;
            let scope = cache_scope(
                &registry,
                self.binding(),
                expected_registry_sha256,
                &sorted_pubkeys,
            );
            let path = cache_dir.join(format!("{}.pubkey-filter", hex_lower(&scope)));
            Some((path, scope, sorted_pubkeys))
        } else {
            None
        };
        let mut stats = RegistryFilterCacheStats::default();

        if let Some((path, scope, sorted_pubkeys)) = cache.as_ref()
            && let Some(encoded) = read_cache(path, scope, sorted_pubkeys)?
        {
            let mut resolved_ids = HashMap::new();
            let mut valid = true;
            for (key, id) in sorted_pubkeys.iter().copied().zip(encoded) {
                if id == 0 {
                    continue;
                }
                if id > self.registry_entries() {
                    valid = false;
                    break;
                }
                let actual = self.resolve_pubkey(&CompactPubkey::Id(id))?;
                stats.registry_read_calls += 1;
                stats.registry_read_bytes += 32;
                if actual != key {
                    valid = false;
                    break;
                }
                resolved_ids.insert(key, id);
            }
            source.verify_unchanged()?;
            if valid {
                stats.cache_hit = true;
                return Ok((self.bind_pubkey_filter(raw_pubkeys, resolved_ids), stats));
            }
        }

        let mut hasher = Sha256::new();
        let filter = self.scan_pubkey_filter(raw_pubkeys, MAX_REGISTRY_READ_BYTES, |bytes| {
            hasher.update(bytes);
            stats.registry_read_calls += 1;
            stats.registry_read_bytes += bytes.len() as u64;
        })?;
        let actual: [u8; 32] = hasher.finalize().into();
        if actual != expected_registry_sha256 {
            return Err(Error::FileHash {
                name: REGISTRY_FILE.to_owned(),
                expected: hex_lower(&expected_registry_sha256),
                actual: hex_lower(&actual),
            });
        }
        source.verify_unchanged()?;
        if let Some((path, scope, sorted_pubkeys)) = cache {
            write_cache(cache_dir, &path, &scope, &sorted_pubkeys, &filter)?;
            source.verify_unchanged()?;
        }
        Ok((filter, stats))
    }
}

fn cache_scope(
    registry: &PinnedLocalObjectIdentity,
    generation: GenerationBinding,
    expected_sha256: [u8; 32],
    pubkeys: &[[u8; 32]],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(MAGIC);
    hasher.update(registry.device.to_le_bytes());
    hasher.update(registry.inode.to_le_bytes());
    hasher.update(registry.size.to_le_bytes());
    hasher.update(registry.modified_seconds.to_le_bytes());
    hasher.update(registry.modified_nanoseconds.to_le_bytes());
    hasher.update(registry.changed_seconds.to_le_bytes());
    hasher.update(registry.changed_nanoseconds.to_le_bytes());
    hasher.update(generation.generation_digest);
    hasher.update(generation.registry_sha256);
    hasher.update(expected_sha256);
    for key in pubkeys {
        hasher.update(key);
    }
    hasher.finalize().into()
}

fn read_cache(path: &Path, scope: &[u8; 32], pubkeys: &[[u8; 32]]) -> Result<Option<Vec<u32>>> {
    let expected_len = HEADER_BYTES + pubkeys.len() * ENTRY_BYTES + CHECKSUM_BYTES;
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(cache_io(path, err)),
    };
    if !metadata.is_file() || metadata.len() != expected_len as u64 {
        return Ok(None);
    }
    let mut file = File::open(path).map_err(|err| cache_io(path, err))?;
    let mut bytes = vec![0; expected_len];
    match file.read_exact(&mut bytes) {
        Ok(()) => (),
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(cache_io(path, err)),
    }
    if file.read(&mut [0]).map_err(|err| cache_io(path, err))? != 0 {
        return Ok(None);
    }
    let (payload, checksum) = bytes.split_at(expected_len - CHECKSUM_BYTES);
    if &payload[..MAGIC.len()] != MAGIC
        || &payload[MAGIC.len()..HEADER_BYTES] != scope
        || &Sha256::digest(payload)[..] != checksum
    {
        return Ok(None);
    }
    let mut ids = Vec::with_capacity(pubkeys.len());
    for (key, entry) in pubkeys
        .iter()
        .zip(payload[HEADER_BYTES..].as_chunks::<ENTRY_BYTES>().0)
    {
        let (cached_key, id) = entry.split_at(32);
        if key != cached_key {
            return Ok(None);
        }
        ids.push(u32::from_le_bytes(
            id.try_into().expect("fixed cache entry width"),
        ));
    }
    Ok(Some(ids))
}

fn write_cache(
    directory: &Path,
    path: &Path,
    scope: &[u8; 32],
    pubkeys: &[[u8; 32]],
    filter: &CompiledPubkeyFilter,
) -> Result<()> {
    let mut bytes = Vec::with_capacity(HEADER_BYTES + pubkeys.len() * ENTRY_BYTES + CHECKSUM_BYTES);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(scope);
    for key in pubkeys {
        bytes.extend_from_slice(key);
        bytes.extend_from_slice(&filter.registry_id_for(key).unwrap_or(0).to_le_bytes());
    }
    let checksum = Sha256::digest(&bytes);
    bytes.extend_from_slice(&checksum);

    let (temporary_path, mut temporary) = open_temporary(directory)?;
    let publish = (|| -> io::Result<()> {
        temporary.write_all(&bytes)?;
        temporary.sync_all()?;
        fs::rename(&temporary_path, path)?;
        File::open(directory)?.sync_all()
    })();
    if let Err(err) = publish {
        let _ = fs::remove_file(&temporary_path);
        return Err(cache_io(path, err));
    }
    Ok(())
}

fn open_temporary(directory: &Path) -> Result<(PathBuf, File)> {
    let pid = std::process::id();
    for _ in 0..32 {
        let serial = TEMP_SERIAL.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!(".pubkey-filter-{pid}-{serial}.tmp"));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => return Ok((path, file)),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(cache_io(&path, err)),
        }
    }
    Err(cache_io(
        directory,
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "cache temporary names are in use",
        ),
    ))
}

fn cache_io(path: &Path, source: io::Error) -> Error {
    Error::Source(SourceError::Io {
        object: path.display().to_string(),
        source,
    })
}
