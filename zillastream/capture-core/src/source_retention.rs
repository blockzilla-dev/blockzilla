//! Local source retirement after a separate producer durably owns every row.
//!
//! Only the source journal writer calls `process_one`. The producer ACK is not
//! a discovery watermark: its FULL-committed input custody must cover all rows
//! through the requested sequence, including incomplete Banks and controls.
use crate::event::digest;
use anyhow::{Context, Result, ensure};
use blockzilla_bank_stream_v2::SourceIdentity;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path},
    time::Duration,
};

pub const SOURCE_ACK_SCHEMA: &str = "hivezilla-continuous-source-ack-v1";
pub const SOURCE_ACK_FILE: &str = "SOURCE-ACK.json";
pub const SOURCE_RETIREMENT_FILE: &str = "SOURCE-RETIREMENT.json";
const DELETE_ROWS: u64 = 2048;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceAckTicket {
    pub schema: String,
    pub source: SourceIdentity,
    pub producer_db: String,
    pub producer_db_device: u64,
    pub producer_db_inode: u64,
    pub producer_generation: String,
    pub feed_header_sha256: String,
    pub source_start_sequence: u64,
    pub through_sequence: u64,
    pub proof_sha256: String,
}

pub fn source_ack_proof(
    source: &SourceIdentity,
    producer_generation: &str,
    feed_header_sha256: &str,
    source_start_sequence: u64,
    custody_through_sequence: u64,
) -> Result<String> {
    Ok(digest(&serde_json::to_vec(&(
        SOURCE_ACK_SCHEMA,
        source,
        producer_generation,
        feed_header_sha256,
        source_start_sequence,
        custody_through_sequence,
    ))?))
}

fn sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn validate_ticket(ticket: &SourceAckTicket, source: &SourceIdentity) -> Result<()> {
    source.validate()?;
    ensure!(
        ticket.schema == SOURCE_ACK_SCHEMA && ticket.source == *source,
        "source ACK generation mismatch"
    );
    ensure!(
        !ticket.producer_generation.is_empty()
            && ticket.producer_generation.len() <= 128
            && ticket
                .producer_generation
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
            && sha(&ticket.feed_header_sha256)
            && sha(&ticket.proof_sha256),
        "invalid source ACK producer binding"
    );
    // A skipped initial prefix needs a separate durable gap contract. The first
    // continuous deployment takes custody from sequence one in a fresh source.
    ensure!(
        ticket.source_start_sequence == 0 && ticket.through_sequence <= i64::MAX as u64,
        "unsupported source ACK start/frontier"
    );
    ensure!(
        ticket.proof_sha256
            == source_ack_proof(
                source,
                &ticket.producer_generation,
                &ticket.feed_header_sha256,
                0,
                ticket.through_sequence
            )?,
        "source ACK ticket proof mismatch"
    );
    Ok(())
}

fn regular(path: &Path, max: u64, private: bool) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect source ACK file {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file() && metadata.nlink() == 1 && metadata.len() <= max,
        "unsafe source ACK file {}",
        path.display()
    );
    ensure!(
        metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & if private { 0o077 } else { 0o022 } == 0,
        "source ACK file ownership/mode mismatch {}",
        path.display()
    );
    Ok(metadata)
}

/// Reject symlinks in every component, rather than trusting a canonical target.
fn real_absolute(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && path.as_os_str().len() <= 4096,
        "source ACK path is not absolute/bounded"
    );
    let mut checked = std::path::PathBuf::new();
    for component in path.components() {
        ensure!(
            matches!(component, Component::RootDir | Component::Normal(_)),
            "unsafe source ACK path component"
        );
        checked.push(component.as_os_str());
        ensure!(
            !fs::symlink_metadata(&checked)?.file_type().is_symlink(),
            "symlink in source ACK path {}",
            checked.display()
        );
    }
    Ok(())
}

pub fn write_source_ack(session: &Path, ticket: &SourceAckTicket) -> Result<()> {
    validate_ticket(ticket, &ticket.source)?;
    private_json(session, SOURCE_ACK_FILE, ticket)
}

/// Read one immutable publication through its opened descriptor. The producer
/// closes and fsyncs each private temporary file before atomic replacement.
/// Replacement can unlink this old inode after lookup or open; a zero link
/// count is valid for this ACK snapshot only. Database identity checks and all
/// durable custody/proof checks remain strict and use the saved ticket.
fn read_ack(path: &Path) -> Result<Option<Vec<u8>>> {
    read_ack_with(path, |_| Ok(()))
}

fn read_ack_with(
    path: &Path,
    after_open: impl FnOnce(&File) -> Result<()>,
) -> Result<Option<Vec<u8>>> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("open source ACK descriptor"),
    };
    after_open(&file)?;
    let before = file.metadata()?;
    let safe = |metadata: &fs::Metadata| {
        metadata.file_type().is_file()
            && metadata.nlink() <= 1
            && metadata.len() <= 65536
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0
    };
    ensure!(safe(&before), "unsafe source ACK descriptor");
    let mut raw = Vec::new();
    (&mut file).take(65537).read_to_end(&mut raw)?;
    let after = file.metadata()?;
    ensure!(
        safe(&after)
            && before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.mode() == after.mode()
            && raw.len() as u64 == before.len(),
        "source ACK descriptor changed during read"
    );
    Ok(Some(raw))
}

fn private_json(session: &Path, name: &str, value: &impl Serialize) -> Result<()> {
    real_absolute(session)?;
    let destination = session.join(name);
    let temporary = destination.with_extension("json.tmp");
    if temporary.try_exists()? {
        regular(&temporary, 65536, true)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)?;
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() < 65536, "source ACK ticket exceeds bound");
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, &destination)?;
    File::open(session)?.sync_all()?;
    Ok(())
}

pub fn initialize(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE live_source_gc(id INTEGER PRIMARY KEY CHECK(id=1),producer_db TEXT NOT NULL,producer_device INTEGER NOT NULL,producer_inode INTEGER NOT NULL,producer_generation TEXT NOT NULL,feed_header_sha256 TEXT NOT NULL,accepted_through INTEGER NOT NULL,retired_through INTEGER NOT NULL,deleted_events INTEGER NOT NULL,custody_through INTEGER NOT NULL,proof_sha256 TEXT NOT NULL);")?;
    Ok(())
}

#[derive(Debug)]
struct Custody {
    frontier: u64,
    proof: String,
}

fn verify_custody(ticket: &SourceAckTicket) -> Result<Custody> {
    let path = Path::new(&ticket.producer_db);
    ensure!(
        path.file_name().is_some_and(|name| name == "feed.sqlite"),
        "source ACK must name the producer feed database"
    );
    real_absolute(path)?;
    let before = regular(path, u64::MAX, false)?;
    ensure!(
        before.dev() == ticket.producer_db_device && before.ino() == ticket.producer_db_inode,
        "producer ACK database identity changed"
    );
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    db.busy_timeout(Duration::ZERO)?;
    let (schema, source_json, generation, header, start, frontier, proof): (String,String,String,String,u64,u64,String) = db.query_row(
        "SELECT schema,source_json,producer_generation,feed_header_sha256,source_start_sequence,custody_through_sequence,proof_sha256 FROM source_acks WHERE id=1 AND length(schema)<=128 AND length(source_json)<=4096 AND length(producer_generation)<=128 AND length(feed_header_sha256)=64 AND length(proof_sha256)=64",
        [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?)),
    )?;
    ensure!(
        source_json.len() <= 4096
            && generation.len() <= 128
            && header.len() == 64
            && proof.len() == 64,
        "producer ACK row exceeds bound"
    );
    let source: SourceIdentity = serde_json::from_str(&source_json)?;
    ensure!(
        schema == SOURCE_ACK_SCHEMA
            && source == ticket.source
            && generation == ticket.producer_generation
            && header == ticket.feed_header_sha256
            && start == 0
            && frontier >= ticket.through_sequence
            && frontier <= i64::MAX as u64,
        "producer durable custody does not cover source ACK"
    );
    ensure!(
        proof == source_ack_proof(&source, &generation, &header, start, frontier)?,
        "producer durable custody proof mismatch"
    );
    let after = regular(path, u64::MAX, false)?;
    ensure!(
        after.dev() == before.dev() && after.ino() == before.ino(),
        "producer ACK database replaced during read"
    );
    Ok(Custody { frontier, proof })
}

fn busy(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<rusqlite::Error>()
        .and_then(|e| e.sqlite_error())
        .is_some_and(|e| {
            matches!(
                e.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            )
        })
}

fn receipt(
    session: &Path,
    ticket: &SourceAckTicket,
    next: u64,
    total: u64,
    custody: &Custody,
) -> Result<()> {
    let value = serde_json::json!({"schema":"hivezilla-continuous-source-retired-v1","source":ticket.source,"producer_generation":ticket.producer_generation,"producer_db":ticket.producer_db,"producer_db_device":ticket.producer_db_device,"producer_db_inode":ticket.producer_db_inode,"accepted_through_sequence":ticket.through_sequence,"retired_through_sequence":next,"deleted_events":total,"custody_through_sequence_used":custody.frontier,"proof_sha256_used":custody.proof,"acknowledgement":"SQLite synchronous FULL deletion commit completed; no archive/R2 prerequisite"});
    let path = session.join(SOURCE_RETIREMENT_FILE);
    if path.try_exists()? {
        regular(&path, 65536, true)?;
        let raw = fs::read(&path)?;
        if serde_json::from_slice::<serde_json::Value>(&raw)? == value {
            return Ok(());
        }
    }
    private_json(session, SOURCE_RETIREMENT_FILE, &value)
}

/// Run only on the journal writer's connection. No large proof reads, VACUUM,
/// blocking checkpoint or second source writer is introduced here.
pub fn process_one(session: &Path, db: &mut Connection, source: &SourceIdentity) -> Result<bool> {
    let path = session.join(SOURCE_ACK_FILE);
    let Some(raw) = read_ack(&path)? else {
        return Ok(false);
    };
    let ticket: SourceAckTicket = serde_json::from_slice(&raw)?;
    validate_ticket(&ticket, source)?;
    let synchronous: u64 = db.query_row("PRAGMA synchronous", [], |r| r.get(0))?;
    ensure!(
        synchronous == 2,
        "source ACK deletion requires synchronous FULL"
    );
    let previous: Option<(String,u64,u64,String,String,u64,u64,u64,u64,String)> = db.query_row(
        "SELECT producer_db,producer_device,producer_inode,producer_generation,feed_header_sha256,accepted_through,retired_through,deleted_events,custody_through,proof_sha256 FROM live_source_gc WHERE id=1", [],
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?)),
    ).optional()?;
    let (retired, deleted, old_custody) = if let Some((
        path,
        dev,
        ino,
        generation,
        header,
        accepted,
        retired,
        deleted,
        custody,
        proof,
    )) = previous
    {
        ensure!(
            path == ticket.producer_db
                && dev == ticket.producer_db_device
                && ino == ticket.producer_db_inode
                && generation == ticket.producer_generation
                && header == ticket.feed_header_sha256,
            "source ACK producer generation changed"
        );
        ensure!(
            ticket.through_sequence >= accepted,
            "source ACK frontier regressed"
        );
        if retired == accepted && accepted == ticket.through_sequence {
            // The committed deletion is already complete. Repair a missing
            // receipt after a crash, but do not re-delete, re-checkpoint, or
            // fsync a new identical receipt on every capture batch.
            receipt(
                session,
                &ticket,
                retired,
                deleted,
                &Custody {
                    frontier: custody,
                    proof,
                },
            )?;
            return Ok(false);
        }
        (retired, deleted, custody)
    } else {
        (0, 0, 0)
    };
    let custody = match verify_custody(&ticket) {
        Ok(custody) => custody,
        Err(error) if busy(&error) => return Ok(false),
        Err(error) => return Err(error),
    };
    let durable: u64 = db.query_row("SELECT durable_sequence FROM status WHERE id=1", [], |r| {
        r.get(0)
    })?;
    ensure!(
        custody.frontier <= durable && ticket.through_sequence <= durable,
        "source ACK exceeds source durability"
    );
    ensure!(
        custody.frontier >= old_custody,
        "producer durable custody frontier regressed"
    );
    let tx = db.transaction()?;
    let chunk: Option<(u64,u64,u64)> = tx.query_row(
        "SELECT min(sequence),max(sequence),count(*) FROM (SELECT sequence FROM events WHERE sequence>?1 AND sequence<=?2 ORDER BY sequence LIMIT ?3)",
        params![retired,ticket.through_sequence,DELETE_ROWS],
        |r| { let first:Option<u64>=r.get(0)?; let last:Option<u64>=r.get(1)?; let count:u64=r.get(2)?; Ok(first.zip(last).map(|(first,last)|(first,last,count))) },
    )?;
    let (next, count) = if let Some((first, last, count)) = chunk {
        ensure!(
            first == retired + 1 && last - retired == count && count <= DELETE_ROWS,
            "source ACK prefix has an unrecorded gap"
        );
        let changed = tx.execute(
            "DELETE FROM events WHERE sequence>?1 AND sequence<=?2",
            params![retired, last],
        )?;
        ensure!(changed as u64 == count, "source ACK delete count changed");
        (last, count)
    } else {
        ensure!(
            retired == ticket.through_sequence,
            "source ACK prefix is missing"
        );
        (retired, 0)
    };
    let total = deleted
        .checked_add(count)
        .context("source ACK delete counter overflow")?;
    tx.execute("INSERT INTO live_source_gc VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) ON CONFLICT(id) DO UPDATE SET accepted_through=excluded.accepted_through,retired_through=excluded.retired_through,deleted_events=excluded.deleted_events,custody_through=excluded.custody_through,proof_sha256=excluded.proof_sha256", params![ticket.producer_db,ticket.producer_db_device,ticket.producer_db_inode,ticket.producer_generation,ticket.feed_header_sha256,ticket.through_sequence,next,total,custody.frontier,custody.proof])?;
    tx.execute(
        "UPDATE status SET retired_events=retired_events+?1 WHERE id=1",
        [count],
    )?;
    tx.commit()?;
    if next == ticket.through_sequence {
        receipt(session, &ticket, next, total, &custody)?;
    }
    Ok(count > 0)
}

#[cfg(test)]
mod descriptor_tests {
    use super::*;
    use serde_json::json;
    use std::{
        os::{
            fd::AsRawFd,
            unix::fs::{PermissionsExt, symlink},
        },
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread,
    };

    #[test]
    fn atomic_replacement_keeps_the_opened_old_ack_and_never_follows_new_path() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        private_json(&root, SOURCE_ACK_FILE, &json!({"sequence":1})).unwrap();
        let path = root.join(SOURCE_ACK_FILE);
        let bytes = read_ack_with(&path, |file| {
            assert_ne!(
                unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
            private_json(&root, SOURCE_ACK_FILE, &json!({"sequence":2}))?;
            assert_eq!(file.metadata()?.nlink(), 0);
            Ok(())
        })
        .unwrap()
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["sequence"],
            1
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&read_ack(&path).unwrap().unwrap())
                .unwrap()["sequence"],
            2
        );
        let bytes = read_ack_with(&path, |file| {
            fs::remove_file(&path)?;
            symlink("/dev/zero", &path)?;
            assert_eq!(file.metadata()?.nlink(), 0);
            Ok(())
        })
        .unwrap()
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["sequence"],
            2
        );
        assert!(read_ack(&path).is_err());
    }

    #[test]
    fn unsafe_ack_inodes_still_fail_and_missing_ack_is_optional() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let path = root.join(SOURCE_ACK_FILE);
        assert!(read_ack(&path).unwrap().is_none());
        private_json(&root, SOURCE_ACK_FILE, &json!({"sequence":1})).unwrap();
        let alias = root.join("alias");
        fs::hard_link(&path, &alias).unwrap();
        assert!(read_ack(&path).is_err());
        fs::remove_file(alias).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_ack(&path).is_err());
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(read_ack(&path).is_err());
        fs::remove_dir(&path).unwrap();
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(read_ack(&path).is_err());
        fs::remove_file(&path).unwrap();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(&vec![b'x'; 65537]).unwrap();
        drop(file);
        assert!(read_ack(&path).is_err());
    }

    #[test]
    fn high_frequency_atomic_publication_has_no_unsafe_inode_false_positive() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        private_json(
            &root,
            SOURCE_ACK_FILE,
            &json!({"sequence":0,"padding":"x".repeat(512)}),
        )
        .unwrap();
        let finished = Arc::new(AtomicBool::new(false));
        let flag = finished.clone();
        let published = root.clone();
        let writer = thread::spawn(move || {
            for sequence in 1..=1000 {
                private_json(
                    &published,
                    SOURCE_ACK_FILE,
                    &json!({"sequence":sequence,"padding":"x".repeat(512)}),
                )
                .unwrap();
            }
            flag.store(true, Ordering::Release);
        });
        let (mut previous, mut reads) = (0, 0);
        loop {
            let bytes = read_ack(&root.join(SOURCE_ACK_FILE)).unwrap().unwrap();
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let sequence = value["sequence"].as_u64().unwrap();
            assert!(sequence >= previous);
            previous = sequence;
            reads += 1;
            if finished.load(Ordering::Acquire) {
                break;
            }
        }
        writer.join().unwrap();
        assert!(reads > 0);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(
                &read_ack(&root.join(SOURCE_ACK_FILE)).unwrap().unwrap()
            )
            .unwrap()["sequence"],
            1000
        );
    }
}
