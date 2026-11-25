//! Small publisher-owned locator catalog. It contains no block payloads.
use crate::recent::RecentMetadata;
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use blockzilla_bank_stream_v2::{self as v2, SourceIdentity};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeArchiveObjectV1 {
    pub key: String,
    pub etag: String,
    pub length: u64,
    pub sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeArchiveV1 {
    pub version: u16,
    pub producer_generation: String,
    pub metadata: RecentMetadata,
    pub root_frame_base64: String,
    pub frame: NativeArchiveObjectV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    version: u16,
    source: SourceIdentity,
    producer_generation: String,
    prefix: String,
}

impl NativeArchiveV1 {
    pub fn validate(&self, source: &SourceIdentity, generation: &str, slot: u64) -> Result<()> {
        let metadata = &self.metadata;
        ensure!(
            self.version == 1
                && self.producer_generation == generation
                && v2::is_digest(generation),
            "native_archive_generation_changed"
        );
        ensure!(
            metadata.version == 1
                && metadata.slot == slot
                && slot <= v2::SAFE
                && metadata.bank_id <= v2::SAFE
                && metadata.parent_slot < slot
                && metadata.commitment == "finalized"
                && &metadata.source == source,
            "native_archive_identity_changed"
        );
        let (session, sequence, sha) = v2::parse_cursor(&metadata.cursor)?;
        ensure!(
            session == source.session_id
                && sequence > 0
                && sha == metadata.frame_sha256
                && v2::is_digest(sha),
            "native_archive_cursor_changed"
        );
        ensure!(
            self.frame.sha256 == metadata.frame_sha256
                && (16..=v2::MAX_FRAME as u64).contains(&self.frame.length),
            "native_archive_frame_changed"
        );
        ensure!(
            self.frame.key
                == format!(
                    "native-stream/bank-v2/{}/frames/{}.bin",
                    source.session_id, self.frame.sha256
                ),
            "native_archive_key_changed"
        );
        let etag = self.frame.etag.as_bytes();
        ensure!(
            (3..=258).contains(&etag.len())
                && etag[0] == b'"'
                && etag[etag.len() - 1] == b'"'
                && etag[1..etag.len() - 1]
                    .iter()
                    .all(|b| b.is_ascii_graphic() && *b != b'"' && *b != b'\\'),
            "native_archive_etag_invalid"
        );
        ensure!(
            self.root_frame_base64.len() <= 5462,
            "native_archive_root_too_large"
        );
        let raw = URL_SAFE_NO_PAD.decode(&self.root_frame_base64)?;
        ensure!(
            raw.len() <= 4096 && URL_SAFE_NO_PAD.encode(&raw) == self.root_frame_base64,
            "native_archive_root_invalid"
        );
        let root = v2::decode(raw.into())?;
        let event = &root.envelope.event;
        ensure!(
            root.source == *source
                && event.kind == "root"
                && event.bank.slot == slot
                && event.bank.bank_id == metadata.bank_id
                && event.bank.parent_slot == metadata.parent_slot
                && event.bank.blockhash == v2::hash(&metadata.blockhash)?
                && event.bank.parent_blockhash == v2::hash(&metadata.parent_blockhash)?
                && event.payload_frame_sha256.as_deref() == Some(metadata.frame_sha256.as_str()),
            "native_archive_root_changed"
        );
        Ok(())
    }
}

pub fn read(
    path: &Path,
    source: &SourceIdentity,
    generation: &str,
    slot: u64,
) -> Result<Option<NativeArchiveV1>> {
    ensure!(
        path.is_absolute()
            && std::fs::symlink_metadata(path)?.is_file()
            && path.canonicalize()? == path,
        "native_archive_catalog_unavailable"
    );
    let db = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    // Read the descriptor and selected locator from one read-only snapshot.
    db.execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF; BEGIN;")?;
    let binding: Binding = serde_json::from_str(
        &record(
            &db,
            "SELECT length(CAST(record AS BLOB)),record FROM meta WHERE id=1",
            None,
        )?
        .context("native_archive_binding_unavailable")?,
    )?;
    ensure!(
        binding.version == 1
            && binding.source == *source
            && binding.producer_generation == generation
            && binding.prefix == format!("native-stream/bank-v2/{}", source.session_id),
        "native_archive_binding_changed"
    );
    let Some(raw) = record(
        &db,
        "SELECT length(CAST(record AS BLOB)),record FROM finalized WHERE slot=?1",
        Some(slot),
    )?
    else {
        return Ok(None);
    };
    let value: NativeArchiveV1 = serde_json::from_str(&raw)?;
    value.validate(source, generation, slot)?;
    Ok(Some(value))
}

fn record(db: &Connection, sql: &str, slot: Option<u64>) -> Result<Option<String>> {
    let mut query = db.prepare(sql)?;
    let mut rows = if let Some(slot) = slot {
        query.query([slot])?
    } else {
        query.query([])?
    };
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let length: u64 = row.get(0)?;
    ensure!(length <= 16384, "native_archive_record_too_large");
    let raw: String = row.get(1)?;
    ensure!(rows.next()?.is_none(), "native_archive_record_ambiguous");
    Ok(Some(raw))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn fixture() -> (
        tempfile::TempDir,
        crate::recent::tests::Fixture,
        NativeArchiveV1,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let native = crate::recent::tests::fixture();
        let found = native.client.read_finalized_by_slot(100).unwrap().unwrap();
        let value = NativeArchiveV1 {
            version: 1,
            producer_generation: "a".repeat(64),
            metadata: found.metadata,
            root_frame_base64: URL_SAFE_NO_PAD.encode(found.root.wire),
            frame: NativeArchiveObjectV1 {
                key: format!(
                    "native-stream/bank-v2/{}/frames/{}.bin",
                    native.frame.source.session_id, native.frame.sha256
                ),
                etag: "\"fixture-etag\"".into(),
                length: native.frame.wire.len() as u64,
                sha256: native.frame.sha256.clone(),
            },
        };
        let db = Connection::open(directory.path().join("archive.sqlite")).unwrap();
        db.execute_batch("CREATE TABLE meta(id INTEGER PRIMARY KEY,record TEXT NOT NULL); CREATE TABLE finalized(slot INTEGER PRIMARY KEY,record TEXT NOT NULL);").unwrap();
        let binding = json!({"version":1,"source":native.frame.source,"producer_generation":"a".repeat(64),"prefix":format!("native-stream/bank-v2/{}",native.frame.source.session_id)});
        db.execute(
            "INSERT INTO meta VALUES(1,?1)",
            [serde_json::to_string(&binding).unwrap()],
        )
        .unwrap();
        db.execute(
            "INSERT INTO finalized VALUES(100,?1)",
            [serde_json::to_string(&value).unwrap()],
        )
        .unwrap();
        (directory, native, value)
    }

    #[test]
    fn verified_catalog_reads_a_small_locator_without_mutation_or_a_block_file() {
        let (directory, native, expected) = fixture();
        let path = directory.path().join("archive.sqlite");
        let before = std::fs::read(&path).unwrap();
        let found = read(&path, &native.frame.source, &"a".repeat(64), 100)
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::to_value(found).unwrap(),
            serde_json::to_value(expected).unwrap()
        );
        assert!(
            read(&path, &native.frame.source, &"a".repeat(64), 99)
                .unwrap()
                .is_none()
        );
        assert_eq!(before, std::fs::read(&path).unwrap());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn changed_catalog_binding_is_an_error_even_when_the_slot_is_absent() {
        let (directory, native, _) = fixture();
        let path = directory.path().join("archive.sqlite");
        assert!(read(&path, &native.frame.source, &"b".repeat(64), 99).is_err());
        Connection::open(&path)
            .unwrap()
            .execute("DELETE FROM meta", [])
            .unwrap();
        assert!(read(&path, &native.frame.source, &"a".repeat(64), 99).is_err());
        assert!(
            read(
                &directory.path().join("absent.sqlite"),
                &native.frame.source,
                &"a".repeat(64),
                99
            )
            .is_err()
        );
    }

    #[test]
    fn malformed_or_unbound_archive_records_never_become_checked_misses() {
        for field in [
            "producer_generation",
            "key",
            "etag",
            "length",
            "frame_sha",
            "cursor",
            "slot",
            "source",
            "root",
            "oversized",
        ] {
            let (directory, native, value) = fixture();
            let path = directory.path().join("archive.sqlite");
            let mut value = serde_json::to_value(value).unwrap();
            match field {
                "producer_generation" => value["producer_generation"] = json!("b".repeat(64)),
                "key" => value["frame"]["key"] = json!("native-stream/bank-v2/other/frames/x.bin"),
                "etag" => value["frame"]["etag"] = json!("unquoted"),
                "length" => value["frame"]["length"] = json!(v2::MAX_FRAME + 1),
                "frame_sha" => value["frame"]["sha256"] = json!("b".repeat(64)),
                "cursor" => {
                    value["metadata"]["cursor"] = json!(v2::cursor(
                        &native.frame.source.session_id,
                        1,
                        &"b".repeat(64)
                    ))
                }
                "slot" => value["metadata"]["slot"] = json!(101),
                "source" => value["metadata"]["source"]["session_id"] = json!("other-session"),
                "root" => {
                    value["root_frame_base64"] = json!(URL_SAFE_NO_PAD.encode(&native.frame.wire))
                }
                "oversized" => value["root_frame_base64"] = json!("a".repeat(17000)),
                _ => unreachable!(),
            }
            Connection::open(&path)
                .unwrap()
                .execute(
                    "UPDATE finalized SET record=?1 WHERE slot=100",
                    [serde_json::to_string(&value).unwrap()],
                )
                .unwrap();
            assert!(
                read(&path, &native.frame.source, &"a".repeat(64), 100).is_err(),
                "accepted {field}"
            );
        }
    }
}
