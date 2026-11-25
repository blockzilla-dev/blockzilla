//! Exact CAR SlotMeta sidecar. This is source metadata, not a consensus verdict.
use anyhow::{Context, Result, ensure};
use blockzilla_solana_wire::slot_meta::SlotMeta;
use std::{
    fs::File,
    io::{BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

pub const CAR_SLOT_META_FILE: &str = "car-slot-meta.v1.bin";
pub const CAR_SLOT_META_SEMANTIC_SCHEMA: &str = "blockzilla-car-slot-meta-v1";
pub const CAR_SLOT_META_MAGIC: [u8; 8] = *b"BZCSM001";
pub const CAR_SLOT_META_VERSION: u32 = 1;
/// Faithful SlotMeta tuple, exact CBOR; v0.7.30/v0.7.33 known fields.
pub const CAR_SLOT_META_SOURCE_PROFILE: u32 = 1;
pub const CAR_SLOT_META_MAX_ROWS: u64 = 432_000;
pub const CAR_SLOT_META_MAX_BYTES: u32 = 64 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub struct CarSlotMetaRecord {
    pub ordinal: u64,
    pub slot: u64,
    pub meta: SlotMeta,
}

pub struct CarSlotMetaWriter<W: Write + Seek> {
    writer: W,
    rows: u64,
    last_slot: Option<u64>,
    directory: Option<PathBuf>,
}
impl<W: Write + Seek> CarSlotMetaWriter<W> {
    pub fn new(mut writer: W) -> Result<Self> {
        writer.write_all(&CAR_SLOT_META_MAGIC)?;
        writer.write_all(&CAR_SLOT_META_VERSION.to_le_bytes())?;
        writer.write_all(&CAR_SLOT_META_SOURCE_PROFILE.to_le_bytes())?;
        // u64::MAX is deliberately invalid until finish commits a real count.
        writer.write_all(&u64::MAX.to_le_bytes())?;
        Ok(Self {
            writer,
            rows: 0,
            last_slot: None,
            directory: None,
        })
    }
    pub fn write(&mut self, ordinal: u64, slot: u64, raw: &[u8]) -> Result<()> {
        ensure!(
            ordinal == self.rows && self.rows < CAR_SLOT_META_MAX_ROWS,
            "CAR metadata ordinal/count mismatch"
        );
        ensure!(
            self.last_slot.is_none_or(|previous| slot > previous),
            "CAR metadata slots must increase"
        );
        ensure!(
            raw.len() <= CAR_SLOT_META_MAX_BYTES as usize,
            "CAR metadata frame exceeds limit"
        );
        SlotMeta::from_cbor(raw).context("invalid CAR SlotMeta")?;
        self.writer.write_all(&ordinal.to_le_bytes())?;
        self.writer.write_all(&slot.to_le_bytes())?;
        self.writer.write_all(&(raw.len() as u32).to_le_bytes())?;
        self.writer.write_all(raw)?;
        self.rows += 1;
        self.last_slot = Some(slot);
        Ok(())
    }
    pub fn finish(mut self) -> Result<W> {
        self.writer.flush()?;
        self.writer.seek(SeekFrom::Start(16))?;
        self.writer.write_all(&self.rows.to_le_bytes())?;
        self.writer.flush()?;
        Ok(self.writer)
    }
}
impl CarSlotMetaWriter<BufWriter<File>> {
    pub fn create(path: &Path) -> Result<Self> {
        let mut writer = Self::new(BufWriter::new(
            File::create(path).with_context(|| format!("create {}", path.display()))?,
        ))?;
        writer.directory = Some(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf(),
        );
        Ok(writer)
    }
    /// Complete and sync this mandatory sidecar before the archive footer.
    pub fn finish_sync(self) -> Result<()> {
        let directory = self
            .directory
            .clone()
            .context("durable CAR metadata writer needs a bound directory; use create")?;
        let writer = self.finish()?;
        writer.get_ref().sync_all()?;
        File::open(&directory)
            .with_context(|| format!("open CAR metadata directory {}", directory.display()))?
            .sync_all()?;
        Ok(())
    }
}

pub struct CarSlotMetaReader<R: Read> {
    reader: R,
    pub rows: u64,
    next: u64,
    last_slot: Option<u64>,
}
impl<R: Read> CarSlotMetaReader<R> {
    pub fn new(mut reader: R) -> Result<Self> {
        let mut header = [0; 24];
        reader.read_exact(&mut header)?;
        ensure!(
            header[..8] == CAR_SLOT_META_MAGIC,
            "invalid CAR metadata magic"
        );
        ensure!(
            u32::from_le_bytes(header[8..12].try_into()?) == CAR_SLOT_META_VERSION,
            "unsupported CAR metadata version"
        );
        ensure!(
            u32::from_le_bytes(header[12..16].try_into()?) == CAR_SLOT_META_SOURCE_PROFILE,
            "unsupported CAR metadata source profile"
        );
        let rows = u64::from_le_bytes(header[16..24].try_into()?);
        ensure!(
            rows <= CAR_SLOT_META_MAX_ROWS,
            "invalid/uncommitted CAR metadata count"
        );
        Ok(Self {
            reader,
            rows,
            next: 0,
            last_slot: None,
        })
    }
    pub fn read_record(&mut self) -> Result<Option<CarSlotMetaRecord>> {
        if self.next == self.rows {
            let mut byte = [0];
            ensure!(
                self.reader.read(&mut byte)? == 0,
                "trailing CAR metadata bytes"
            );
            return Ok(None);
        }
        let mut header = [0; 20];
        self.reader.read_exact(&mut header)?;
        let ordinal = u64::from_le_bytes(header[..8].try_into()?);
        let slot = u64::from_le_bytes(header[8..16].try_into()?);
        let len = u32::from_le_bytes(header[16..20].try_into()?);
        ensure!(ordinal == self.next, "CAR metadata ordinal mismatch");
        ensure!(
            self.last_slot.is_none_or(|previous| slot > previous),
            "CAR metadata slots must increase"
        );
        ensure!(
            len <= CAR_SLOT_META_MAX_BYTES,
            "CAR metadata frame exceeds limit"
        );
        let mut raw = vec![0; len as usize];
        self.reader.read_exact(&mut raw)?;
        let meta = SlotMeta::from_cbor(&raw)?;
        self.next += 1;
        self.last_slot = Some(slot);
        Ok(Some(CarSlotMetaRecord {
            ordinal,
            slot,
            meta,
        }))
    }
    /// Full exact alignment with the compact block index, including EOF.
    pub fn validate_slots(mut self, slots: impl IntoIterator<Item = u64>) -> Result<()> {
        for slot in slots {
            let row = self
                .read_record()?
                .context("CAR metadata missing index row")?;
            ensure!(row.slot == slot, "CAR metadata/index slot mismatch");
        }
        ensure!(
            self.read_record()?.is_none(),
            "CAR metadata has extra index rows"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    fn complete() -> Vec<u8> {
        let mut w = CarSlotMetaWriter::new(Cursor::new(Vec::new())).unwrap();
        w.write(0, 10, &[0x82, 1, 2]).unwrap();
        w.write(1, 12, &[0x84, 3, 4, 0xf6, 0x80]).unwrap();
        w.finish().unwrap().into_inner()
    }
    #[test]
    fn exact_raw_and_index_roundtrip() {
        let bytes = complete();
        let mut r = CarSlotMetaReader::new(Cursor::new(&bytes)).unwrap();
        assert_eq!(
            r.read_record().unwrap().unwrap().meta.raw_cbor(),
            &[0x82, 1, 2]
        );
        assert_eq!(
            r.read_record().unwrap().unwrap().meta.raw_cbor(),
            &[0x84, 3, 4, 0xf6, 0x80]
        );
        assert!(r.read_record().unwrap().is_none());
        CarSlotMetaReader::new(Cursor::new(bytes))
            .unwrap()
            .validate_slots([10, 12])
            .unwrap();
    }
    #[test]
    fn incomplete_and_wrong_coverage_fail() {
        let w = CarSlotMetaWriter::new(Cursor::new(Vec::new())).unwrap();
        assert!(CarSlotMetaReader::new(Cursor::new(w.writer.into_inner())).is_err());
        for slots in [vec![10], vec![10, 11], vec![10, 12, 13]] {
            assert!(
                CarSlotMetaReader::new(Cursor::new(complete()))
                    .unwrap()
                    .validate_slots(slots)
                    .is_err()
            );
        }
    }
    #[test]
    fn truncation_trailing_invalid_ordinal_and_oversize_fail() {
        let bytes = complete();
        for end in 0..bytes.len() {
            let result = CarSlotMetaReader::new(Cursor::new(&bytes[..end]))
                .and_then(|r| r.validate_slots([10, 12]));
            assert!(result.is_err(), "accepted length {end}");
        }
        let mut b = bytes.clone();
        b.push(0);
        assert!(
            CarSlotMetaReader::new(Cursor::new(b))
                .unwrap()
                .validate_slots([10, 12])
                .is_err()
        );
        let mut b = bytes.clone();
        b[24] = 1;
        assert!(
            CarSlotMetaReader::new(Cursor::new(b))
                .unwrap()
                .read_record()
                .is_err()
        );
        let mut b = bytes;
        b[40..44].copy_from_slice(&(CAR_SLOT_META_MAX_BYTES + 1).to_le_bytes());
        assert!(
            CarSlotMetaReader::new(Cursor::new(b))
                .unwrap()
                .read_record()
                .is_err()
        );
    }
    #[test]
    fn writer_rejects_reorder_and_invalid_source() {
        let mut w = CarSlotMetaWriter::new(Cursor::new(Vec::new())).unwrap();
        assert!(w.write(1, 1, &[0x82, 1, 2]).is_err());
        assert!(w.write(0, 1, &[0xa0]).is_err());
        w.write(0, 1, &[0x82, 1, 2]).unwrap();
        assert!(w.write(1, 1, &[0x82, 1, 2]).is_err());
    }
}
