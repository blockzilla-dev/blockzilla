//! Lossless Faithful SlotMeta tuples (v0.7.30 and later).
//!
//! Marker bytes are opaque. Their order, absent/null fields and future tuple
//! values are retained without assuming a consensus activation or marker version.
use minicbor::{Decode, Decoder, Encode, Encoder, data::Type, decode::Error};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldPresence<T> {
    Absent,
    Null,
    Value(T),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SlotMeta {
    pub parent_slot: Option<u64>,
    pub blocktime: Option<i64>,
    pub block_height: Option<u64>,
    /// Decoded marker array, while `block_markers()` retains absent/null detail.
    #[serde(skip_serializing)]
    pub block_markers: Option<Vec<Vec<u8>>>,
    /// Consensus block ID from the source tuple, not the PoH entry hash.
    #[serde(skip_serializing)]
    pub block_id: Option<[u8; 32]>,
    /// Exact source tuple length, including fields not interpreted here.
    #[serde(skip_serializing)]
    pub meta_len: u64,
    // Keep this in serde too: serializing the typed projection must not erase
    // fields that this reader does not interpret.
    raw_cbor: Vec<u8>,
}

// Keep the existing four-field serde representation. Rebuild the derived
// marker projection from its retained CBOR rather than adding a second source
// of truth or changing serialized legacy reconstruction records.
impl<'de> Deserialize<'de> for SlotMeta {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Stored {
            parent_slot: Option<u64>,
            blocktime: Option<i64>,
            block_height: Option<u64>,
            raw_cbor: Vec<u8>,
        }
        let stored = Stored::deserialize(deserializer)?;
        let value = Self::from_cbor(&stored.raw_cbor).map_err(serde::de::Error::custom)?;
        if (stored.parent_slot, stored.blocktime, stored.block_height)
            != (value.parent_slot, value.blocktime, value.block_height)
        {
            return Err(serde::de::Error::custom(
                "SlotMeta projection differs from source bytes",
            ));
        }
        Ok(value)
    }
}

impl SlotMeta {
    /// Last parsed header/update-parent consensus ID. Invalid markers are skipped.
    pub fn parent_consensus_block_id(&self) -> Option<[u8; 32]> {
        self.block_markers
            .as_deref()
            .and_then(crate::blockmarker::parent_consensus_block_id)
    }

    /// Whether the source has the extended tuple shape, including a null tail.
    /// This shape alone does not verify consensus or marker signatures.
    pub fn alpenglow(&self) -> bool {
        self.meta_len > 3
    }

    /// The exact original tuple, including its original scalar encodings.
    pub fn raw_cbor(&self) -> &[u8] {
        &self.raw_cbor
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        let mut d = Decoder::new(bytes);
        let value = d.decode()?;
        if d.position() != bytes.len() {
            return Err(Error::message("trailing SlotMeta bytes"));
        }
        Ok(value)
    }

    /// Raw CBOR of one tuple value. A future field needs no local schema change.
    pub fn field(&self, index: u64) -> Result<FieldPresence<&[u8]>, Error> {
        let mut d = Decoder::new(&self.raw_cbor);
        let len = d
            .array()?
            .ok_or_else(|| Error::message("indefinite SlotMeta"))?;
        if index >= len {
            return Ok(FieldPresence::Absent);
        }
        for _ in 0..index {
            d.skip()?;
        }
        if d.datatype()? == Type::Null {
            return Ok(FieldPresence::Null);
        }
        let start = d.position();
        d.skip()?;
        Ok(FieldPresence::Value(&self.raw_cbor[start..d.position()]))
    }

    pub fn block_markers(&self) -> Result<FieldPresence<Vec<&[u8]>>, Error> {
        match self.field(3)? {
            FieldPresence::Absent => Ok(FieldPresence::Absent),
            FieldPresence::Null => Ok(FieldPresence::Null),
            FieldPresence::Value(raw) => {
                let mut d = Decoder::new(raw);
                let n = d
                    .array()?
                    .ok_or_else(|| Error::message("indefinite block markers"))?;
                // A CBOR byte string needs at least one byte. Bound allocation by
                // the actual encoded input, not an untrusted declared array size.
                if n > raw.len() as u64 {
                    return Err(Error::message("block marker count exceeds input"));
                }
                let mut markers = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    markers.push(d.bytes()?);
                }
                Ok(FieldPresence::Value(markers))
            }
        }
    }

    pub fn block_id(&self) -> Result<FieldPresence<&[u8; 32]>, Error> {
        match self.field(4)? {
            FieldPresence::Absent => Ok(FieldPresence::Absent),
            FieldPresence::Null => Ok(FieldPresence::Null),
            FieldPresence::Value(raw) => {
                let bytes = Decoder::new(raw).bytes()?;
                Ok(FieldPresence::Value(bytes.try_into().map_err(|_| {
                    Error::message("block id must have 32 bytes")
                })?))
            }
        }
    }
}

fn optional_u64(d: &mut Decoder<'_>) -> Result<Option<u64>, Error> {
    if d.datatype()? == Type::Null {
        d.null()?;
        Ok(None)
    } else {
        d.u64().map(Some)
    }
}
fn optional_i64(d: &mut Decoder<'_>) -> Result<Option<i64>, Error> {
    if d.datatype()? == Type::Null {
        d.null()?;
        Ok(None)
    } else {
        d.i64().map(Some)
    }
}

impl<'b, C> Decode<'b, C> for SlotMeta {
    fn decode(d: &mut Decoder<'b>, _: &mut C) -> Result<Self, Error> {
        let start = d.position();
        let n = d
            .array()?
            .ok_or_else(|| Error::message("indefinite SlotMeta"))?;
        // Preserve the former reader's support for short legacy tuples too.
        // Missing fields remain absent; this does not manufacture scalar values.
        let parent_slot = if n > 0 { optional_u64(d)? } else { None };
        let blocktime = if n > 1 { optional_i64(d)? } else { None };
        let block_height = if n > 2 { optional_u64(d)? } else { None };
        for _ in 3..n {
            d.skip()?;
        }
        let mut value = Self {
            parent_slot,
            blocktime,
            block_height,
            block_markers: None,
            block_id: None,
            meta_len: n,
            raw_cbor: d.input()[start..d.position()].to_vec(),
        };
        // Validate only published outer field shapes. Unknown marker versions,
        // variants and payloads remain exact opaque bytes, including empty bytes.
        value.block_markers = match value.block_markers()? {
            FieldPresence::Value(markers) => {
                Some(markers.into_iter().map(<[u8]>::to_vec).collect())
            }
            FieldPresence::Absent | FieldPresence::Null => None,
        };
        value.block_id = match value.block_id()? {
            FieldPresence::Value(id) => Some(*id),
            FieldPresence::Absent | FieldPresence::Null => None,
        };
        Ok(value)
    }
}

impl<C> Encode<C> for SlotMeta {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
        _: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let original = Self::from_cbor(&self.raw_cbor)
            .map_err(|_| minicbor::encode::Error::message("invalid retained SlotMeta"))?;
        if (self.parent_slot, self.blocktime, self.block_height)
            != (
                original.parent_slot,
                original.blocktime,
                original.block_height,
            )
            || self.block_markers != original.block_markers
            || self.block_id != original.block_id
            || self.meta_len != original.meta_len
        {
            return Err(minicbor::encode::Error::message(
                "SlotMeta projection changed; cannot emit stale source bytes",
            ));
        }
        e.writer_mut()
            .write_all(&self.raw_cbor)
            .map_err(minicbor::encode::Error::write)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tuple(n: u64, tail: impl FnOnce(&mut Encoder<Vec<u8>>)) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(n).unwrap().u64(4).unwrap().i64(-2).unwrap();
        tail(&mut e);
        e.into_writer()
    }
    #[test]
    fn absent_null_and_empty_are_distinct_and_roundtrip() {
        let cases = [
            tuple(2, |_| {}),
            tuple(3, |e| {
                e.null().unwrap();
            }),
            tuple(4, |e| {
                e.null().unwrap().null().unwrap();
            }),
            tuple(4, |e| {
                e.null().unwrap().array(0).unwrap();
            }),
        ];
        for raw in &cases {
            let m = SlotMeta::from_cbor(raw).unwrap();
            assert_eq!(minicbor::to_vec(&m).unwrap(), *raw);
        }
        assert_eq!(
            SlotMeta::from_cbor(&cases[0]).unwrap().field(2).unwrap(),
            FieldPresence::Absent
        );
        assert_eq!(
            SlotMeta::from_cbor(&cases[1]).unwrap().field(2).unwrap(),
            FieldPresence::Null
        );
        assert_eq!(
            SlotMeta::from_cbor(&cases[2])
                .unwrap()
                .block_markers()
                .unwrap(),
            FieldPresence::Null
        );
        assert_eq!(
            SlotMeta::from_cbor(&cases[3])
                .unwrap()
                .block_markers()
                .unwrap(),
            FieldPresence::Value(vec![])
        );
    }
    #[test]
    fn all_marker_bytes_order_block_id_and_future_fields_survive() {
        let markers: Vec<Vec<u8>> = (0..4)
            .map(|v| vec![1, 0, v, 1, 0, 99])
            .chain([vec![254, 255, 251, 0, 0], vec![]])
            .collect();
        let raw = tuple(7, |e| {
            e.u64(7).unwrap().array(markers.len() as u64).unwrap();
            for m in &markers {
                e.bytes(m).unwrap();
            }
            e.bytes(&[42; 32])
                .unwrap()
                .map(1)
                .unwrap()
                .str("future")
                .unwrap()
                .array(2)
                .unwrap()
                .null()
                .unwrap()
                .bool(true)
                .unwrap()
                .bytes(&[255, 0])
                .unwrap();
        });
        let m = SlotMeta::from_cbor(&raw).unwrap();
        assert_eq!(
            m.block_markers().unwrap(),
            FieldPresence::Value(markers.iter().map(Vec::as_slice).collect())
        );
        assert_eq!(m.block_id().unwrap(), FieldPresence::Value(&[42; 32]));
        assert!(matches!(m.field(5).unwrap(), FieldPresence::Value(_)));
        assert_eq!(m.field(7).unwrap(), FieldPresence::Absent);
        assert_eq!(minicbor::to_vec(&m).unwrap(), raw);
    }
    #[test]
    fn serde_keeps_the_original_shape_and_restores_marker_projection() {
        let raw = tuple(5, |e| {
            e.null()
                .unwrap()
                .array(1)
                .unwrap()
                .bytes(&[1, 2, 3])
                .unwrap()
                .bytes(&[8; 32])
                .unwrap();
        });
        let meta = SlotMeta::from_cbor(&raw).unwrap();
        let value = serde_json::to_value(&meta).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 4);
        assert!(value.get("block_markers").is_none());
        let decoded: SlotMeta = serde_json::from_value(value).unwrap();
        assert_eq!(decoded, meta);
        assert_eq!(decoded.block_markers, Some(vec![vec![1, 2, 3]]));
        assert_eq!(decoded.block_id, Some([8; 32]));
        assert_eq!(decoded.meta_len, 5);
        assert_eq!(minicbor::to_vec(&decoded).unwrap(), raw);
    }

    #[test]
    fn changed_marker_projection_cannot_emit_stale_source_bytes() {
        let raw = tuple(5, |e| {
            e.null().unwrap().array(0).unwrap().bytes(&[8; 32]).unwrap();
        });
        let original = SlotMeta::from_cbor(&raw).unwrap();
        let mut changed = original.clone();
        changed.block_markers = None;
        assert!(minicbor::to_vec(changed).is_err());
        let mut changed = original.clone();
        changed.block_id = Some([9; 32]);
        assert!(minicbor::to_vec(changed).is_err());
        let mut changed = original;
        changed.meta_len = 3;
        assert!(minicbor::to_vec(changed).is_err());
    }

    #[test]
    fn invalid_known_shapes_and_changed_projection_fail() {
        for raw in [
            tuple(4, |e| {
                e.null().unwrap().bytes(&[1]).unwrap();
            }),
            tuple(5, |e| {
                e.null().unwrap().null().unwrap().bytes(&[0; 31]).unwrap();
            }),
        ] {
            assert!(SlotMeta::from_cbor(&raw).is_err());
        }
        let mut m = SlotMeta::from_cbor(&[0x82, 1, 2]).unwrap();
        m.parent_slot = Some(99);
        assert!(minicbor::to_vec(m).is_err());
        assert!(SlotMeta::from_cbor(&[0x82, 1, 2, 0]).is_err());
    }
}
