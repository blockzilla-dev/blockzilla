use crate::{ArchiveReader, BlockhashResolver, DecodedBlock, Error, RangeSource, Result};

/// One archive block with resolved identity fields for canonical recovery.
#[derive(Debug)]
pub struct FinalizedArchiveBlock {
    pub decoded: DecodedBlock,
    pub blockhash: [u8; 32],
    /// Absent only for a block at slot zero.
    pub parent_blockhash: Option<[u8; 32]>,
    pub block_height: u64,
}

impl<S: RangeSource> ArchiveReader<S> {
    /// Read the block at `slot` and require its resolved hash to match.
    ///
    /// The caller must pin a verified canonical archive generation, its
    /// blockhash resolver sidecars, and the requested block identity. Compare
    /// the returned parent and height with the trusted chain before applying
    /// the block. This method does not establish finality or supply a native
    /// stream cursor.
    ///
    /// `Ok(None)` means the slot has no row in this generation. It does not
    /// establish that the slot was skipped.
    pub fn read_finalized_block(
        &self,
        slot: u64,
        expected_blockhash: [u8; 32],
        blockhashes: &BlockhashResolver,
    ) -> Result<Option<FinalizedArchiveBlock>> {
        let Ok(row) = self
            .index()
            .rows
            .binary_search_by_key(&slot, |row| row.slot)
        else {
            return Ok(None);
        };
        let decoded = self.read_block(row)?;
        let header = &decoded.block.header;
        let invalid = |message| Error::InvalidBlock { slot, message };
        let blockhash_id = i32::try_from(header.blockhash_id)
            .map_err(|_| invalid("blockhash ID is out of range".into()))?;
        let blockhash = blockhashes
            .resolve(blockhash_id)
            .map_err(|error| invalid(format!("cannot resolve blockhash: {error}")))?;
        if blockhash != expected_blockhash {
            return Err(invalid(
                "blockhash does not match the requested block".into(),
            ));
        }
        let block_height = header
            .block_height
            .ok_or_else(|| invalid("block height is unavailable".into()))?;
        let parent_blockhash = if slot == 0 {
            if header.parent_slot != 0 || header.previous_blockhash_id != 0 {
                return Err(invalid("slot zero has an invalid parent reference".into()));
            }
            None
        } else {
            if header.parent_slot >= slot {
                return Err(invalid("parent slot is not before the block".into()));
            }
            Some(
                blockhashes
                    .resolve_header_previous(header.blockhash_id, header.previous_blockhash_id)
                    .map_err(|error| {
                        invalid(format!("cannot resolve parent blockhash: {error}"))
                    })?,
            )
        };
        Ok(Some(FinalizedArchiveBlock {
            decoded,
            blockhash,
            parent_blockhash,
            block_height,
        }))
    }
}
