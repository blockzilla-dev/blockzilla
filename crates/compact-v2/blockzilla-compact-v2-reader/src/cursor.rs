use std::ops::Range;

use blockzilla_archive_v2::ArchiveV2HotBlockIndexRow;

use crate::{
    Error, Result,
    reader::{
        ArchiveReader, BorrowedBlockStream, BorrowedBlockStreamIoStats, BorrowedDecodedBlock,
        RecycledBlockScratch, RecycledBlockStats,
    },
    source::RangeSource,
};

/// A decoded block and its absolute position in the archive index.
#[derive(Debug)]
pub struct CursorBlock<'a> {
    pub row: usize,
    pub block: BorrowedDecodedBlock<'a>,
}

/// Accumulated measurements for both cursor read paths.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BlockCursorIoStats {
    pub sequential: BorrowedBlockStreamIoStats,
    pub sparse: RecycledBlockStats,
}

/// A forward, seekable cursor over a bounded range of archive index rows.
///
/// The cursor reuses its buffers. A returned block must be dropped before the next
/// cursor operation. Current-schema blocks omit rewards. Historical schemas use the
/// reader's owned compatibility decoder.
pub struct BlockCursor<'a, S> {
    reader: &'a ArchiveReader<S>,
    range: Range<usize>,
    next: usize,
    stream: BorrowedBlockStream<'a, S>,
    scratch: RecycledBlockScratch,
}

impl<'a, S: RangeSource> BlockCursor<'a, S> {
    pub(crate) fn new(reader: &'a ArchiveReader<S>, range: Range<usize>) -> Result<Self> {
        let stream = reader.borrowed_blocks_without_rewards_range(range.clone())?;
        Ok(Self {
            reader,
            next: range.start,
            range,
            stream,
            scratch: RecycledBlockScratch::new(),
        })
    }

    /// Return the next absolute row, or the end of the range at EOF.
    pub const fn next_row(&self) -> usize {
        self.next
    }

    /// Return read measurements since construction, including reads made before a seek.
    pub fn io_stats(&self) -> BlockCursorIoStats {
        BlockCursorIoStats {
            sequential: self.stream.io_stats(),
            sparse: self.scratch.stats(),
        }
    }

    /// Set the next row by absolute position. The end of the range is valid and marks EOF.
    pub fn seek_row(&mut self, row: usize) -> Result<()> {
        if row < self.range.start || row > self.range.end {
            return Err(Error::InvalidIndex(format!(
                "cursor row {row} is outside {}..={}",
                self.range.start, self.range.end,
            )));
        }
        self.next = row;
        Ok(())
    }

    /// Set and return the first row in the range with a slot at or above `slot`.
    /// Return the end of the range if there is no such row. This only uses the index.
    pub fn seek_slot(&mut self, slot: u64) -> usize {
        let rows = &self.reader.index().rows[self.range.clone()];
        self.next = self.range.start + rows.partition_point(|row| row.slot < slot);
        self.next
    }

    /// Read the next row using coalesced reads. A read or decode error leaves the position intact.
    pub fn next_block(&mut self) -> Result<Option<CursorBlock<'_>>> {
        let row = self.next;
        self.stream.seek_row(row);
        let Some(block) = self.stream.next_block().transpose()? else {
            return Ok(None);
        };
        self.next = row + 1;
        Ok(Some(CursorBlock { row, block }))
    }

    /// Discover facts in the next block, then process the same decoded bytes with those facts.
    ///
    /// `discover` runs before `process`. Neither callback runs at EOF, and a discovery error
    /// prevents processing. A callback error leaves the cursor at the original row. Keep
    /// discovery free of durable side effects and make processing safe to retry.
    pub fn next_block_with_discovery<D, T, E>(
        &mut self,
        discover: impl FnOnce(&CursorBlock<'_>) -> std::result::Result<D, E>,
        process: impl FnOnce(&CursorBlock<'_>, D) -> std::result::Result<T, E>,
    ) -> std::result::Result<Option<T>, E>
    where
        E: From<Error>,
    {
        let row = self.next;
        let Some(block) = self.next_block()? else {
            return Ok(None);
        };
        let result = discover(&block).and_then(|facts| process(&block, facts));
        if result.is_err() {
            self.next = row;
        }
        result.map(Some)
    }

    /// Find the next index row that satisfies `predicate` and read its block.
    ///
    /// This uses one exact block read for a match. The predicate can run again for the same rows
    /// if the caller retries after a read or decode error. If no rows match, the cursor moves to EOF.
    pub fn next_matching_block(
        &mut self,
        predicate: impl FnMut(&ArchiveV2HotBlockIndexRow) -> bool,
    ) -> Result<Option<CursorBlock<'_>>> {
        let rows = &self.reader.index().rows[self.next..self.range.end];
        let Some(offset) = rows.iter().position(predicate) else {
            self.next = self.range.end;
            return Ok(None);
        };
        let row = self.next + offset;
        let block = self
            .reader
            .read_borrowed_block_reusing(row, &mut self.scratch, true)?;
        self.next = row + 1;
        Ok(Some(CursorBlock { row, block }))
    }
}
