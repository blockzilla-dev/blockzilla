//! Read blocks from the public Foundation Compact V2 archive.
//!
//! Run from the workspace root:
//! cargo run --locked -p blockzilla-compact-v2-reader --features http \
//!   --example read_epoch -- <epoch> <max-blocks>
//!
//! The default epoch is 200. Its directory is on the public Foundation bucket.

use std::{error::Error, num::NonZeroU32};

use blockzilla_compact_v2_reader::archive::{
    ArchiveInstructionSourceExt, CompactV2Archive, ExecutionStatus, ScanRequest,
};
use solana_signature::Signature;

const ARCHIVE_BASE: &str =
    "https://pub-97348740d6ef467aa2f1b4b62daa98dc.r2.dev/compact-v2/blockzilla-20261004";

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let epoch: u64 = args.next().as_deref().unwrap_or("200").parse()?;
    let max_blocks: u32 = args.next().as_deref().unwrap_or("10").parse()?;
    let max_blocks = NonZeroU32::new(max_blocks).ok_or("max-blocks must be at least 1")?;

    // START read-epoch
    let cache = std::env::current_dir()?.join(".blockzilla-cache");
    let epoch_url = format!("{ARCHIVE_BASE}/epoch-{epoch}");
    let mut archive = CompactV2Archive::open_epoch_url(&epoch_url, epoch, &cache)?;

    let range = archive.bounded_range(0, max_blocks)?;
    let request = ScanRequest::bounded(range);

    let receipt = archive.for_each_block(&request, |block| {
        for tx in block.transaction_views() {
            let status = match tx.header.status {
                ExecutionStatus::Succeeded => "ok",
                ExecutionStatus::Failed => "failed",
                ExecutionStatus::Unknown(_) => "unknown",
            };
            let signature = tx
                .primary_signature
                .map(|bytes| Signature::from(*bytes).to_string())
                .unwrap_or_default();
            println!(
                "slot={} tx={} {status} instructions={} {signature}",
                block.header.slot,
                tx.header.tx_index,
                tx.instructions.len(),
            );
        }
        Ok(())
    })?;

    eprintln!(
        "Read {} blocks and {} transactions",
        receipt.blocks, receipt.transactions,
    );
    // END read-epoch
    Ok(())
}
