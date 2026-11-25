use anyhow::{Context, ensure};

use crate::{
    AdaptiveV3ResolvedPosting, Error, IndexerV3AddressTransactions, IndexerV3Archive, Result,
};

/// A borrowed transaction payload from the selected standalone V3 block.
pub use crate::standalone_v2::SemanticTransaction as IndexerV3AddressTransaction;

impl IndexerV3Archive {
    /// Visit the payloads for a bounded address lookup in ledger order.
    ///
    /// The callback receives the indexed account roles and the borrowed semantic
    /// fields for each match. The reader fetches each matched block's planes
    /// once for the selected transactions. The result includes the same
    /// locations, truncation flag, and coverage as
    /// [`Self::lookup_address_transactions`]. A zero limit only checks for
    /// indexed matches.
    ///
    /// Keep callback results only after a successful return. For local input,
    /// call [`Self::verify_local_unchanged`] before accepting the results.
    pub fn visit_address_transactions(
        &mut self,
        address: &[u8; 32],
        limit: usize,
        mut visit: impl FnMut(
            AdaptiveV3ResolvedPosting,
            IndexerV3AddressTransaction<'_>,
        ) -> anyhow::Result<()>,
    ) -> Result<IndexerV3AddressTransactions> {
        let lookup = self.lookup_address_transactions(address, limit)?;
        if lookup.matches.postings.is_empty() {
            return Ok(lookup);
        }

        let reader = self.adaptive_reader()?;
        let mut indexes = Vec::new();
        for block in lookup
            .matches
            .postings
            .chunk_by(|a, b| a.block_id == b.block_id)
        {
            let block_id = block[0].block_id;
            let ordinal = usize::try_from(block_id).map_err(|_| Error::SizeOverflow)?;
            indexes.clear();
            indexes.extend(block.iter().map(|posting| posting.tx_index));

            let mut expected = block.iter().copied();
            reader
                .visit_standalone_semantic_transactions(ordinal, Some(&indexes), |transaction| {
                    let posting = expected
                        .next()
                        .context("unexpected address transaction payload")?;
                    ensure!(
                        (transaction.block_id, transaction.tx_index)
                            == (posting.block_id, posting.tx_index),
                        "address posting position differs from transaction payload"
                    );
                    visit(posting, transaction)
                })
                .with_context(|| format!("visit address transactions in block {block_id}"))
                .map_err(Error::Reverse)?;
            if let Some(posting) = expected.next() {
                return Err(Error::Reverse(anyhow::anyhow!(
                    "missing address transaction payload for block {} transaction {}",
                    posting.block_id,
                    posting.tx_index
                )));
            }
        }
        Ok(lookup)
    }
}
