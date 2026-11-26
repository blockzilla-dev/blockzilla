//! Worker-owned output storage. Recycle once per block, not through a lock per row.
use crate::{CanonicalBlock, RecordedTokenBalance, ResolvedInstruction};

const MAX_RETAINED_BYTES: usize = 8 << 20;
const MAX_BUFFERS: usize = 16_384;
// Token metadata can contain 256 rows per side. The final class also holds
// larger buffers supplied by callers of the public projection API.
const BALANCE_SIZE_CLASSES: usize = 10;

#[derive(Debug, Default)]
pub struct ProjectionPool {
    instructions: Vec<Vec<ResolvedInstruction>>,
    balances: [Vec<Vec<RecordedTokenBalance>>; BALANCE_SIZE_CLASSES],
    balance_buffers: usize,
    data: Vec<Vec<u8>>,
    accounts: Vec<Vec<[u8; 32]>>,
    bytes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BlockHeader, CanonicalTransaction, CoverageReason, CpiCoverage, ExecutionStatus,
        InstructionCoordinate, InstructionCoverage, InstructionDataCoverage, TokenBalanceCoverage,
        TransactionHeader,
    };

    #[test]
    fn balance_buffer_reuse_skips_an_undersized_buffer() {
        let mut pool = ProjectionPool::default();
        let small = Vec::with_capacity(4);
        let large = Vec::with_capacity(32);
        let small_ptr = small.as_ptr();
        let large_ptr = large.as_ptr();
        pool.bytes = (small.capacity() + large.capacity()) * size_of::<RecordedTokenBalance>();
        pool.balance_buffers = 2;
        pool.balances[balance_size_class(small.capacity())].push(small);
        pool.balances[balance_size_class(large.capacity())].push(large);

        let larger_request = pool.balances_with_capacity(25).unwrap();
        let smaller_request = pool.balances_with_capacity(3).unwrap();
        assert_eq!(larger_request.as_ptr(), large_ptr);
        assert_eq!(smaller_request.as_ptr(), small_ptr);
        assert_eq!(pool.bytes, 0);
        assert_eq!(pool.balance_buffers, 0);
    }

    #[test]
    fn retains_nested_buffers_without_retaining_old_values() {
        let mut pool = ProjectionPool::default();
        let data = vec![7; 128];
        let data_ptr = data.as_ptr();
        let accounts = vec![[8; 32]; 4];
        let account_ptr = accounts.as_ptr();
        let mut block = CanonicalBlock {
            header: BlockHeader {
                epoch: 0,
                block_ordinal: 0,
                slot: 0,
            },
            counts: None,
            transactions: vec![CanonicalTransaction {
                header: TransactionHeader {
                    tx_index: 0,
                    status: ExecutionStatus::Unknown(CoverageReason::MetadataAbsent),
                    failed_outer_instruction_index: None,
                    instruction_coverage: InstructionCoverage::Complete,
                    cpi_coverage: CpiCoverage::Complete,
                },
                primary_signature: None,
                required_signers: Vec::new(),
                instructions: vec![ResolvedInstruction {
                    coordinate: InstructionCoordinate {
                        order: 0,
                        outer_index: 0,
                        inner_index: None,
                        stack_height: None,
                    },
                    program_id: None,
                    accounts,
                    data,
                    data_coverage: InstructionDataCoverage::Exact,
                }],
                token_balance_coverage: TokenBalanceCoverage::NotRequested,
                token_balances: Vec::new(),
            }],
        };
        pool.recycle_block(&mut block);
        let reused_data = pool.copy_data(&[9; 64]).unwrap();
        assert_eq!(reused_data.as_ptr(), data_ptr);
        assert_eq!(reused_data, [9; 64]);
        let reused_accounts = pool.accounts();
        assert_eq!(reused_accounts.as_ptr(), account_ptr);
        assert!(reused_accounts.is_empty());
        assert!(pool.bytes <= MAX_RETAINED_BYTES);
    }
}

impl ProjectionPool {
    /// Copy once into retained output storage. Output can outlive the decode buffer.
    pub fn copy_data(
        &mut self,
        bytes: &[u8],
    ) -> Result<Vec<u8>, std::collections::TryReserveError> {
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        let mut value = self.data.pop().unwrap_or_default();
        self.bytes -= value.capacity();
        value.try_reserve(bytes.len())?;
        value.extend_from_slice(bytes);
        Ok(value)
    }

    pub fn accounts(&mut self) -> Vec<[u8; 32]> {
        let value = self.accounts.pop().unwrap_or_default();
        self.bytes -= value.capacity() * size_of::<[u8; 32]>();
        value
    }

    pub fn instructions(&mut self) -> Vec<ResolvedInstruction> {
        let value = self.instructions.pop().unwrap_or_default();
        self.bytes -= value.capacity() * size_of::<ResolvedInstruction>();
        value
    }

    pub fn balances(&mut self) -> Vec<RecordedTokenBalance> {
        self.take_balance_buffer(0).unwrap_or_default()
    }

    /// Prefer a recycled buffer that fits the complete transaction. This
    /// avoids growing a small buffer while a larger one waits in the pool.
    pub fn balances_with_capacity(
        &mut self,
        minimum_capacity: usize,
    ) -> Result<Vec<RecordedTokenBalance>, std::collections::TryReserveError> {
        let capacity = minimum_capacity
            .checked_next_power_of_two()
            .unwrap_or(minimum_capacity);
        let mut value = self
            .take_balance_buffer(balance_size_class(capacity))
            .unwrap_or_default();
        value.try_reserve_exact(capacity)?;
        Ok(value)
    }

    fn take_balance_buffer(&mut self, first_class: usize) -> Option<Vec<RecordedTokenBalance>> {
        let value = self.balances[first_class..].iter_mut().find_map(Vec::pop)?;
        self.balance_buffers -= 1;
        self.bytes -= value.capacity() * size_of::<RecordedTokenBalance>();
        Some(value)
    }

    pub fn recycle_block(&mut self, block: &mut CanonicalBlock) {
        for mut transaction in block.transactions.drain(..) {
            for mut instruction in transaction.instructions.drain(..) {
                instruction.data.clear();
                let bytes = instruction.data.capacity();
                if bytes != 0
                    && bytes <= MAX_RETAINED_BYTES.saturating_sub(self.bytes)
                    && self.data.len() < MAX_BUFFERS
                {
                    self.bytes += bytes;
                    self.data.push(instruction.data);
                }
                instruction.accounts.clear();
                let bytes = instruction.accounts.capacity() * size_of::<[u8; 32]>();
                if bytes != 0
                    && bytes <= MAX_RETAINED_BYTES.saturating_sub(self.bytes)
                    && self.accounts.len() < MAX_BUFFERS
                {
                    self.bytes += bytes;
                    self.accounts.push(instruction.accounts);
                }
            }
            let bytes = transaction.instructions.capacity() * size_of::<ResolvedInstruction>();
            if bytes != 0
                && bytes <= MAX_RETAINED_BYTES.saturating_sub(self.bytes)
                && self.instructions.len() < MAX_BUFFERS
            {
                self.bytes += bytes;
                self.instructions.push(transaction.instructions);
            }
            transaction.token_balances.clear();
            let bytes = transaction.token_balances.capacity() * size_of::<RecordedTokenBalance>();
            if bytes != 0
                && bytes <= MAX_RETAINED_BYTES.saturating_sub(self.bytes)
                && self.balance_buffers < MAX_BUFFERS
            {
                self.bytes += bytes;
                self.balance_buffers += 1;
                let class = balance_size_class(transaction.token_balances.capacity());
                self.balances[class].push(transaction.token_balances);
            }
        }
    }
}

fn balance_size_class(capacity: usize) -> usize {
    (capacity.max(1).ilog2() as usize).min(BALANCE_SIZE_CLASSES - 1)
}
