//! Application block identity within a pinned genesis. Native source cursors
//! still identify individual transport events.
use crate::{BankIdentity, SAFE, hash};
use anyhow::{Context, Result, ensure};
use std::{fmt, str::FromStr};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct BlockId {
    pub slot: u64,
    pub blockhash: [u8; 32],
}

impl From<&BankIdentity> for BlockId {
    fn from(bank: &BankIdentity) -> Self {
        Self {
            slot: bank.slot,
            blockhash: bank.blockhash,
        }
    }
}

impl fmt::Display for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}",
            self.slot,
            bs58::encode(self.blockhash).into_string()
        )
    }
}

impl FromStr for BlockId {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let (slot, blockhash) = value.split_once(':').context("invalid_block_id")?;
        ensure!(
            slot.len() <= 16 && (32..=44).contains(&blockhash.len()),
            "invalid_block_id"
        );
        let number: u64 = slot.parse().context("invalid_block_id")?;
        ensure!(
            number <= SAFE && number.to_string() == slot,
            "invalid_block_id"
        );
        Ok(Self {
            slot: number,
            blockhash: hash(blockhash).context("invalid_block_id")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_canonical_bounded_block_ids_parse() {
        let id = BlockId {
            slot: SAFE,
            blockhash: [0; 32],
        };
        assert_eq!(id.to_string().parse::<BlockId>().unwrap(), id);
        let encoded = bs58::encode(id.blockhash).into_string();
        for invalid in [
            format!("{}:{encoded}", SAFE + 1),
            format!("01:{encoded}"),
            format!("+1:{encoded}"),
            format!("1:{encoded}:extra"),
            format!("1:1{encoded}"),
            "1:0".into(),
        ] {
            assert!(invalid.parse::<BlockId>().is_err(), "{invalid}");
        }
    }
}
