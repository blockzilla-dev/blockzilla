use anyhow::{Context, Result, bail, ensure};
use blockzilla_archive_v2::{WincodeArchiveV2Block, WincodeArchiveV2Payload};
use blockzilla_compact::{
    OwnedCompactInstruction, OwnedCompactMessage, OwnedCompactRecentBlockhash,
    OwnedCompactTransaction,
};
use blockzilla_compact_v2_reader::signed_message::{
    ResolvedAddressTableLookup, SignedInstruction, SignedMessage, SignedMessageVersion,
    SignedTransactionConfig, serialize_signed_message,
};
use blockzilla_primitives::{CompactPubkey, wincode_leb128_config};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_DECODED_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockSummary {
    pub slot: u64,
    pub parent_slot: u64,
    pub transactions: usize,
    pub signatures: usize,
    pub metadata_rows: usize,
    pub failed_transactions: usize,
    pub inner_instructions: usize,
    pub log_events: usize,
    pub signed_transactions_sha256: String,
}

pub fn sha256(bytes: &[u8]) -> String {
    hex_bytes(&Sha256::digest(bytes))
}

pub fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}

pub fn decode(bytes: &[u8]) -> Result<WincodeArchiveV2Block> {
    ensure!(
        bytes.len() <= MAX_DECODED_BYTES,
        "sample exceeds decoded size limit"
    );
    wincode::config::deserialize_exact(bytes, wincode_leb128_config())
        .context("decode Compact V2 sample")
}

pub fn summarize(block: &WincodeArchiveV2Block) -> Result<BlockSummary> {
    let mut result = BlockSummary {
        slot: block.header.compact.slot,
        parent_slot: block.header.compact.parent_slot,
        transactions: block.txs.len(),
        signatures: 0,
        metadata_rows: 0,
        failed_transactions: 0,
        inner_instructions: 0,
        log_events: 0,
        signed_transactions_sha256: String::new(),
    };
    let mut signed = Sha256::new();
    signed.update(b"BZ-SIGNED-TRANSACTIONS-V1");
    for (ordinal, row) in block.txs.iter().enumerate() {
        ensure!(
            row.tx_index as usize == ordinal,
            "sample transaction order mismatch"
        );
        let WincodeArchiveV2Payload::Decoded { value: tx, .. } = &row.tx else {
            bail!("sample contains an undecoded transaction");
        };
        result.signatures += tx.signatures.len();
        let wire = signed_transaction_bytes(tx)?;
        signed.update(row.tx_index.to_le_bytes());
        signed.update((wire.len() as u64).to_le_bytes());
        signed.update(wire);
        if let Some(meta) = &row.metadata {
            let WincodeArchiveV2Payload::Decoded { value, .. } = meta else {
                bail!("sample contains undecoded metadata");
            };
            result.metadata_rows += 1;
            result.failed_transactions += usize::from(value.err.is_some());
            result.inner_instructions += value.inner_instructions.as_ref().map_or(0, |groups| {
                groups.iter().map(|group| group.instructions.len()).sum()
            });
            result.log_events += value.logs.as_ref().map_or(0, |logs| logs.events.len());
        }
    }
    result.signed_transactions_sha256 = hex_bytes(&signed.finalize());
    Ok(result)
}

fn raw_key(key: &CompactPubkey) -> Result<[u8; 32]> {
    match key {
        CompactPubkey::Raw(value) => Ok(*value),
        _ => bail!("standalone sample requires inline public keys"),
    }
}

fn raw_hash(hash: &OwnedCompactRecentBlockhash) -> Result<[u8; 32]> {
    match hash {
        OwnedCompactRecentBlockhash::Nonce(value) => Ok(*value),
        OwnedCompactRecentBlockhash::Id(_) => {
            bail!("standalone sample requires inline recent hashes")
        }
    }
}

fn signed_transaction_bytes(tx: &OwnedCompactTransaction) -> Result<Vec<u8>> {
    let (header, keys, hash, instructions, lookups, config) = match &tx.message {
        OwnedCompactMessage::Legacy(message) => (
            message.header,
            &message.account_keys,
            &message.recent_blockhash,
            &message.instructions,
            None,
            None,
        ),
        OwnedCompactMessage::V0(message) => (
            message.header,
            &message.account_keys,
            &message.recent_blockhash,
            &message.instructions,
            Some(&message.address_table_lookups),
            None,
        ),
        OwnedCompactMessage::V1(message) => (
            message.header,
            &message.account_keys,
            &message.recent_blockhash,
            &message.instructions,
            None,
            Some(message.config),
        ),
    };
    let keys = keys.iter().map(raw_key).collect::<Result<Vec<_>>>()?;
    let instructions = instructions
        .iter()
        .map(|instruction: &OwnedCompactInstruction| SignedInstruction {
            program_id_index: instruction.program_id_index,
            accounts: &instruction.accounts,
            data: &instruction.data,
        })
        .collect::<Vec<_>>();
    let lookups = lookups
        .map(|lookups| {
            lookups
                .iter()
                .map(|lookup| {
                    Ok(ResolvedAddressTableLookup {
                        account_key: raw_key(&lookup.account_key)?,
                        writable_indexes: &lookup.writable_indexes,
                        readonly_indexes: &lookup.readonly_indexes,
                    })
                })
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?;
    let version = if let Some(config) = config {
        SignedMessageVersion::V1 {
            config: SignedTransactionConfig {
                priority_fee: config.priority_fee,
                compute_unit_limit: config.compute_unit_limit,
                loaded_accounts_data_size_limit: config.loaded_accounts_data_size_limit,
                heap_size: config.heap_size,
            },
        }
    } else if let Some(lookups) = &lookups {
        SignedMessageVersion::V0 {
            address_table_lookups: lookups,
        }
    } else {
        SignedMessageVersion::Legacy
    };
    let message = serialize_signed_message(&SignedMessage {
        version,
        header,
        static_account_keys: &keys,
        recent_blockhash: raw_hash(hash)?,
        instructions: &instructions,
    })?;
    let mut output = Vec::new();
    let mut signatures = u16::try_from(tx.signatures.len())?;
    loop {
        let byte = (signatures & 0x7f) as u8;
        signatures >>= 7;
        output.push(byte | if signatures > 0 { 0x80 } else { 0 });
        if signatures == 0 {
            break;
        }
    }
    for signature in &tx.signatures {
        ensure!(signature.len() == 64, "invalid sample signature length");
        output.extend_from_slice(signature);
    }
    output.extend(message);
    Ok(output)
}
