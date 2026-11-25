use anyhow::{Context, Result, bail};
use blockzilla_compact_v2_reader::{
    CompactV2ParallelScanConfig, NetworkInputConfig, S3Credentials, S3SigV4Signer,
    archive::{CompactV2Archive, CompactV2LocalDescriptor},
};
use blockzilla_model::{
    ArchiveInstructionSource, BlockSink, BlockView, Error, ExecutionStatus, RecordedTokenBalance,
    ScanRequest, TokenBalanceSide,
};
use clap::Parser;
use std::{
    io::{self, BufWriter, Write},
    num::NonZeroU32,
    path::PathBuf,
};

#[derive(Clone, Copy)]
pub enum Kind {
    Token,
    Wallet,
    Program,
}
#[derive(Parser)]
struct Args {
    /// Local Compact V2 epoch directory. Omit it when `--url` is set.
    archive: Option<PathBuf>,
    #[arg(long)]
    epoch: u64,
    /// Stable identifier of this immutable local archive generation.
    #[arg(long)]
    source_id: Option<String>,
    /// Stream a public HTTPS epoch directory instead of a local one, for
    /// example `https://archive.example/compact-v2/build/epoch-200`.
    #[arg(long)]
    url: Option<String>,
    /// Private cache directory for the network reader's control files.
    #[arg(long, requires = "url")]
    cache_dir: Option<PathBuf>,
    /// Sign requests for a private S3-compatible bucket in this region (`auto`
    /// for Cloudflare R2). Credentials come from AWS_ACCESS_KEY_ID,
    /// AWS_SECRET_ACCESS_KEY and the optional AWS_SESSION_TOKEN.
    #[arg(long, requires = "url")]
    s3_region: Option<String>,
    /// First block row of the scan.
    #[arg(long, default_value_t = 0)]
    first_block: u32,
    /// Maximum number of block rows to scan.
    #[arg(long)]
    max_blocks: Option<NonZeroU32>,
    /// Token mint, required signer, or invoked program in base58.
    #[arg(long)]
    key: Option<String>,
    /// Parallel decode workers. The default is the number of logical CPUs.
    /// 0 selects the sequential reader.
    #[arg(long)]
    workers: Option<usize>,
    /// Concurrent HTTPS range requests for a network archive.
    #[arg(long, requires = "url")]
    http_requests: Option<usize>,
    /// Target size of one HTTPS range request, in MiB.
    #[arg(long, requires = "url")]
    http_range_mib: Option<usize>,
    /// Concurrent block reads for a local archive. Use several on a NAS or
    /// disk array; 1 reads one range at a time.
    #[arg(long, default_value_t = 1, conflicts_with = "url")]
    read_concurrency: usize,
    /// Print the scan receipt with pipeline timings to standard error.
    #[arg(long)]
    stats: bool,
}

/// Output buffer for standard output. Rows are flushed once per block, so
/// output still streams while a scan runs, without one write call per row.
const OUTPUT_BUFFER_BYTES: usize = 1 << 20;

/// The rows that one dump prints for each block.
#[derive(Clone, Copy)]
struct Rows {
    kind: Kind,
    key: Option<[u8; 32]>,
}

impl Rows {
    /// Append the rows of one block to `out`.
    fn block(&self, block: &BlockView<'_>, out: &mut Vec<u8>) {
        let slot = block.header.slot;
        for tx in block.transaction_views() {
            match self.kind {
                Kind::Token => {
                    for row in tx.token_balances {
                        // The scan request already selects the mint. Keep the
                        // check so a source without mint selection prints the
                        // same rows. Rows with an unknown mint stay visible.
                        if self.key.is_some() && row.mint.is_some() && row.mint != self.key {
                            continue;
                        }
                        token_row(out, slot, tx.header.tx_index, tx.header.status, row);
                    }
                }
                Kind::Wallet | Kind::Program => {
                    let key = self.key.expect("validated before scan");
                    let matched = match self.kind {
                        Kind::Wallet => tx.required_signers.contains(&key),
                        Kind::Program => {
                            tx.instructions.iter().any(|ix| ix.program_id == Some(key))
                        }
                        Kind::Token => unreachable!(),
                    };
                    if matched {
                        transaction_row(
                            out,
                            slot,
                            tx.header.tx_index,
                            tx.header.status,
                            tx.primary_signature,
                        );
                    }
                }
            }
        }
    }
}

fn number(out: &mut Vec<u8>, value: impl itoa::Integer) {
    out.extend_from_slice(itoa::Buffer::new().format(value).as_bytes());
}

/// A JSON string with the base58 key, or `null`.
fn key_32(out: &mut Vec<u8>, key: Option<&[u8; 32]>) {
    let Some(key) = key else {
        out.extend_from_slice(b"null");
        return;
    };
    let mut text = [0u8; five8::BASE58_ENCODED_32_MAX_LEN];
    let length = usize::from(five8::encode_32(key, &mut text));
    out.push(b'"');
    out.extend_from_slice(&text[..length]);
    out.push(b'"');
}

fn key_64(out: &mut Vec<u8>, key: Option<&[u8; 64]>) {
    let Some(key) = key else {
        out.extend_from_slice(b"null");
        return;
    };
    let mut text = [0u8; five8::BASE58_ENCODED_64_MAX_LEN];
    let length = usize::from(five8::encode_64(key, &mut text));
    out.push(b'"');
    out.extend_from_slice(&text[..length]);
    out.push(b'"');
}

/// The JSON string of `format!("{status:?}")`, as the example has always
/// printed it.
fn status(out: &mut Vec<u8>, status: ExecutionStatus) {
    match status {
        ExecutionStatus::Succeeded => out.extend_from_slice(b"\"Succeeded\""),
        ExecutionStatus::Failed => out.extend_from_slice(b"\"Failed\""),
        unknown => serde_json::to_writer(&mut *out, &format!("{unknown:?}"))
            .expect("a string serializes into a Vec"),
    }
}

/// One token balance row. Keys are in the sorted order that a
/// `serde_json::json!` object prints, so the bytes equal the earlier output.
fn token_row(
    out: &mut Vec<u8>,
    slot: u64,
    tx_index: u32,
    execution: ExecutionStatus,
    row: &RecordedTokenBalance,
) {
    out.extend_from_slice(b"{\"account_index\":");
    number(out, row.account_index);
    out.extend_from_slice(b",\"amount\":\"");
    number(out, row.amount);
    out.extend_from_slice(b"\",\"decimals\":");
    number(out, row.decimals);
    out.extend_from_slice(b",\"mint\":");
    key_32(out, row.mint.as_ref());
    out.extend_from_slice(b",\"owner\":");
    key_32(out, row.owner.as_ref());
    out.extend_from_slice(match row.side {
        TokenBalanceSide::Pre => b",\"side\":\"Pre\",\"slot\":",
        TokenBalanceSide::Post => b",\"side\":\"Post\",\"slot\":",
    });
    number(out, slot);
    out.extend_from_slice(b",\"status\":");
    status(out, execution);
    out.extend_from_slice(b",\"tx_index\":");
    number(out, tx_index);
    out.extend_from_slice(b"}\n");
}

fn transaction_row(
    out: &mut Vec<u8>,
    slot: u64,
    tx_index: u32,
    execution: ExecutionStatus,
    signature: Option<&[u8; 64]>,
) {
    out.extend_from_slice(b"{\"signature\":");
    key_64(out, signature);
    out.extend_from_slice(b",\"slot\":");
    number(out, slot);
    out.extend_from_slice(b",\"status\":");
    status(out, execution);
    out.extend_from_slice(b",\"tx_index\":");
    number(out, tx_index);
    out.extend_from_slice(b"}\n");
}

/// Writes each block's rows with one call, then flushes, so output still
/// streams block by block without one write call per row.
struct Sink<W> {
    rows: Rows,
    output: W,
    scratch: Vec<u8>,
}

impl<W: Write> BlockSink for Sink<W> {
    fn visit_block(&mut self, block: BlockView<'_>) -> blockzilla_model::Result<()> {
        self.scratch.clear();
        self.rows.block(&block, &mut self.scratch);
        self.output.write_all(&self.scratch).map_err(Error::sink)?;
        self.output.flush().map_err(Error::sink)
    }
}

pub fn run(kind: Kind) -> Result<()> {
    let args = Args::parse();
    let key = args
        .key
        .map(|value| -> Result<[u8; 32]> {
            bs58::decode(value)
                .into_vec()?
                .try_into()
                .map_err(|_| anyhow::anyhow!("key must contain 32 bytes"))
        })
        .transpose()?;
    if !matches!(kind, Kind::Token) {
        anyhow::ensure!(key.is_some(), "--key is required");
    }
    let local = args.archive.is_some();
    let mut archive = match (args.archive, args.url) {
        (Some(directory), None) => CompactV2Archive::open_local_with_read_concurrency(
            &directory,
            CompactV2LocalDescriptor::mainnet(
                args.epoch,
                args.source_id
                    .context("--source-id is required for a local archive")?,
            )?,
            args.read_concurrency,
        )?,
        (None, Some(url)) => {
            let cache_dir = args
                .cache_dir
                .context("--cache-dir is required with --url")?;
            match args.s3_region {
                Some(region) => {
                    let signer = S3SigV4Signer::new(S3Credentials::from_env()?, region)?;
                    CompactV2Archive::open_signed_epoch_url(
                        &url,
                        args.epoch,
                        cache_dir,
                        std::sync::Arc::new(signer),
                    )?
                }
                None => CompactV2Archive::open_epoch_url(&url, args.epoch, cache_dir)?,
            }
        }
        _ => bail!("give either a local ARCHIVE directory or --url, not both"),
    };
    let mut request = match kind {
        // Token rows print no signature and no signer, so the request reads
        // neither. With a mint, the reader skips other rows before it
        // resolves their owner and token program. Unknown mints stay selected.
        Kind::Token => match key {
            Some(mint) => ScanRequest::token_balances_only().with_token_balances_for([mint]),
            None => ScanRequest::token_balances_only(),
        },
        // The reader keeps only the selected signer in each signer list, so
        // it does not resolve every other signer key.
        Kind::Wallet => ScanRequest::all()
            .without_instructions()
            .with_required_signer(key.expect("validated above")),
        // Program identities are enough to find a call; instruction data and
        // account lists are not printed. A signature is read only for a
        // transaction that calls the program. Complete CPI stays required.
        Kind::Program => {
            let mut request = ScanRequest::all()
                .with_instruction_programs_for([key.expect("validated above")])
                .with_selected_primary_signatures();
            request.require_complete_cpi = true;
            request
        }
    };
    if args.first_block != 0 || args.max_blocks.is_some() {
        request.range = Some(
            archive.bounded_range(args.first_block, args.max_blocks.unwrap_or(NonZeroU32::MAX))?,
        );
    }
    let workers = match args.workers {
        Some(workers) => workers,
        None => std::thread::available_parallelism().map_or(1, usize::from),
    };
    let mut sink = Sink {
        rows: Rows { kind, key },
        output: BufWriter::with_capacity(OUTPUT_BUFFER_BYTES, io::stdout().lock()),
        scratch: Vec::new(),
    };
    // The parallel reader serves requests without instruction payload bytes,
    // which holds for all three dumps.
    if workers > 0 {
        let mut config = CompactV2ParallelScanConfig::new(workers);
        if let Some(input) = config.network_input.as_mut() {
            let defaults = NetworkInputConfig::default();
            // The source hint only turns on concurrent input; the input
            // window sets how many reads are in flight.
            input.workers = match args.http_requests {
                Some(requests) => requests,
                None if local && args.read_concurrency > 1 => args.read_concurrency,
                None => defaults.workers,
            };
            input.range_bytes = args
                .http_range_mib
                .map_or(defaults.range_bytes, |mib| mib << 20);
        }
        let receipt = if request.include_primary_signatures {
            // Signatures are assigned on the ordered thread, so dumps that
            // print them use the plain parallel scan.
            archive.scan_ordered_parallel(&request, &mut sink, config)
        } else {
            // The workers format each block's rows; the ordered thread only
            // writes the bytes. This keeps the single ordered thread small.
            let rows = sink.rows;
            let output = &mut sink.output;
            archive.scan_ordered_parallel_map(
                &request,
                config,
                move |block| {
                    let mut bytes = Vec::new();
                    rows.block(&block, &mut bytes);
                    Ok(bytes)
                },
                |bytes: Vec<u8>| {
                    output.write_all(&bytes).map_err(Error::sink)?;
                    output.flush().map_err(Error::sink)
                },
            )
        }
        .context("archive scan did not complete")?;
        if args.stats {
            eprintln!("{receipt:#?}");
            eprintln!("limiting stage: {}", receipt.limiting_stage());
        }
    } else {
        let receipt = archive
            .scan_ordered(&request, &mut sink)
            .context("archive scan did not complete")?;
        if args.stats {
            eprintln!("{receipt:#?}");
        }
    }
    sink.output.flush().context("flush output")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use blockzilla_model::CoverageReason;
    use serde_json::json;

    /// The JSON the example printed before the hand-written writer.
    fn reference_token_row(
        slot: u64,
        tx_index: u32,
        status: ExecutionStatus,
        row: &RecordedTokenBalance,
    ) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(&json!({
            "slot": slot, "tx_index": tx_index,
            "status": format!("{:?}", status),
            "side": format!("{:?}", row.side), "account_index": row.account_index,
            "mint": row.mint.map(|v| bs58::encode(v).into_string()),
            "owner": row.owner.map(|v| bs58::encode(v).into_string()),
            "amount": row.amount.to_string(), "decimals": row.decimals
        }))
        .unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn reference_transaction_row(
        slot: u64,
        tx_index: u32,
        status: ExecutionStatus,
        signature: Option<&[u8; 64]>,
    ) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(&json!({
            "slot": slot, "tx_index": tx_index,
            "status": format!("{:?}", status),
            "signature": signature.map(|v| bs58::encode(v).into_string())
        }))
        .unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn statuses() -> Vec<ExecutionStatus> {
        let reasons = [
            CoverageReason::MetadataAbsent,
            CoverageReason::RawTransaction,
            CoverageReason::RawMetadata,
            CoverageReason::InvalidReference,
            CoverageReason::AmbiguousInstructionData,
            CoverageReason::InstructionDataUnavailable,
            CoverageReason::ProjectionNotRequested,
            CoverageReason::UnsupportedInstruction,
            CoverageReason::SourceUnverified,
            CoverageReason::NonContiguousHistory,
            CoverageReason::Other,
        ];
        [ExecutionStatus::Succeeded, ExecutionStatus::Failed]
            .into_iter()
            .chain(reasons.into_iter().map(ExecutionStatus::Unknown))
            .collect()
    }

    fn keys() -> Vec<[u8; 32]> {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut keys = vec![[0; 32], [0xff; 32], {
            let mut key = [0; 32];
            key[31] = 1;
            key
        }];
        for _ in 0..200 {
            let mut key = [0; 32];
            for byte in &mut key {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            // Leading zero bytes become leading '1' characters in base58.
            let zeros = (state % 4) as usize;
            key[..zeros].fill(0);
            keys.push(key);
        }
        keys
    }

    #[test]
    fn token_rows_match_the_json_macro_output_byte_for_byte() {
        let keys = keys();
        let mut output = Vec::new();
        let mut expected = Vec::new();
        for (index, status) in statuses().into_iter().enumerate() {
            for (position, key) in keys.iter().enumerate() {
                let row = RecordedTokenBalance {
                    side: if position % 2 == 0 {
                        TokenBalanceSide::Pre
                    } else {
                        TokenBalanceSide::Post
                    },
                    balance_index: position as u32,
                    account_index: [0, 1, 255, u32::MAX][position % 4],
                    mint: (position % 5 != 0).then_some(*key),
                    owner: (position % 3 != 0).then(|| keys[(position + 7) % keys.len()]),
                    token_program: None,
                    amount: [0, 1, 10, u64::MAX, 1_000_000_007][position % 5],
                    decimals: [0, 6, 9, u8::MAX][position % 4],
                };
                let slot = [0, 86_604_091, u64::MAX][index % 3];
                let tx_index = [0, 72, u32::MAX][position % 3];
                expected.extend(reference_token_row(slot, tx_index, status, &row));
                token_row(&mut output, slot, tx_index, status, &row);
            }
        }
        assert_eq!(
            String::from_utf8(output).unwrap(),
            String::from_utf8(expected).unwrap()
        );
    }

    #[test]
    fn transaction_rows_match_the_json_macro_output_byte_for_byte() {
        let keys = keys();
        let mut output = Vec::new();
        let mut expected = Vec::new();
        for status in statuses() {
            for pair in keys.chunks_exact(2) {
                let mut signature = [0u8; 64];
                signature[..32].copy_from_slice(&pair[0]);
                signature[32..].copy_from_slice(&pair[1]);
                for signature in [Some(&signature), None] {
                    expected.extend(reference_transaction_row(7, 3, status, signature));
                    transaction_row(&mut output, 7, 3, status, signature);
                }
            }
        }
        assert_eq!(
            String::from_utf8(output).unwrap(),
            String::from_utf8(expected).unwrap()
        );
    }
}
