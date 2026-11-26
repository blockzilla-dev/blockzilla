//! Small, strict token-balance export example for the common reader API.

use std::{
    io::{self, BufWriter, Write},
    num::NonZeroU32,
    path::PathBuf,
    time::Instant,
};

use anyhow::{Context, Result};
use blockzilla_compact_v2_reader::archive::{
    ArchiveInstructionSource, BlockSink, BlockView, CompactV2Archive, CompactV2LocalDescriptor,
    CompactV2ParallelScanConfig, QueryError, QueryResult, ScanRequest,
};
use blockzilla_model::{ExecutionStatus, TokenBalanceCoverage, TokenBalanceSide};
use clap::Args;
use sha2::{Digest, Sha256};

#[derive(Args, Debug)]
pub(crate) struct TokenDumpArgs {
    /// Epoch to read from the public Foundation archive.
    #[arg(long)]
    pub epoch: u64,
    /// Compatible HTTPS archive origin. Omit it to read the public Foundation bucket.
    #[arg(long, env = "BLOCKZILLA_ORIGIN", conflicts_with = "archive_dir")]
    pub origin: Option<String>,
    /// Public HTTPS epoch directory. Omit `--archive-url` and `--origin` to read
    /// `https://pub-97348740d6ef467aa2f1b4b62daa98dc.r2.dev/compact-v2/blockzilla-20261004/epoch-<EPOCH>`.
    #[arg(long, env = "BLOCKZILLA_ARCHIVE_URL", conflicts_with_all = ["origin", "archive_dir"])]
    pub archive_url: Option<String>,
    /// Sign requests to --archive-url for a private S3-compatible bucket in this
    /// region (`auto` for Cloudflare R2). Credentials come from
    /// AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and the optional
    /// AWS_SESSION_TOKEN.
    #[arg(long, requires = "archive_url")]
    pub s3_region: Option<String>,
    /// Cache directory. Relative paths are resolved from the current directory.
    #[arg(long, default_value = ".blockzilla-cache")]
    pub cache_root: PathBuf,
    /// Read this local epoch directory instead of the HTTPS source.
    #[arg(long, requires = "source_id")]
    pub archive_dir: Option<PathBuf>,
    /// Stable ID for a local archive build. Change it when you replace that build.
    #[arg(long, requires = "archive_dir")]
    pub source_id: Option<String>,
    /// Concurrent block reads for --archive-dir. Use several on a NAS or disk
    /// array; 1 reads one range at a time.
    #[arg(long, default_value_t = 1, requires = "archive_dir", value_parser = clap::value_parser!(u16).range(1..=64))]
    pub read_concurrency: u16,
    /// Decode workers (1 through 64).
    #[arg(long, default_value_t = 4, value_parser = clap::value_parser!(u16).range(1..=64))]
    pub threads: u16,
    /// First block row to read. Use the next row after a saved checkpoint to
    /// resume a dump.
    #[arg(long, default_value_t = 0)]
    pub first_block: u32,
    /// Read at most this many block rows. Omit to read all admitted rows.
    #[arg(long)]
    pub max_blocks: Option<NonZeroU32>,
    /// Select one base58 mint. Unknown mint identities remain visible as null.
    #[arg(long, value_parser = parse_mint)]
    pub mint: Option<[u8; 32]>,
}

fn parse_mint(value: &str) -> Result<[u8; 32], String> {
    let mut mint = [0; 32];
    five8::decode_32(value, &mut mint).map_err(|error| match error {
        five8::DecodeError::InvalidChar(_) => format!("Invalid base58 mint: {error}"),
        _ => "A mint must decode to exactly 32 bytes".into(),
    })?;
    Ok(mint)
}

/// Output buffer for standard output. The sink flushes once per accepted
/// block, so each block appears as a whole without one write call per row.
const OUTPUT_BUFFER_BYTES: usize = 1 << 20;

struct TokenSink<W> {
    output: W,
    /// `"source_id":"<id>",` as JSON, written in front of every row.
    source_prefix: Vec<u8>,
    numbers: itoa::Buffer,
    rows: u64,
    blocks: u64,
    last_report: Instant,
}

impl<W: Write> TokenSink<W> {
    fn new(output: W, source_id: &str) -> Self {
        let mut source_prefix = b"{\"source_id\":".to_vec();
        serde_json::to_writer(&mut source_prefix, source_id).expect("a string serializes");
        source_prefix.extend_from_slice(b",\"epoch\":");
        Self {
            output,
            source_prefix,
            numbers: itoa::Buffer::new(),
            rows: 0,
            blocks: 0,
            last_report: Instant::now(),
        }
    }

    fn number(&mut self, value: impl itoa::Integer) -> io::Result<()> {
        let text = self.numbers.format(value);
        self.output.write_all(text.as_bytes())
    }

    /// A JSON string with the base58 transaction signature, or `null`.
    fn signature(&mut self, signature: Option<&[u8; 64]>) -> io::Result<()> {
        let Some(signature) = signature else {
            return self.output.write_all(b"null");
        };
        let mut text = [0u8; five8::BASE58_ENCODED_64_MAX_LEN];
        let length = usize::from(five8::encode_64(signature, &mut text));
        self.output.write_all(b"\"")?;
        self.output.write_all(&text[..length])?;
        self.output.write_all(b"\"")
    }

    /// A JSON string with the base58 key, or `null`.
    fn key(&mut self, key: Option<&[u8; 32]>) -> io::Result<()> {
        let Some(key) = key else {
            return self.output.write_all(b"null");
        };
        let mut text = [0u8; five8::BASE58_ENCODED_32_MAX_LEN];
        let length = usize::from(five8::encode_32(key, &mut text));
        self.output.write_all(b"\"")?;
        self.output.write_all(&text[..length])?;
        self.output.write_all(b"\"")
    }

    /// One row. The field order and text are those of the earlier
    /// `#[derive(Serialize)]` row struct, so the bytes are unchanged.
    #[allow(clippy::too_many_arguments)]
    fn row(
        &mut self,
        epoch: u64,
        block_ordinal: u32,
        slot: u64,
        tx_index: u32,
        signature: Option<&[u8; 64]>,
        status: &'static [u8],
        balance: &blockzilla_model::RecordedTokenBalance,
    ) -> io::Result<()> {
        self.output.write_all(&self.source_prefix)?;
        self.number(epoch)?;
        self.output.write_all(b",\"block_ordinal\":")?;
        self.number(block_ordinal)?;
        self.output.write_all(b",\"slot\":")?;
        self.number(slot)?;
        self.output.write_all(b",\"tx_index\":")?;
        self.number(tx_index)?;
        self.output.write_all(b",\"signature\":")?;
        self.signature(signature)?;
        self.output.write_all(b",\"execution_status\":\"")?;
        self.output.write_all(status)?;
        self.output.write_all(match balance.side {
            TokenBalanceSide::Pre => b"\",\"side\":\"pre\",\"balance_index\":",
            TokenBalanceSide::Post => b"\",\"side\":\"post\",\"balance_index\":",
        })?;
        self.number(balance.balance_index)?;
        self.output.write_all(b",\"account_index\":")?;
        self.number(balance.account_index)?;
        self.output.write_all(b",\"mint\":")?;
        self.key(balance.mint.as_ref())?;
        self.output.write_all(b",\"owner\":")?;
        self.key(balance.owner.as_ref())?;
        self.output.write_all(b",\"token_program\":")?;
        self.key(balance.token_program.as_ref())?;
        // A decimal string also preserves every UInt64 value in JavaScript clients.
        self.output.write_all(b",\"amount\":\"")?;
        self.number(balance.amount)?;
        self.output.write_all(b"\",\"decimals\":")?;
        self.number(balance.decimals)?;
        self.output.write_all(b"}\n")
    }
}

impl<W: Write> BlockSink for TokenSink<W> {
    fn visit_block(&mut self, block: BlockView<'_>) -> QueryResult<()> {
        // Do not publish a partly accepted block when required facts are absent.
        for tx in block.transaction_views() {
            if matches!(tx.header.status, ExecutionStatus::Unknown(_))
                || tx.token_balance_coverage != TokenBalanceCoverage::Complete
            {
                return Err(QueryError::sink(std::io::Error::other(format!(
                    "Incomplete token data at slot {}, transaction {}",
                    block.header.slot, tx.header.tx_index,
                ))));
            }
        }
        for tx in block.transaction_views() {
            let status: &'static [u8] = match tx.header.status {
                ExecutionStatus::Succeeded => b"succeeded",
                ExecutionStatus::Failed => b"failed",
                ExecutionStatus::Unknown(_) => unreachable!("checked above"),
            };
            for balance in tx.token_balances {
                self.row(
                    block.header.epoch,
                    block.header.block_ordinal,
                    block.header.slot,
                    tx.header.tx_index,
                    tx.primary_signature,
                    status,
                    balance,
                )
                .map_err(QueryError::sink)?;
                self.rows += 1;
            }
        }
        self.output.flush().map_err(QueryError::sink)?;
        self.blocks += 1;
        if self.last_report.elapsed().as_secs() >= 3 {
            eprintln!(
                "Read {} blocks, wrote {} token balance rows",
                self.blocks, self.rows
            );
            self.last_report = Instant::now();
        }
        Ok(())
    }
}

fn open(args: &TokenDumpArgs) -> Result<CompactV2Archive> {
    eprintln!("Opening epoch {}...", args.epoch);
    let archive = if let Some(root) = &args.archive_dir {
        let root = std::fs::canonicalize(&root)
            .with_context(|| format!("Cannot open archive directory {}", root.display()))?;
        let source_id = args
            .source_id
            .as_deref()
            .context("Local reads require --source-id")?;
        let descriptor = CompactV2LocalDescriptor::mainnet(args.epoch, source_id)?;
        CompactV2Archive::open_local_with_read_concurrency(
            root,
            descriptor,
            usize::from(args.read_concurrency),
        )?
    } else {
        let cache_root = if args.cache_root.is_absolute() {
            args.cache_root.clone()
        } else {
            std::env::current_dir()?.join(&args.cache_root)
        };
        if let Some(epoch_url) = &args.archive_url {
            eprintln!("Source: {epoch_url}\nPreparing archive index and key registry...");
            match &args.s3_region {
                Some(region) => {
                    let signer = blockzilla_compact_v2_reader::S3SigV4Signer::new(
                        blockzilla_compact_v2_reader::S3Credentials::from_env()?,
                        region.as_str(),
                    )?;
                    CompactV2Archive::open_signed_epoch_url(
                        epoch_url,
                        args.epoch,
                        cache_root,
                        std::sync::Arc::new(signer),
                    )
                }
                None => CompactV2Archive::open_epoch_url(epoch_url, args.epoch, cache_root),
            }
            .with_context(|| format!("Cannot open epoch {} at {epoch_url}", args.epoch))?
        } else if let Some(origin) = args.origin.as_deref() {
            eprintln!("Source: {origin}\nPreparing archive index and key registry...");
            CompactV2Archive::open(origin, args.epoch, cache_root)
                .with_context(|| format!("Cannot open epoch {} at {origin}", args.epoch))?
        } else {
            let epoch_url = blockzilla::public_epoch_url(args.epoch);
            eprintln!("Source: {epoch_url}\nPreparing archive index and key registry...");
            CompactV2Archive::open_epoch_url(&epoch_url, args.epoch, cache_root)
                .with_context(|| format!("Cannot open epoch {} at {epoch_url}", args.epoch))?
        }
    };
    Ok(archive)
}

fn parallel_config(args: &TokenDumpArgs) -> CompactV2ParallelScanConfig {
    let mut config = CompactV2ParallelScanConfig::new(usize::from(args.threads));
    if args.archive_dir.is_some()
        && args.read_concurrency > 1
        && let Some(input) = config.network_input.as_mut()
    {
        input.workers = usize::from(args.read_concurrency);
    }
    config
}

fn request(archive: &CompactV2Archive, args: &TokenDumpArgs) -> Result<ScanRequest> {
    Ok(match (args.first_block, args.max_blocks) {
        (0, None) => ScanRequest::all(),
        (first_block, limit) => ScanRequest::bounded(
            archive.bounded_range(first_block, limit.unwrap_or(NonZeroU32::MAX))?,
        ),
    })
}

pub(crate) fn run(args: TokenDumpArgs) -> Result<()> {
    let started = Instant::now();
    let mut archive = open(&args)?;
    let request = request(&archive, &args)?
        .without_instructions()
        .without_required_signers();
    let request = match args.mint {
        Some(mint) => request.with_token_balances_for([mint]),
        None => request.with_token_balances(),
    };
    let source_bytes = serde_json::to_vec(archive.identity())?;
    let source_id = Sha256::digest(&source_bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    eprintln!("Source ID: {source_id}\nWriting recorded token balances to stdout...");
    let mut sink = TokenSink::new(
        BufWriter::with_capacity(OUTPUT_BUFFER_BYTES, io::stdout().lock()),
        &source_id,
    );
    let receipt = archive
        .scan_ordered_parallel(&request, &mut sink, parallel_config(&args))
        .context("Token dump stopped; output can contain an incomplete prefix")?;
    sink.output.flush().context("flush token dump output")?;
    archive.verify_local_unchanged()?;
    anyhow::ensure!(
        receipt.scan.blocks == sink.blocks,
        "Token dump block counts differ"
    );
    eprintln!(
        "Token dump complete: {} blocks, {} balance rows in {:.1}s",
        sink.blocks,
        sink.rows,
        started.elapsed().as_secs_f64(),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use blockzilla_model::{
        BlockHeader, CanonicalTransaction, CoverageReason, CpiCoverage, InstructionCoverage,
        RecordedTokenBalance, TransactionHeader,
    };

    fn transaction() -> CanonicalTransaction {
        CanonicalTransaction {
            header: TransactionHeader {
                tx_index: 0,
                status: ExecutionStatus::Failed,
                failed_outer_instruction_index: None,
                instruction_coverage: InstructionCoverage::Unknown(
                    CoverageReason::ProjectionNotRequested,
                ),
                cpi_coverage: CpiCoverage::NotRecorded,
            },
            primary_signature: Some([5; 64]),
            required_signers: Vec::new(),
            instructions: Vec::new(),
            token_balance_coverage: TokenBalanceCoverage::Complete,
            token_balances: vec![RecordedTokenBalance {
                side: TokenBalanceSide::Post,
                balance_index: 9,
                account_index: 4,
                mint: None,
                owner: Some([1; 32]),
                token_program: None,
                amount: u64::MAX,
                decimals: 9,
            }],
        }
    }

    fn sink() -> TokenSink<Vec<u8>> {
        TokenSink::new(Vec::new(), "source-test")
    }

    /// The row struct the dump serialized before the direct writer.
    #[derive(serde::Serialize)]
    struct TokenRow<'a> {
        source_id: &'a str,
        epoch: u64,
        block_ordinal: u32,
        slot: u64,
        tx_index: u32,
        signature: Option<String>,
        execution_status: &'static str,
        side: TokenBalanceSide,
        balance_index: u32,
        account_index: u32,
        mint: Option<String>,
        owner: Option<String>,
        token_program: Option<String>,
        amount: String,
        decimals: u8,
    }

    #[test]
    fn direct_rows_equal_the_serde_rows_byte_for_byte() {
        let key = |seed: u64| {
            let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
            let mut key = [0u8; 32];
            for byte in &mut key {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            key[..(seed % 4) as usize].fill(0);
            key
        };
        let text = |key: Option<[u8; 32]>| key.map(|key| bs58::encode(key).into_string());
        let signature_text = |signature: Option<[u8; 64]>| {
            signature.map(|signature| bs58::encode(signature).into_string())
        };
        for source_id in ["source-test", "a\"b\\c\u{1}"] {
            let mut sink = TokenSink::new(Vec::new(), source_id);
            let mut expected = Vec::new();
            for index in 0..300u64 {
                let balance = RecordedTokenBalance {
                    side: if index % 2 == 0 {
                        TokenBalanceSide::Pre
                    } else {
                        TokenBalanceSide::Post
                    },
                    balance_index: [0, 9, u32::MAX][index as usize % 3],
                    account_index: [0, 4, u32::MAX][index as usize % 3],
                    mint: (index % 5 != 0).then(|| key(index)),
                    owner: (index % 3 != 0).then(|| key(index + 1000)),
                    token_program: (index % 7 != 0).then(|| [0; 32]),
                    amount: [0, 1, u64::MAX, 123_456_789][index as usize % 4],
                    decimals: [0, 6, 9, u8::MAX][index as usize % 4],
                };
                let signature = (index % 4 != 0).then(|| {
                    let mut signature = [0u8; 64];
                    signature[..32].copy_from_slice(&key(index));
                    signature[32..].copy_from_slice(&key(index + 7));
                    signature
                });
                let (status, status_text) = if index % 3 == 0 {
                    (&b"failed"[..], "failed")
                } else {
                    (&b"succeeded"[..], "succeeded")
                };
                let (epoch, ordinal, slot, tx_index) = (
                    [0, 900, u64::MAX][index as usize % 3],
                    index as u32,
                    index * 7,
                    index as u32,
                );
                serde_json::to_writer(
                    &mut expected,
                    &TokenRow {
                        source_id,
                        epoch,
                        block_ordinal: ordinal,
                        slot,
                        tx_index,
                        signature: signature_text(signature),
                        execution_status: status_text,
                        side: balance.side,
                        balance_index: balance.balance_index,
                        account_index: balance.account_index,
                        mint: text(balance.mint),
                        owner: text(balance.owner),
                        token_program: text(balance.token_program),
                        amount: balance.amount.to_string(),
                        decimals: balance.decimals,
                    },
                )
                .unwrap();
                expected.push(b'\n');
                sink.row(
                    epoch,
                    ordinal,
                    slot,
                    tx_index,
                    signature.as_ref(),
                    status,
                    &balance,
                )
                .unwrap();
            }
            assert_eq!(
                String::from_utf8(sink.output).unwrap(),
                String::from_utf8(expected).unwrap()
            );
        }
    }

    fn header() -> BlockHeader {
        BlockHeader {
            epoch: 900,
            block_ordinal: 7,
            slot: 388_800_010,
        }
    }

    #[test]
    fn dump_keeps_exact_amount_source_coordinates_failed_status_and_unknown_keys() {
        let mut sink = sink();
        sink.visit_block(BlockView {
            counts: None,
            header: header(),
            transactions: &[transaction()],
        })
        .unwrap();
        let row: serde_json::Value = serde_json::from_slice(&sink.output).unwrap();
        assert_eq!(row["amount"], u64::MAX.to_string());
        assert_eq!(row["mint"], serde_json::Value::Null);
        assert_eq!(row["signature"], bs58::encode([5; 64]).into_string());
        assert_eq!(row["execution_status"], "failed");
        assert_eq!(row["balance_index"], 9);
        assert_eq!(row["account_index"], 4);
        assert_eq!(row["source_id"], "source-test");
        assert_eq!(sink.rows, 1);
    }

    #[test]
    fn incomplete_block_is_rejected_before_its_first_output_row() {
        let first = transaction();
        let mut second = transaction();
        second.header.tx_index = 1;
        second.token_balance_coverage =
            TokenBalanceCoverage::Unknown(CoverageReason::MetadataAbsent);
        let mut sink = sink();
        assert!(
            sink.visit_block(BlockView {
                counts: None,
                header: header(),
                transactions: &[first, second]
            })
            .is_err()
        );
        assert!(sink.output.is_empty());
        assert_eq!(sink.blocks, 0);
    }

    #[test]
    fn mint_parser_requires_exact_public_key_length() {
        assert!(parse_mint("bad!").is_err());
        assert!(parse_mint("1").is_err());
        assert!(parse_mint(&"1".repeat(33)).is_err());
        assert_eq!(
            parse_mint(&bs58::encode([255; 32]).into_string()).unwrap(),
            [255; 32]
        );
        assert_eq!(
            parse_mint("11111111111111111111111111111111").unwrap(),
            [0; 32]
        );
    }
}
