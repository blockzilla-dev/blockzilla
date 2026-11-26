use anyhow::{Context, Result, bail};
use blockzilla_compact_v2_reader::{
    CompactV2ParallelScanConfig, NetworkInputConfig, S3Credentials, S3SigV4Signer,
    archive::{CompactV2Archive, CompactV2LocalDescriptor},
};
use blockzilla_model::{
    ArchiveInstructionSource, BlockSink, BlockView, Error, ExecutionStatus, ScanRequest,
};
use clap::Parser;
use std::{
    io::{self, BufWriter, Write},
    num::NonZeroU32,
    path::PathBuf,
};

#[derive(Clone, Copy)]
pub enum Kind {
    Wallet,
    Program,
}

#[derive(clap::Args)]
pub struct Args {
    /// Local Compact V2 epoch directory. Omit it when `--url` is set.
    archive: Option<PathBuf>,
    #[arg(long)]
    epoch: u64,
    /// Stable identifier of this immutable local archive generation.
    #[arg(long)]
    source_id: Option<String>,
    /// Public HTTPS epoch directory. Omit it to read
    /// `https://pub-97348740d6ef467aa2f1b4b62daa98dc.r2.dev/compact-v2/blockzilla-20261004/epoch-<EPOCH>`
    /// for the selected epoch.
    #[arg(long)]
    url: Option<String>,
    /// Cache directory for the network reader's control files. The default is
    /// `.blockzilla-cache` in the current directory. A relative path is
    /// resolved from the current directory.
    #[arg(long, conflicts_with = "archive")]
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
    /// Required signer or invoked program in base58.
    #[arg(long)]
    key: Option<String>,
    /// Parallel decode workers. The default is the number of logical CPUs.
    /// 0 selects the sequential reader.
    #[arg(long)]
    workers: Option<usize>,
    /// Concurrent HTTPS range requests for a network archive.
    #[arg(long, conflicts_with = "archive")]
    http_requests: Option<usize>,
    /// Target size of one HTTPS range request, in MiB.
    #[arg(long, conflicts_with = "archive")]
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
        let key = self.key.expect("validated before scan");
        for tx in block.transaction_views() {
            let matched = match self.kind {
                Kind::Wallet => tx.required_signers.contains(&key),
                Kind::Program => tx.instructions.iter().any(|ix| ix.program_id == Some(key)),
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

fn number(out: &mut Vec<u8>, value: impl itoa::Integer) {
    out.extend_from_slice(itoa::Buffer::new().format(value).as_bytes());
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

#[derive(Parser)]
struct ExampleCommand {
    #[command(flatten)]
    args: Args,
}

fn absolute_cache_dir(cache_dir: Option<PathBuf>) -> Result<PathBuf> {
    let path = cache_dir.unwrap_or_else(|| PathBuf::from(".blockzilla-cache"));
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

/// Parse the example binary's arguments and run one dump.
pub fn run(kind: Kind) -> Result<()> {
    execute(kind, ExampleCommand::parse().args)
}

/// Run one dump with arguments already parsed by `blockzilla`.
pub fn execute(kind: Kind, args: Args) -> Result<()> {
    let key = args
        .key
        .map(|value| -> Result<[u8; 32]> {
            bs58::decode(value)
                .into_vec()?
                .try_into()
                .map_err(|_| anyhow::anyhow!("key must contain 32 bytes"))
        })
        .transpose()?;
    anyhow::ensure!(key.is_some(), "--key is required");
    let local = args.archive.is_some();
    let mut archive = match (args.archive, args.url) {
        (Some(_), Some(_)) => bail!("give either a local ARCHIVE directory or --url, not both"),
        (Some(directory), None) => CompactV2Archive::open_local_with_read_concurrency(
            &directory,
            CompactV2LocalDescriptor::mainnet(
                args.epoch,
                args.source_id
                    .context("--source-id is required for a local archive")?,
            )?,
            args.read_concurrency,
        )?,
        (None, url) => {
            let url = url.unwrap_or_else(|| crate::public_epoch_url(args.epoch));
            let cache_dir = absolute_cache_dir(args.cache_dir)?;
            eprintln!("Source: {url}");
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
    };
    let mut request = match kind {
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
    fn example_command_accepts_the_local_and_https_forms() {
        let local = ExampleCommand::try_parse_from([
            "wallet-dump",
            "/data/epoch-900",
            "--epoch",
            "900",
            "--source-id",
            "my-generation",
            "--key",
            "WALLET",
            "--workers",
            "4",
        ])
        .unwrap();
        assert_eq!(local.args.epoch, 900);
        assert_eq!(
            local.args.archive.as_deref(),
            Some(PathBuf::from("/data/epoch-900").as_path())
        );
        assert_eq!(local.args.source_id.as_deref(), Some("my-generation"));
        assert_eq!(local.args.key.as_deref(), Some("WALLET"));
        assert_eq!(local.args.workers, Some(4));

        let remote = ExampleCommand::try_parse_from([
            "wallet-dump",
            "--url",
            "https://archive.example/compact-v2/build/epoch-200",
            "--epoch",
            "200",
            "--cache-dir",
            "/var/cache/blockzilla",
            "--s3-region",
            "auto",
            "--max-blocks",
            "10",
        ])
        .unwrap();
        assert!(remote.args.archive.is_none());
        assert_eq!(remote.args.epoch, 200);
        assert_eq!(remote.args.max_blocks.unwrap().get(), 10);
        assert_eq!(remote.args.s3_region.as_deref(), Some("auto"));

        let foundation =
            ExampleCommand::try_parse_from(["wallet-dump", "--epoch", "1094"]).unwrap();
        assert!(foundation.args.archive.is_none());
        assert!(foundation.args.url.is_none());
        assert!(foundation.args.cache_dir.is_none());
        assert_eq!(
            crate::public_epoch_url(1094),
            "https://pub-97348740d6ef467aa2f1b4b62daa98dc.r2.dev/compact-v2/blockzilla-20261004/epoch-1094"
        );

        assert!(
            ExampleCommand::try_parse_from([
                "wallet-dump",
                "/data/epoch-200",
                "--url",
                "https://archive.example/epoch-200",
                "--epoch",
                "200",
                "--cache-dir",
                "/var/cache/blockzilla",
                "--read-concurrency",
                "6",
            ])
            .is_err()
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
