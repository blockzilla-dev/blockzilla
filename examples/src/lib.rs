use anyhow::{Context, Result};
use blockzilla_compact_v2_reader::archive::{CompactV2Archive, CompactV2LocalDescriptor};
use blockzilla_model::{BlockSink, BlockView, Error, ScanRequest};
use clap::Parser;
use serde_json::json;
use std::{io::Write, path::PathBuf};

#[derive(Clone, Copy)]
pub enum Kind {
    Token,
    Wallet,
    Program,
}
#[derive(Parser)]
struct Args {
    /// Local Compact V2 epoch directory.
    archive: PathBuf,
    #[arg(long)]
    epoch: u64,
    /// Stable identifier of this immutable archive generation.
    #[arg(long)]
    source_id: String,
    /// Token mint, required signer, or invoked program in base58.
    #[arg(long)]
    key: Option<String>,
}
struct Sink<W> {
    kind: Kind,
    key: Option<[u8; 32]>,
    output: W,
}
impl<W: Write> BlockSink for Sink<W> {
    fn visit_block(&mut self, block: BlockView<'_>) -> blockzilla_model::Result<()> {
        for tx in block.transaction_views() {
            match self.kind {
                Kind::Token => {
                    for row in tx.token_balances {
                        if self.key.is_some() && row.mint.is_some() && row.mint != self.key {
                            continue;
                        }
                        serde_json::to_writer(&mut self.output, &json!({
                        "slot": block.header.slot, "tx_index": tx.header.tx_index,
                        "status": format!("{:?}", tx.header.status),
                        "side": format!("{:?}", row.side), "account_index": row.account_index,
                        "mint": row.mint.map(|v| bs58::encode(v).into_string()),
                        "owner": row.owner.map(|v| bs58::encode(v).into_string()),
                        "amount": row.amount.to_string(), "decimals": row.decimals
                    })).map_err(Error::sink)?;
                        self.output.write_all(b"\n").map_err(Error::sink)?;
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
                    if !matched {
                        continue;
                    }
                    serde_json::to_writer(
                        &mut self.output,
                        &json!({
                            "slot": block.header.slot, "tx_index": tx.header.tx_index,
                            "status": format!("{:?}", tx.header.status),
                            "signature": tx.primary_signature.map(|v| bs58::encode(v).into_string())
                        }),
                    )
                    .map_err(Error::sink)?;
                    self.output.write_all(b"\n").map_err(Error::sink)?;
                }
            }
        }
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
    let mut archive = CompactV2Archive::open_local(
        &args.archive,
        CompactV2LocalDescriptor::mainnet(args.epoch, args.source_id)?,
    )?;
    let mut request = ScanRequest::all();
    match kind {
        Kind::Token => {
            request = request.without_instructions().with_token_balances();
        }
        Kind::Wallet => {
            request = request.without_instructions();
        }
        Kind::Program => {
            request.require_complete_cpi = true;
        }
    }
    let stdout = std::io::stdout();
    archive
        .scan_ordered(
            &request,
            &mut Sink {
                kind,
                key,
                output: stdout.lock(),
            },
        )
        .context("archive scan did not complete")?;
    Ok(())
}
