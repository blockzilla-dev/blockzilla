//! Core Blockzilla commands. Application indexes and source migration tools
//! are maintained outside this command tree.

use anyhow::Result;
use blockzilla_compact_v2_reader::archive::ArchiveInstructionSource;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod archive_v2;
mod compare_sdk_rpc;
mod dump_tokens;
mod first_seen_finalization;
mod progress;
mod stream;
use progress::{ProgressTracker, file_nonempty};

pub const BUFFER_SIZE: usize = 256 << 20;
pub const PROGRESS_REPORT_INTERVAL_SECS: u64 = 3;
pub const SLOTS_PER_EPOCH: u64 = 432_000;

#[derive(Parser)]
#[command(
    name = "blockzilla",
    version,
    about = "Read and build compact Solana blocks"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    // Preserve the accepted global option for existing producer launchers.
    #[arg(long, default_value_t = true, global = true, hide = true)]
    resume: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Stream an archive epoch as ordered JSON block summaries.
    Stream(stream::StreamArgs),
    /// Export recorded token balances from an archive epoch.
    DumpTokens(dump_tokens::DumpTokensArgs),
    /// Show the admitted identity and range of an archive epoch.
    Inspect {
        #[command(flatten)]
        source: stream::EpochSourceArgs,
    },
    /// Compare an SDK capture with finalized JSON-RPC blocks.
    CompareSdkRpc(compare_sdk_rpc::CompareSdkRpcArgs),
    /// Build a compact projection from a complete native Agave callback batch.
    BuildDirectAgaveCompact {
        normalized_dir: PathBuf,
        output_dir: PathBuf,
        #[arg(long, default_value_t = 1)]
        level: i32,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::INFO)
        .init();
    match Cli::parse().command {
        Commands::CompareSdkRpc(args) => compare_sdk_rpc::run(args),
        Commands::Stream(args) => stream::run(args),
        Commands::DumpTokens(args) => dump_tokens::run(args),
        Commands::Inspect { source } => {
            let archive = stream::open(&source)?;
            println!("{}", serde_json::to_string_pretty(archive.identity())?);
            archive.verify_local_unchanged()?;
            Ok(())
        }
        Commands::BuildDirectAgaveCompact {
            normalized_dir,
            output_dir,
            level,
        } => archive_v2::direct_agave::build(&normalized_dir, &output_dir, level),
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn sdk_comparison_parses_local_default_and_bounded_timeout() {
        let cli = Cli::try_parse_from(["blockzilla", "compare-sdk-rpc", "capture.json"]).unwrap();
        let Commands::CompareSdkRpc(args) = cli.command else {
            panic!("wrong command")
        };
        assert_eq!(args.rpc_url.as_str(), "http://127.0.0.1:8899/");
        assert_eq!(args.timeout_seconds, 30);
        assert!(
            Cli::try_parse_from([
                "blockzilla",
                "compare-sdk-rpc",
                "capture.json",
                "--timeout-seconds",
                "0"
            ])
            .is_err()
        );
    }

    #[test]
    fn native_builder_keeps_existing_arguments_and_default_level() {
        let cli = Cli::try_parse_from([
            "blockzilla",
            "build-direct-agave-compact",
            "/normalized",
            "/output",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Commands::BuildDirectAgaveCompact { level: 1, .. }
        ));
        let cli = Cli::try_parse_from([
            "blockzilla",
            "build-direct-agave-compact",
            "/normalized",
            "/output",
            "--level",
            "3",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Commands::BuildDirectAgaveCompact { level: 3, .. }
        ));
    }

    #[test]
    fn removed_application_and_source_commands_are_not_core_commands() {
        for command in [
            "archive-v3",
            "index-tokens",
            "scheduler",
            "bench-car-archive",
            "build-archive-v2",
        ] {
            assert!(Cli::try_parse_from(["blockzilla", command]).is_err());
        }
    }
}
