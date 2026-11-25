use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Run the local rolling producer. Bounds apply to retained custody, not lifetime counters.
    BuildContinuous {
        session: PathBuf,
        output: PathBuf,
        #[arg(long)]
        blockzilla: PathBuf,
        #[arg(long)]
        retained_banks: u64,
        #[arg(long)]
        max_retained_banks: u64,
        #[arg(long)]
        retained_events: u64,
        #[arg(long)]
        max_output_bytes: u64,
        #[arg(long)]
        min_retention_ms: u64,
        #[arg(long)]
        release_checkpoint: PathBuf,
        #[arg(long)]
        required_consumer: String,
    },
    /// Build v2 controls and frames from already committed compact banks and native observations.
    BuildConfirmed {
        processed: PathBuf,
        output: PathBuf,
        #[arg(long)]
        follow: bool,
        /// Retire the local replay window from the durable feed tip, without a consumer ACK.
        #[arg(long)]
        local_beam_retention: bool,
    },
    /// Compact complete processed banks once; journal controls and archive selections separately.
    BuildProcessed {
        session: PathBuf,
        output: PathBuf,
        #[arg(long)]
        blockzilla: PathBuf,
        /// Explicit source prefix boundary. Needed when attaching after source retirement.
        #[arg(long)]
        start_sequence: Option<u64>,
        #[arg(long)]
        follow: bool,
        /// Finite live producer only: no archive custody, restore, or source retirement.
        #[arg(long, requires_all = ["live_max_banks", "live_max_events", "live_max_output_bytes", "live_max_seconds"])]
        live_only: bool,
        #[arg(long, requires = "live_only")]
        live_max_banks: Option<u64>,
        #[arg(long, requires = "live_only")]
        live_max_events: Option<u64>,
        #[arg(long, requires = "live_only")]
        live_max_output_bytes: Option<u64>,
        #[arg(long, requires = "live_only")]
        live_max_seconds: Option<u64>,
    },
    /// Build compact blocks from durable local Agave events. No gRPC connection is used.
    Build {
        session: PathBuf,
        output: PathBuf,
        #[arg(long)]
        blockzilla: PathBuf,
        #[arg(long, default_value_t = 32)]
        batch_blocks: usize,
        #[arg(long)]
        follow: bool,
    },
    /// Check capture state without relying on service process state.
    Status { session: PathBuf },
}
fn main() -> Result<()> {
    match Args::parse().command {
        Command::BuildContinuous {
            session,
            output,
            blockzilla,
            retained_banks,
            max_retained_banks,
            retained_events,
            max_output_bytes,
            min_retention_ms,
            release_checkpoint,
            required_consumer,
        } => hivezilla_direct_agave::processed::run_continuous(
            &session,
            &output,
            &blockzilla,
            hivezilla_direct_agave::processed::ContinuousLiveOptions {
                retained_banks,
                max_retained_banks,
                retained_events,
                max_output_bytes,
                min_retention_ms,
                release_checkpoint,
                required_consumer,
            },
        ),
        Command::BuildConfirmed {
            processed,
            output,
            follow,
            local_beam_retention,
        } => {
            if local_beam_retention {
                hivezilla_direct_agave::confirmed::run_local_beam(&processed, &output, follow)
            } else {
                hivezilla_direct_agave::confirmed::run(&processed, &output, follow)
            }
        }
        Command::BuildProcessed {
            session,
            output,
            blockzilla,
            start_sequence,
            follow,
            live_only,
            live_max_banks,
            live_max_events,
            live_max_output_bytes,
            live_max_seconds,
        } => {
            if live_only {
                let limits = hivezilla_direct_agave::processed::LiveCanaryLimits {
                    max_banks: live_max_banks
                        .context("--live-max-banks is required with --live-only")?,
                    max_events: live_max_events
                        .context("--live-max-events is required with --live-only")?,
                    max_output_bytes: live_max_output_bytes
                        .context("--live-max-output-bytes is required with --live-only")?,
                    max_seconds: live_max_seconds
                        .context("--live-max-seconds is required with --live-only")?,
                };
                hivezilla_direct_agave::processed::run_live(
                    &session,
                    &output,
                    &blockzilla,
                    start_sequence,
                    follow,
                    limits,
                )
            } else {
                hivezilla_direct_agave::processed::run(
                    &session,
                    &output,
                    &blockzilla,
                    start_sequence,
                    follow,
                )
            }
        }
        Command::Build {
            session,
            output,
            blockzilla,
            batch_blocks,
            follow,
        } => hivezilla_direct_agave::worker::run(
            &session,
            &output,
            &blockzilla,
            batch_blocks,
            follow,
        ),
        Command::Status { session } => {
            let failure: serde_json::Value =
                serde_json::from_slice(&std::fs::read(session.join("FAILURE.json"))?)?;
            anyhow::ensure!(failure.get("state").is_none(), "capture failed: {failure}");
            let db = hivezilla_direct_agave::journal::open_reader(&session.join("events.sqlite"))?;
            let (state, seq): (String, u64) =
                db.query_row("SELECT state,durable_sequence FROM status", [], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?;
            anyhow::ensure!(
                state != "CAPTURING" || hivezilla_direct_agave::journal::capture_is_live(&session)?,
                "capture ended without a clean close; possible source gap"
            );
            println!(
                "{}",
                serde_json::json!({"state":state,"durable_sequence":seq,"clean_close":session.join("CLOSED.json").exists(),"canonical":false})
            );
            anyhow::ensure!(state != "FAILED", "capture failed");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn confirmed_local_beam_retention_requires_explicit_flag() {
        for local in [false, true] {
            let mut args = vec![
                "direct-agave",
                "build-confirmed",
                "processed",
                "output",
                "--follow",
            ];
            if local {
                args.push("--local-beam-retention");
            }
            match Args::try_parse_from(args).unwrap().command {
                Command::BuildConfirmed {
                    processed,
                    output,
                    follow,
                    local_beam_retention,
                } => {
                    assert_eq!(processed, PathBuf::from("processed"));
                    assert_eq!(output, PathBuf::from("output"));
                    assert!(follow);
                    assert_eq!(local_beam_retention, local);
                }
                _ => panic!("wrong command"),
            }
        }
        assert!(
            Args::try_parse_from([
                "direct-agave",
                "build-confirmed",
                "processed",
                "output",
                "--local-beam-retention=false"
            ])
            .is_err()
        );
    }
    #[test]
    fn continuous_requires_retention_bounds_but_has_no_lifetime_limit() {
        let prefix = [
            "direct-agave",
            "build-continuous",
            "source",
            "output",
            "--blockzilla",
            "writer",
        ];
        assert!(Args::try_parse_from(prefix).is_err());
        let mut full = prefix.to_vec();
        full.extend([
            "--retained-banks",
            "1024",
            "--max-retained-banks",
            "4096",
            "--retained-events",
            "1000000",
            "--max-output-bytes",
            "68719476736",
            "--min-retention-ms",
            "120000",
            "--release-checkpoint",
            "/private/PROCESSED-RELEASE.json",
            "--required-consumer",
            "sidecar-primary",
        ]);
        assert!(matches!(
            Args::try_parse_from(full).unwrap().command,
            Command::BuildContinuous {
                max_retained_banks: 4096,
                ..
            }
        ));
    }
    #[test]
    fn processed_default_keeps_archive_mode_opt_in_unchanged() {
        let args = Args::try_parse_from([
            "direct-agave",
            "build-processed",
            "source",
            "output",
            "--blockzilla",
            "writer",
        ])
        .unwrap();
        assert!(matches!(
            args.command,
            Command::BuildProcessed {
                live_only: false,
                live_max_banks: None,
                ..
            }
        ));
    }
    #[test]
    fn live_only_requires_all_four_explicit_bounds() {
        let prefix = [
            "direct-agave",
            "build-processed",
            "source",
            "output",
            "--blockzilla",
            "writer",
            "--live-only",
        ];
        assert!(Args::try_parse_from(prefix).is_err());
        let mut full = prefix.to_vec();
        full.extend([
            "--live-max-banks",
            "16",
            "--live-max-events",
            "10000",
            "--live-max-output-bytes",
            "1073741824",
            "--live-max-seconds",
            "60",
        ]);
        let args = Args::try_parse_from(full).unwrap();
        assert!(matches!(
            args.command,
            Command::BuildProcessed {
                live_only: true,
                live_max_banks: Some(16),
                live_max_events: Some(10000),
                live_max_output_bytes: Some(1073741824),
                live_max_seconds: Some(60),
                ..
            }
        ));
        assert!(
            Args::try_parse_from([
                "direct-agave",
                "build-processed",
                "source",
                "output",
                "--blockzilla",
                "writer",
                "--live-max-banks",
                "1"
            ])
            .is_err()
        );
    }
}
