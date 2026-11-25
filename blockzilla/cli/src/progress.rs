//! Progress reports shared by the native archive builder.
use crate::{PROGRESS_REPORT_INTERVAL_SECS, SLOTS_PER_EPOCH};
use std::{
    fmt::Write as _,
    fs::File,
    io::Write as _,
    os::fd::{AsRawFd, FromRawFd, RawFd},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tracing::info;

pub(crate) fn file_nonempty(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.len() > 0)
        .unwrap_or(false)
}

pub(crate) fn format_duration(seconds: f64) -> String {
    let total_secs = seconds as u64;

    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let minutes = (total_secs % 3600) / 60;
    let secs = total_secs % 60;

    if days > 0 {
        format!("{}d {}h {}m {}s", days, hours, minutes, secs)
    } else if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, secs)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, secs)
    } else {
        format!("{}s", secs)
    }
}

pub(crate) struct ProgressTracker {
    start_time: Instant,
    last_report: Instant,
    blocks: u64,
    txs: u64,
    report_interval: Duration,
    estimated_total_blocks: u64,
    total_blocks_is_exact: bool,
    first_slot: Option<u64>,
    last_slot: Option<u64>,
    blocks_since_report: u64,
    txs_since_report: u64,
    input_bytes_done: Option<u64>,
    input_bytes_at_last_report: u64,
    input_mib_per_sec: Option<f64>,
    phase: &'static str,
    progress_path: Option<PathBuf>,
    /// Pipe back to a spawning scheduler, set only for job kinds piloting the disk-free
    /// progress channel (currently PoH migration only -- see `BLOCKZILLA_PROGRESS_FD`).
    /// Takes over from `progress_path` entirely when present: every snapshot goes to this fd
    /// instead of a file, since the point is to stop competing with the job's own sequential
    /// disk I/O for head movement. The scheduler owns crash/restart recovery by re-deriving
    /// state from what the job already produced, not from a durable progress checkpoint.
    progress_fd: Option<File>,
}

impl ProgressTracker {
    pub(crate) fn new(phase: &'static str) -> Self {
        let now = Instant::now();
        let progress_fd = std::env::var("BLOCKZILLA_PROGRESS_FD")
            .ok()
            .and_then(|value| value.parse::<RawFd>().ok())
            // SAFETY: the scheduler opens this fd across the exec boundary specifically for
            // this process to own; it is never inherited by anything else and never reused.
            .map(|fd| unsafe { File::from_raw_fd(fd) });
        Self {
            start_time: now,
            last_report: now,
            blocks: 0,
            txs: 0,
            report_interval: Duration::from_secs(PROGRESS_REPORT_INTERVAL_SECS),
            estimated_total_blocks: SLOTS_PER_EPOCH,
            total_blocks_is_exact: false,
            first_slot: None,
            last_slot: None,
            blocks_since_report: 0,
            txs_since_report: 0,
            input_bytes_done: None,
            input_bytes_at_last_report: 0,
            input_mib_per_sec: None,
            phase,
            progress_path: (progress_fd.is_none())
                .then(|| std::env::var_os("BLOCKZILLA_PROGRESS_FILE").map(PathBuf::from))
                .flatten(),
            progress_fd,
        }
    }

    #[inline(always)]
    pub(crate) fn update_slot(&mut self, slot: u64) {
        if self.first_slot.is_none() {
            self.first_slot = Some(slot);
        }
        self.last_slot = Some(slot);
    }

    /// Overrides the `SLOTS_PER_EPOCH` default with an exact known unit count
    /// (e.g. an index's row count), for phases that iterate a fixed, already-known
    /// set of items rather than scanning an epoch of unknown density.
    #[inline(always)]
    pub(crate) fn set_estimated_total_blocks(&mut self, total: u64) {
        self.estimated_total_blocks = total;
        self.total_blocks_is_exact = true;
    }

    fn progress_metrics(
        &self,
        slots_processed: Option<u64>,
        blocks_per_sec: f64,
    ) -> (Option<f64>, Option<f64>) {
        let completed_units = if self.total_blocks_is_exact {
            Some(self.blocks)
        } else {
            slots_processed
        };
        let progress_pct = completed_units.map(|completed| {
            if self.estimated_total_blocks == 0 {
                100.0
            } else {
                (completed as f64 / self.estimated_total_blocks as f64 * 100.0).min(100.0)
            }
        });
        let eta_secs = completed_units.and_then(|completed| {
            let remaining = self.estimated_total_blocks.saturating_sub(completed);
            if remaining == 0 {
                return Some(0.0);
            }
            if !blocks_per_sec.is_finite() || blocks_per_sec <= 0.0 {
                return None;
            }
            if self.total_blocks_is_exact {
                return Some(remaining as f64 / blocks_per_sec);
            }
            if completed == 0 {
                return None;
            }
            let blocks_per_unit = self.blocks as f64 / completed as f64;
            let eta = remaining as f64 * blocks_per_unit / blocks_per_sec;
            (eta.is_finite() && eta >= 0.0).then_some(eta)
        });
        (progress_pct, eta_secs)
    }

    /// Records cumulative useful input bytes consumed by this phase. This is
    /// logical payload progress, not physical device I/O; the scheduler uses
    /// it to compare aggregate useful throughput across lane counts.
    #[inline(always)]
    pub(crate) fn update_input_bytes(&mut self, cumulative_bytes: u64) {
        self.input_bytes_done = Some(
            self.input_bytes_done
                .map_or(cumulative_bytes, |current| current.max(cumulative_bytes)),
        );
    }

    #[inline(always)]
    pub(crate) fn update(&mut self, blocks_delta: u64, txs_delta: u64) {
        self.blocks += blocks_delta;
        self.txs += txs_delta;
        self.blocks_since_report += blocks_delta;
        self.txs_since_report += txs_delta;

        let now = Instant::now();
        if now.duration_since(self.last_report) >= self.report_interval {
            let interval_secs = now
                .duration_since(self.last_report)
                .as_secs_f64()
                .max(0.001);
            self.input_mib_per_sec = self.input_bytes_done.and_then(|bytes| {
                let delta = bytes.checked_sub(self.input_bytes_at_last_report)?;
                let rate = delta as f64 / (1024.0 * 1024.0) / interval_secs;
                rate.is_finite().then_some(rate)
            });
            self.input_bytes_at_last_report = self.input_bytes_done.unwrap_or_default();
            self.report();
            self.last_report = now;
            self.blocks_since_report = 0;
            self.txs_since_report = 0;
        }
    }

    fn report(&mut self) {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed < 0.001 {
            return;
        }

        self.write_progress_snapshot("running");

        let blocks_per_sec = self.blocks as f64 / elapsed;
        let txs_per_sec = self.txs as f64 / elapsed;
        let slots_processed = self
            .first_slot
            .zip(self.last_slot)
            .map(|(first, last)| last.saturating_sub(first));
        let (progress_pct, eta_secs) = self.progress_metrics(slots_processed, blocks_per_sec);
        let slot_summary = self
            .first_slot
            .zip(self.last_slot)
            .map_or_else(String::new, |(first, last)| {
                format!(" | slots={first}-{last} ({})", last.saturating_sub(first))
            });

        if let Some(progress_pct) = progress_pct {
            if let Some(eta_secs) = eta_secs {
                info!(
                    "[{}] progress={:.1}% ETA={} | blocks={} ({:.0} blk/s) txs={} ({:.0} tx/s){} | elapsed={}",
                    self.phase,
                    progress_pct,
                    format_duration(eta_secs),
                    self.blocks,
                    blocks_per_sec,
                    self.txs,
                    txs_per_sec,
                    slot_summary,
                    format_duration(elapsed)
                );
            } else {
                info!(
                    "[{}] progress={:.1}% | blocks={} ({:.0} blk/s) txs={} ({:.0} tx/s){} | elapsed={}",
                    self.phase,
                    progress_pct,
                    self.blocks,
                    blocks_per_sec,
                    self.txs,
                    txs_per_sec,
                    slot_summary,
                    format_duration(elapsed)
                );
            }
        } else {
            info!(
                "[{}] blocks={} ({:.0} blk/s) txs={} ({:.0} tx/s) | elapsed={}",
                self.phase,
                self.blocks,
                blocks_per_sec,
                self.txs,
                txs_per_sec,
                format_duration(elapsed)
            );
        }
    }

    pub(crate) fn final_report(&mut self) {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let blocks_per_sec = self.blocks as f64 / elapsed;
        let txs_per_sec = self.txs as f64 / elapsed;

        self.write_progress_snapshot("complete");

        let mut msg = format!(
            "[{}] Complete: blocks={} txs={} | {:.0} blk/s, {:.0} tx/s | elapsed={}",
            self.phase,
            self.blocks,
            self.txs,
            blocks_per_sec,
            txs_per_sec,
            format_duration(elapsed)
        );

        if let (Some(first), Some(last)) = (self.first_slot, self.last_slot) {
            let slots_processed = last.saturating_sub(first);
            msg.push_str(&format!(
                " | slots={}-{} ({})",
                first, last, slots_processed
            ));
        }

        info!("{}", msg);
    }

    fn write_progress_snapshot(&mut self, state: &str) {
        if self.progress_fd.is_none() && self.progress_path.is_none() {
            return;
        }
        let elapsed_secs = self.start_time.elapsed().as_secs_f64().max(0.001);
        let blocks_per_sec = self.blocks as f64 / elapsed_secs;
        let txs_per_sec = self.txs as f64 / elapsed_secs;
        let slots_processed = self
            .first_slot
            .zip(self.last_slot)
            .map(|(first, last)| last.saturating_sub(first));
        let (progress_pct, eta_secs) = self.progress_metrics(slots_processed, blocks_per_sec);
        let updated_unix_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        let mut json = String::with_capacity(512);
        let _ = writeln!(
            json,
            "{{\"schema_version\":1,\"pid\":{},\"phase\":\"{}\",\"state\":\"{}\",\"blocks_done\":{},\"transactions_done\":{},\"blocks_total_estimate\":{},\"first_slot\":{},\"last_slot\":{},\"slots_processed\":{},\"elapsed_secs\":{:.3},\"blocks_per_sec\":{:.3},\"transactions_per_sec\":{:.3},\"input_bytes_done\":{},\"input_mib_per_sec\":{},\"progress_pct\":{},\"eta_secs\":{},\"updated_unix_secs\":{}}}",
            std::process::id(),
            self.phase,
            state,
            self.blocks,
            self.txs,
            self.estimated_total_blocks,
            json_u64(self.first_slot),
            json_u64(self.last_slot),
            json_u64(slots_processed),
            elapsed_secs,
            blocks_per_sec,
            txs_per_sec,
            json_u64(self.input_bytes_done),
            json_f64(self.input_mib_per_sec),
            json_f64(progress_pct),
            json_f64(eta_secs),
            updated_unix_secs,
        );

        if let Some(fd) = self.progress_fd.as_mut() {
            // The scheduler makes this descriptor non-blocking before exec. Keep each snapshot
            // at or below this pipe's atomic-write bound, then make exactly one write attempt:
            // a full pipe drops telemetry instead of ever stalling the migration's real work.
            let pipe_buf = unsafe { libc::fpathconf(fd.as_raw_fd(), libc::_PC_PIPE_BUF) };
            let pipe_buf = usize::try_from(pipe_buf).unwrap_or(512);
            if json.len() <= pipe_buf {
                match fd.write(json.as_bytes()) {
                    Ok(written) if written == json.len() => {}
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => {}
                }
            }
            return;
        }
        let Some(path) = self.progress_path.as_deref() else {
            return;
        };
        if let Some(parent) = path.parent()
            && std::fs::create_dir_all(parent).is_err()
        {
            return;
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("progress.json");
        let temp_path = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
        if std::fs::write(&temp_path, json).is_ok() {
            let _ = std::fs::rename(temp_path, path);
        }
    }
}

fn json_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "null".to_string(), |value| value.to_string())
}

fn json_f64(value: Option<f64>) -> String {
    value
        .filter(|value| value.is_finite())
        .map_or_else(|| "null".to_string(), |value| format!("{value:.3}"))
}
