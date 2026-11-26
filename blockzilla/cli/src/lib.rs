//! Shared archive dump commands for the `blockzilla` binary and the example bins.

/// Public Foundation Compact V2 bucket. Objects for one epoch live in
/// `{PUBLIC_ARCHIVE_BASE}/epoch-<epoch>/`.
pub const PUBLIC_ARCHIVE_BASE: &str =
    "https://pub-97348740d6ef467aa2f1b4b62daa98dc.r2.dev/compact-v2/blockzilla-20261004";

/// Epoch directory on the public Foundation bucket.
pub fn public_epoch_url(epoch: u64) -> String {
    format!("{PUBLIC_ARCHIVE_BASE}/epoch-{epoch}")
}

#[doc(hidden)]
pub mod archive_dump;
