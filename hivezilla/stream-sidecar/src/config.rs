use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
};

/// Exact first-join snapshot emitted by the pinned raw SSH gateway. It carries
/// no credential and does not authorize a later replacement source or cursor.
#[derive(Clone, Serialize, Deserialize)]
pub struct BeamBootstrapFile {
    pub schema: String,
    pub status: u16,
    pub source: blockzilla_bank_stream_v2::SourceIdentity,
    pub generation: String,
    pub producer_generation: String,
    pub head: blockzilla_bank_stream_v2::Head,
    #[serde(default)]
    pub after: Option<String>,
}
impl BeamBootstrapFile {
    pub fn validate(&self, config: &blockzilla_bank_client::ssh_beam::SshConfig) -> Result<String> {
        ensure!(
            self.schema == "blockzilla-ssh-beam-v1"
                && self.status == 200
                && self.source == config.source
                && self.generation == config.generation
                && self.producer_generation == config.producer_generation,
            "bootstrap_source_or_generation_changed"
        );
        self.head.validate(
            &config.source,
            blockzilla_bank_client::now_ms(),
            blockzilla_bank_stream_v2::DEFAULT_MAX_LAG_MS,
        )?;
        ensure!(self.head.status != "failed", "bootstrap_source_failed");
        let after = self
            .head
            .cursor
            .clone()
            .ok_or_else(|| anyhow::anyhow!("bootstrap_cursor_missing"))?;
        ensure!(
            self.after.as_ref().is_none_or(|value| *value == after),
            "bootstrap_after_must_match_head"
        );
        Ok(after)
    }
}

pub fn private_token(path: &Path) -> Result<String> {
    let meta = std::fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink() && meta.len() <= 4096,
        "invalid_token_file"
    );
    let token = std::fs::read_to_string(path)?.trim().to_owned();
    ensure!(
        (32..=256).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_graphic()),
        "invalid_token_file"
    );
    Ok(token)
}

/// The public recovery credential stays on the consumer host. Refuse links,
/// shared files and file types that can block startup or disclose the key.
pub fn recovery_api_key(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= 4096,
        "invalid_recovery_api_key_file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() }
                && metadata.nlink() == 1
                && metadata.mode() & 0o077 == 0,
            "recovery_api_key_file_must_be_private"
        );
    }
    let mut key = String::new();
    file.take(4097).read_to_string(&mut key)?;
    let key = key.trim().to_owned();
    ensure!(
        (32..=256).contains(&key.len()) && key.bytes().all(|b| b.is_ascii_graphic()),
        "invalid_recovery_api_key_file"
    );
    Ok(key)
}

#[cfg(all(test, unix))]
mod recovery_key_tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn recovery_key_accepts_only_a_private_bounded_regular_file() {
        let directory = tempfile::tempdir().unwrap();
        let key = directory.path().join("worker-key");
        let value = "k".repeat(48);
        std::fs::write(&key, format!("{value}\n")).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(recovery_api_key(&key).unwrap(), value);

        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(recovery_api_key(&key).is_err());
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let linked = directory.path().join("linked-key");
        symlink(&key, &linked).unwrap();
        assert!(recovery_api_key(&linked).is_err());
        std::fs::remove_file(&linked).unwrap();
        std::fs::hard_link(&key, &linked).unwrap();
        assert!(recovery_api_key(&key).is_err());
        std::fs::remove_file(&linked).unwrap();
        std::fs::write(&key, "k".repeat(4097)).unwrap();
        assert!(recovery_api_key(&key).is_err());
        std::fs::write(&key, "short").unwrap();
        assert!(recovery_api_key(&key).is_err());
        assert!(recovery_api_key(directory.path()).is_err());
    }
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum View {
    Blockhashes,
    Blocks,
    Updates,
    #[default]
    Signatures,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filter {
    #[serde(default)]
    pub accounts: Vec<String>,
    #[serde(default)]
    pub programs: Vec<String>,
    #[serde(default)]
    pub failed: Option<bool>,
}
impl Filter {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.accounts.len() <= 256 && self.programs.len() <= 256,
            "filter_too_large"
        );
        for key in self.accounts.iter().chain(&self.programs) {
            let raw = bs58::decode(key).into_vec()?;
            ensure!(
                raw.len() == 32 && bs58::encode(&raw).into_string() == *key,
                "invalid_filter_key"
            );
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookTarget {
    pub id: String,
    pub url: String,
    #[serde(default)]
    pub token_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key_file: Option<PathBuf>,
    #[serde(default)]
    pub view: View,
    #[serde(default = "queue_bytes")]
    pub queue_bytes: u64,
    #[serde(default = "queue_events")]
    pub queue_events: u64,
    #[serde(default = "retry_limit")]
    pub retry_limit: u32,
    #[serde(default)]
    pub filter: Filter,
    #[serde(default = "default_kinds")]
    pub kinds: Vec<String>,
}
fn queue_bytes() -> u64 {
    16 * 1024 * 1024
}
fn queue_events() -> u64 {
    1024
}
fn retry_limit() -> u32 {
    16
}
fn default_kinds() -> Vec<String> {
    vec!["root".into(), "invalidate".into()]
}
impl WebhookTarget {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.id.is_empty()
                && self.id.len() <= 64
                && self
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')),
            "invalid_webhook_id"
        );
        let url = reqwest::Url::parse(&self.url)?;
        let local = url
            .host_str()
            .and_then(|v| v.parse::<IpAddr>().ok())
            .is_some_and(|v| v.is_loopback());
        ensure!(
            (url.scheme() == "https" || (url.scheme() == "http" && local))
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none(),
            "invalid_webhook_url"
        );
        ensure!(
            !self.kinds.is_empty()
                && self.kinds.len() <= 4
                && self
                    .kinds
                    .iter()
                    .all(|v| matches!(v.as_str(), "block" | "confirmed" | "root" | "invalidate")),
            "invalid_webhook_kinds"
        );
        ensure!(
            (65536..=256 * 1024 * 1024).contains(&self.queue_bytes)
                && (1..=8192).contains(&self.queue_events)
                && (1..=64).contains(&self.retry_limit),
            "invalid_webhook_bounds"
        );
        self.filter.validate()?;
        if matches!(self.view, View::Blocks | View::Blockhashes) {
            ensure!(
                self.filter.accounts.is_empty()
                    && self.filter.programs.is_empty()
                    && self.filter.failed.is_none(),
                "blockhashes_and_full_blocks_cannot_be_filtered"
            );
        }
        if let Some(p) = &self.token_file {
            let _ = private_token(p)?;
        }
        if let Some(p) = &self.signing_key_file {
            let _ = webhook_signing_key(p)?;
        }
        Ok(())
    }
}

pub fn webhook_signing_key(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= 4096,
        "invalid_signing_key_file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() }
                && metadata.nlink() == 1
                && metadata.mode() & 0o077 == 0,
            "webhook_signing_key_must_be_private"
        );
    }
    let mut token = String::new();
    file.take(4097).read_to_string(&mut token)?;
    let token = token.trim().to_owned();
    ensure!(
        (32..=256).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_graphic()),
        "invalid_signing_key_file"
    );
    Ok(token)
}

#[cfg(test)]
mod webhook_tests {
    use super::*;

    #[test]
    fn optional_signing_path_keeps_legacy_target_json_readable() {
        let value = serde_json::json!({"id":"fixture","url":"http://127.0.0.1:1/"});
        let target: WebhookTarget = serde_json::from_value(value).unwrap();
        target.validate().unwrap();
        assert!(target.signing_key_file.is_none());
        assert!(
            serde_json::to_value(target)
                .unwrap()
                .get("signing_key_file")
                .is_none()
        );
    }

    #[test]
    fn signing_key_requires_a_private_regular_file() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let t = tempfile::tempdir().unwrap();
        let key = t.path().join("signing-key");
        std::fs::write(&key, "local-test-signing-key-0000000000000000000000000000").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(webhook_signing_key(&key).is_ok());
        let link = t.path().join("link");
        symlink(&key, &link).unwrap();
        assert!(webhook_signing_key(&link).is_err());
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(webhook_signing_key(&key).is_err());
    }
}
