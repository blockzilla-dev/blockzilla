//! Sidecar output positions cover both Bank events and non-Bank coverage gaps.
use anyhow::{Result, ensure};
use blockzilla_bank_stream_v2 as v2;
pub fn make(session: &str, position: u64, digest: &str) -> String {
    format!("{session}:o{position}:{digest}")
}
pub fn parse(cursor: &str, session: &str) -> Result<u64> {
    let mut parts = cursor.split(':');
    let s = parts.next();
    let n = parts.next().and_then(|p| p.strip_prefix('o'));
    let hash = parts.next();
    ensure!(
        parts.next().is_none() && s == Some(session),
        "source_changed"
    );
    let n = n.ok_or_else(|| anyhow::anyhow!("invalid_cursor"))?;
    let number: u64 = n.parse()?;
    ensure!(
        number <= v2::SAFE && number.to_string() == n,
        "invalid_cursor"
    );
    ensure!(
        hash.is_some_and(|h| if number == 0 {
            h == "-"
        } else {
            v2::is_digest(h)
        }),
        "invalid_cursor"
    );
    Ok(number)
}
