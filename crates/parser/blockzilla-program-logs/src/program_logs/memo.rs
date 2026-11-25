use serde::{Deserialize, Serialize};
use wincode::{SchemaRead, SchemaWrite};

use blockzilla_primitives::{StrId, StringTable};

pub const STR_ID: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, SchemaRead, SchemaWrite)]
pub enum MemoLog {
    /// processor.rs:18 "Signed by {:?}"
    SignedByDebug { address: StrId },

    /// processor.rs:28 "Invalid UTF-8, from byte {}"
    InvalidUtf8FromByte { valid_up_to: StrId },

    /// processor.rs:31 "Memo (len {}): {:?}"
    MemoLenAndDebug { len: StrId, memo: StrId },
}

impl MemoLog {
    #[inline]
    pub fn parse(payload: &str, st: &mut StringTable) -> Option<Self> {
        if let Some(x) = payload.strip_prefix("Signed by ") {
            return Some(Self::SignedByDebug {
                address: st.push(x.trim()),
            });
        }

        if let Some(x) = parse_one_braced(payload, "Invalid UTF-8, from byte ", "") {
            return Some(Self::InvalidUtf8FromByte {
                valid_up_to: st.push(x),
            });
        }

        if let Some((a, b)) = parse_two_braced(payload, "Memo (len ", "): ") {
            return Some(Self::MemoLenAndDebug {
                len: st.push(a),
                memo: st.push(b),
            });
        }

        None
    }

    #[inline]
    pub fn as_str(&self, st: &StringTable) -> String {
        match self {
            // These tails already contain the source program's Debug output.
            // Rendering them with Debug again adds quotes and escape bytes.
            Self::SignedByDebug { address } => format!("Signed by {}", st.resolve(*address)),
            Self::InvalidUtf8FromByte { valid_up_to } => {
                format!("Invalid UTF-8, from byte {}", st.resolve(*valid_up_to))
            }
            Self::MemoLenAndDebug { len, memo } => {
                format!("Memo (len {}): {}", st.resolve(*len), st.resolve(*memo))
            }
        }
    }
}

#[inline]
fn parse_one_braced<'a>(text: &'a str, prefix: &str, suffix: &str) -> Option<&'a str> {
    let rest = text.strip_prefix(prefix)?;
    if suffix.is_empty() {
        return Some(rest.trim());
    }
    let inner = rest.strip_suffix(suffix)?;
    Some(inner.trim())
}

#[inline]
fn parse_two_braced<'a>(text: &'a str, prefix: &str, mid: &str) -> Option<(&'a str, &'a str)> {
    let rest = text.strip_prefix(prefix)?;
    let (a, b) = rest.split_once(mid)?;
    Some((a.trim(), b.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captured_memo_95_preserves_the_exact_log_bytes() {
        // Native callback and ledger log at mainnet slot 472243214, tx 99.
        let payload = r#"Memo (len 95): "usertx-36MDKSJgfyboXZ7W8BRtNFFqG8xMJLtxTSq92mRvWvHNqKDmTEYhbMBWAhaaYQEodjmES8oX6REpHr1Z3dJ92exK""#;
        let mut st = StringTable::default();
        let parsed = MemoLog::parse(payload, &mut st).unwrap();
        let MemoLog::MemoLenAndDebug { len, memo } = &parsed else {
            panic!("memo payload selected another variant");
        };
        assert_eq!(st.resolve(*len), "95");
        assert_eq!(st.resolve(*memo).as_bytes(), &payload.as_bytes()[15..]);
        assert_eq!(parsed.as_str(&st).as_bytes(), payload.as_bytes());
    }

    #[test]
    fn memo_debug_tails_preserve_quotes_escapes_and_utf8_bytes() {
        for text in [
            "",
            "say \"hello\"",
            r"path\to\memo",
            "Solana 🦀 café",
            "first\nsecond",
            r"first\nsecond",
            "  padded memo  ",
        ] {
            let debug_tail = format!("{text:?}");
            let payload = format!("Memo (len {}): {debug_tail}", text.len());
            let mut st = StringTable::default();
            let parsed = MemoLog::parse(&payload, &mut st).unwrap();
            let MemoLog::MemoLenAndDebug { len, memo } = &parsed else {
                panic!("memo payload selected another variant");
            };
            assert_eq!(st.resolve(*len), text.len().to_string());
            assert_eq!(st.resolve(*memo).as_bytes(), debug_tail.as_bytes());
            assert_eq!(parsed.as_str(&st).as_bytes(), payload.as_bytes());
        }
    }

    #[test]
    fn signed_by_debug_preserves_the_rendered_pubkey_without_quotes() {
        let address = "11111111111111111111111111111111";
        let payload = format!("Signed by {address}");
        let mut st = StringTable::default();
        let parsed = MemoLog::parse(&payload, &mut st).unwrap();
        let MemoLog::SignedByDebug { address: id } = &parsed else {
            panic!("signer payload selected another variant");
        };
        assert_eq!(st.resolve(*id).as_bytes(), address.as_bytes());
        assert_eq!(parsed.as_str(&st).as_bytes(), payload.as_bytes());
    }
}
