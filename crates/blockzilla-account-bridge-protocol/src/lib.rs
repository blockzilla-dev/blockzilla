//! Owned, bounded messages for native account and ledger reads. No Agave or RPC dependency.
//!
//! Each message is JSON preceded by its four-byte big-endian byte length.
//! A requested Bank is exact: neither the server nor the client may substitute
//! a newer Bank. Account values contain no inferred historical write metadata.

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fmt,
    io::{self, Read, Write},
};

pub const VERSION: u16 = 1;
pub const MAX_REQUEST_BYTES: usize = 16 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_ACCOUNTS: usize = 100;
pub const MAX_ACCOUNT_DATA_BYTES: usize = 10 * 1024 * 1024;
pub const MAX_ERROR_MESSAGE_BYTES: usize = 256;
/// Legacy and V0 keep the original packet bound. SDK 5 V1 transactions
/// start with their message discriminator and allow the larger wire format.
pub const MAX_LEGACY_TRANSACTION_BYTES: usize = 1232;
pub const V1_TRANSACTION_PREFIX: u8 = 0x81;
pub const MAX_TRANSACTION_BYTES: usize = 4096;
pub const MAX_BLOCK_TRANSACTIONS: usize = 100_000;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Json(serde_json::Error),
    FrameTooLarge { bytes: usize, limit: usize },
    Invalid(&'static str),
    SourceMismatch,
    BankMismatch,
    BlockMismatch,
    RequestIdMismatch,
    OperationMismatch,
    AccountOrderMismatch,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "bridge I/O: {e}"),
            Self::Json(e) => write!(f, "bridge JSON: {e}"),
            Self::FrameTooLarge { bytes, limit } => {
                write!(f, "bridge frame has {bytes} bytes; limit is {limit}")
            }
            Self::Invalid(field) => write!(f, "invalid bridge {field}"),
            Self::SourceMismatch => f.write_str("bridge source mismatch"),
            Self::BankMismatch => f.write_str("bridge Bank mismatch"),
            Self::BlockMismatch => f.write_str("bridge block slot or hash mismatch"),
            Self::RequestIdMismatch => f.write_str("bridge request ID mismatch"),
            Self::OperationMismatch => f.write_str("bridge operation mismatch"),
            Self::AccountOrderMismatch => {
                f.write_str("bridge account order or duplicate value mismatch")
            }
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Json(e) => Some(e),
            _ => None,
        }
    }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}
pub type Result<T> = std::result::Result<T, Error>;

// A missing field must not be interpreted as an absent account or an omitted
// constraint. Explicit JSON null is allowed; omission is a protocol error.
fn required_option<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

fn key(value: &str) -> bool {
    if !(32..=44).contains(&value.len()) {
        return false;
    }
    let Ok(bytes) = bs58::decode(value).into_vec() else {
        return false;
    };
    bytes.len() == 32 && bs58::encode(bytes).into_string() == value
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentity {
    pub instance_id: String,
    pub genesis_hash: String,
    pub node_identity: String,
    pub agave_revision: String,
}
impl SourceIdentity {
    pub fn validate(&self) -> Result<()> {
        if !(16..=128).contains(&self.instance_id.len())
            || !self
                .instance_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || !key(&self.genesis_hash)
            || !key(&self.node_identity)
            || !(7..=128).contains(&self.agave_revision.len())
            || !self.agave_revision.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(Error::Invalid("source identity"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BankContext {
    pub slot: u64,
    pub bank_id: u64,
    pub blockhash: String,
    pub parent_slot: u64,
    /// An additional exact parent PoH constraint, when that proof is available.
    /// None omits only this constraint; it does not permit another Bank.
    #[serde(deserialize_with = "required_option")]
    pub parent_blockhash: Option<String>,
}
impl BankContext {
    pub fn validate(&self) -> Result<()> {
        if !key(&self.blockhash)
            || self
                .parent_blockhash
                .as_deref()
                .is_some_and(|hash| !key(hash))
            || self.parent_slot > self.slot
            || (self.slot != 0 && self.parent_slot == self.slot)
        {
            return Err(Error::Invalid("Bank context"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolLimits {
    pub max_request_bytes: u32,
    pub max_response_bytes: u32,
    pub max_accounts: u32,
}
impl Default for ProtocolLimits {
    fn default() -> Self {
        Self {
            max_request_bytes: MAX_REQUEST_BYTES as u32,
            max_response_bytes: MAX_RESPONSE_BYTES as u32,
            max_accounts: MAX_ACCOUNTS as u32,
        }
    }
}
impl ProtocolLimits {
    pub fn validate(&self) -> Result<()> {
        if !(1..=MAX_REQUEST_BYTES as u32).contains(&self.max_request_bytes)
            || !(1..=MAX_RESPONSE_BYTES as u32).contains(&self.max_response_bytes)
            || !(1..=MAX_ACCOUNTS as u32).contains(&self.max_accounts)
        {
            return Err(Error::Invalid("advertised limits"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Describe,
    GetAccount {
        bank: BankContext,
        pubkey: String,
    },
    GetMultipleAccounts {
        bank: BankContext,
        pubkeys: Vec<String>,
    },
    /// Read one complete rooted ledger block. No unrooted fallback is allowed.
    GetBlock {
        slot: u64,
        #[serde(deserialize_with = "required_option")]
        expected_blockhash: Option<String>,
    },
}
impl Operation {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Describe => Ok(()),
            Self::GetAccount { bank, pubkey } => {
                bank.validate()?;
                if !key(pubkey) {
                    return Err(Error::Invalid("pubkey"));
                }
                Ok(())
            }
            Self::GetMultipleAccounts { bank, pubkeys } => {
                bank.validate()?;
                if pubkeys.is_empty()
                    || pubkeys.len() > MAX_ACCOUNTS
                    || pubkeys.iter().any(|p| !key(p))
                {
                    return Err(Error::Invalid("pubkey list"));
                }
                Ok(())
            }
            Self::GetBlock {
                expected_blockhash, ..
            } => {
                if expected_blockhash.as_deref().is_some_and(|hash| !key(hash)) {
                    return Err(Error::Invalid("expected blockhash"));
                }
                Ok(())
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u16,
    pub request_id: u64,
    pub expected_source: SourceIdentity,
    pub operation: Operation,
}
impl Request {
    pub fn new(request_id: u64, expected_source: SourceIdentity, operation: Operation) -> Self {
        Self {
            version: VERSION,
            request_id,
            expected_source,
            operation,
        }
    }
    pub fn validate(&self) -> Result<()> {
        if self.version != VERSION || self.request_id == 0 {
            return Err(Error::Invalid("version or request ID"));
        }
        self.expected_source.validate()?;
        self.operation.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub lamports: u64,
    pub owner: String,
    pub executable: bool,
    pub rent_epoch: u64,
    pub data_base64: String,
}
impl Account {
    pub fn validate(&self) -> Result<()> {
        if !key(&self.owner) || self.data_base64.len() > MAX_ACCOUNT_DATA_BYTES.div_ceil(3) * 4 {
            return Err(Error::Invalid("account owner or data size"));
        }
        let data = STANDARD
            .decode(&self.data_base64)
            .map_err(|_| Error::Invalid("account base64"))?;
        if data.len() > MAX_ACCOUNT_DATA_BYTES || STANDARD.encode(&data) != self.data_base64 {
            return Err(Error::Invalid("account base64"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountEntry {
    pub pubkey: String,
    #[serde(deserialize_with = "required_option")]
    pub account: Option<Account>,
}
impl AccountEntry {
    pub fn validate(&self) -> Result<()> {
        if !key(&self.pubkey) {
            return Err(Error::Invalid("response pubkey"));
        }
        if let Some(account) = &self.account {
            account.validate()?;
        }
        Ok(())
    }
}

/// Owned executed block from the native ledger, admitted only after rooting.
/// This value does not contain a Bank handle or an AccountsDB storage path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerBlock {
    pub slot: u64,
    pub blockhash: String,
    pub previous_blockhash: String,
    pub parent_slot: u64,
    pub block_time: i64,
    pub block_height: u64,
    pub transactions: Vec<LedgerTransaction>,
    pub rewards: serde_json::Value,
    #[serde(deserialize_with = "required_option")]
    pub num_partitions: Option<u64>,
}
impl LedgerBlock {
    pub fn validate(&self) -> Result<()> {
        if !key(&self.blockhash)
            || !key(&self.previous_blockhash)
            || self.parent_slot > self.slot
            || (self.slot != 0 && self.parent_slot == self.slot)
            || self.transactions.len() > MAX_BLOCK_TRANSACTIONS
            || !self.rewards.is_array()
        {
            return Err(Error::Invalid("ledger block"));
        }
        for transaction in &self.transactions {
            transaction.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerTransaction {
    /// Canonical base64 of the serialized signed transaction, not JSON RPC data.
    pub transaction_base64: String,
    pub execution: ExecutionMetadata,
}
impl LedgerTransaction {
    pub fn validate(&self) -> Result<()> {
        if self.transaction_base64.is_empty()
            || self.transaction_base64.len() > MAX_TRANSACTION_BYTES.div_ceil(3) * 4
        {
            return Err(Error::Invalid("transaction base64 size"));
        }
        let bytes = STANDARD
            .decode(&self.transaction_base64)
            .map_err(|_| Error::Invalid("transaction base64"))?;
        let transaction_limit = if bytes.first() == Some(&V1_TRANSACTION_PREFIX) {
            MAX_TRANSACTION_BYTES
        } else {
            MAX_LEGACY_TRANSACTION_BYTES
        };
        if bytes.is_empty()
            || bytes.len() > transaction_limit
            || STANDARD.encode(bytes) != self.transaction_base64
        {
            return Err(Error::Invalid("transaction base64"));
        }
        self.execution.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionMetadata {
    #[serde(deserialize_with = "required_option")]
    pub error: Option<serde_json::Value>,
    pub fee: u64,
    pub pre_balances: Vec<u64>,
    pub post_balances: Vec<u64>,
    #[serde(deserialize_with = "required_option")]
    pub inner_instructions: Option<serde_json::Value>,
    #[serde(deserialize_with = "required_option")]
    pub pre_token_balances: Option<serde_json::Value>,
    #[serde(deserialize_with = "required_option")]
    pub post_token_balances: Option<serde_json::Value>,
    #[serde(deserialize_with = "required_option")]
    pub rewards: Option<serde_json::Value>,
    #[serde(deserialize_with = "required_option")]
    pub log_messages: Option<Vec<String>>,
    pub loaded_addresses: LoadedAddresses,
    #[serde(deserialize_with = "required_option")]
    pub return_data: Option<ReturnData>,
    #[serde(deserialize_with = "required_option")]
    pub compute_units_consumed: Option<u64>,
    #[serde(deserialize_with = "required_option")]
    pub cost_units: Option<u64>,
}
impl ExecutionMetadata {
    pub fn validate(&self) -> Result<()> {
        if self.pre_balances.len() != self.post_balances.len()
            || self.error.as_ref().is_some_and(serde_json::Value::is_null)
            || [
                &self.inner_instructions,
                &self.pre_token_balances,
                &self.post_token_balances,
                &self.rewards,
            ]
            .iter()
            .any(|value| value.as_ref().is_some_and(|value| !value.is_array()))
        {
            return Err(Error::Invalid("execution metadata"));
        }
        self.loaded_addresses.validate()?;
        if let Some(data) = &self.return_data {
            data.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadedAddresses {
    pub writable: Vec<String>,
    pub readonly: Vec<String>,
}
impl LoadedAddresses {
    pub fn validate(&self) -> Result<()> {
        if self
            .writable
            .iter()
            .chain(&self.readonly)
            .any(|address| !key(address))
        {
            return Err(Error::Invalid("loaded address"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReturnData {
    pub program_id: String,
    pub data_base64: String,
}
impl ReturnData {
    pub fn validate(&self) -> Result<()> {
        // The frame cap is the wire bound. Return data is intentionally not
        // assigned the transaction's 1232-byte packet bound.
        if !key(&self.program_id) || self.data_base64.len() > MAX_RESPONSE_BYTES {
            return Err(Error::Invalid("return data"));
        }
        let bytes = STANDARD
            .decode(&self.data_base64)
            .map_err(|_| Error::Invalid("return data base64"))?;
        if STANDARD.encode(bytes) != self.data_base64 {
            return Err(Error::Invalid("return data base64"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeErrorCode {
    BankRemoved,
    StaleBank,
    SourceMismatch,
    BudgetExceeded,
    InvalidRequest,
    BlockUnavailable,
    BlockNotFinalized,
    BlockMetadataIncomplete,
    BlockHashMismatch,
    Internal,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeError {
    pub code: BridgeErrorCode,
    pub message: String,
}
impl BridgeError {
    pub fn new(code: BridgeErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
    fn validate(&self) -> Result<()> {
        if self.message.is_empty()
            || self.message.len() > MAX_ERROR_MESSAGE_BYTES
            || self.message.chars().any(char::is_control)
        {
            return Err(Error::Invalid("error message"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResponseData {
    Describe {
        limits: ProtocolLimits,
    },
    GetAccount {
        bank: BankContext,
        entry: AccountEntry,
    },
    GetMultipleAccounts {
        bank: BankContext,
        entries: Vec<AccountEntry>,
    },
    GetBlock {
        block: LedgerBlock,
    },
}
impl ResponseData {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Describe { limits } => limits.validate(),
            Self::GetAccount { bank, entry } => {
                bank.validate()?;
                entry.validate()
            }
            Self::GetMultipleAccounts { bank, entries } => {
                bank.validate()?;
                if entries.is_empty() || entries.len() > MAX_ACCOUNTS {
                    return Err(Error::Invalid("response account count"));
                }
                for entry in entries {
                    entry.validate()?;
                }
                for (at, entry) in entries.iter().enumerate() {
                    if entries[..at]
                        .iter()
                        .any(|old| old.pubkey == entry.pubkey && old.account != entry.account)
                    {
                        return Err(Error::AccountOrderMismatch);
                    }
                }
                Ok(())
            }
            Self::GetBlock { block } => block.validate(),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Outcome {
    Ok(ResponseData),
    Error(BridgeError),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub version: u16,
    pub request_id: u64,
    pub source: SourceIdentity,
    pub outcome: Outcome,
}
impl Response {
    pub fn ok(request: &Request, source: SourceIdentity, data: ResponseData) -> Self {
        Self {
            version: VERSION,
            request_id: request.request_id,
            source,
            outcome: Outcome::Ok(data),
        }
    }
    pub fn error(
        request: &Request,
        source: SourceIdentity,
        code: BridgeErrorCode,
        message: impl Into<String>,
    ) -> Self {
        Self {
            version: VERSION,
            request_id: request.request_id,
            source,
            outcome: Outcome::Error(BridgeError::new(code, message)),
        }
    }
    pub fn validate(&self) -> Result<()> {
        if self.version != VERSION || self.request_id == 0 {
            return Err(Error::Invalid("version or request ID"));
        }
        self.source.validate()?;
        match &self.outcome {
            Outcome::Ok(data) => data.validate(),
            Outcome::Error(error) => error.validate(),
        }
    }
    pub fn validate_for(&self, request: &Request) -> Result<()> {
        request.validate()?;
        self.validate()?;
        if self.request_id != request.request_id {
            return Err(Error::RequestIdMismatch);
        }
        if self.source != request.expected_source {
            return Err(Error::SourceMismatch);
        }
        let Outcome::Ok(data) = &self.outcome else {
            return Ok(());
        };
        match (&request.operation, data) {
            (Operation::Describe, ResponseData::Describe { .. }) => Ok(()),
            (
                Operation::GetAccount { bank, pubkey },
                ResponseData::GetAccount {
                    bank: actual,
                    entry,
                },
            ) => {
                if bank != actual {
                    return Err(Error::BankMismatch);
                }
                if pubkey != &entry.pubkey {
                    return Err(Error::AccountOrderMismatch);
                }
                Ok(())
            }
            (
                Operation::GetMultipleAccounts { bank, pubkeys },
                ResponseData::GetMultipleAccounts {
                    bank: actual,
                    entries,
                },
            ) => {
                if bank != actual {
                    return Err(Error::BankMismatch);
                }
                if entries.len() != pubkeys.len()
                    || pubkeys
                        .iter()
                        .zip(entries)
                        .any(|(key, entry)| key != &entry.pubkey)
                {
                    return Err(Error::AccountOrderMismatch);
                }
                Ok(())
            }
            (
                Operation::GetBlock {
                    slot,
                    expected_blockhash,
                },
                ResponseData::GetBlock { block },
            ) => {
                if *slot != block.slot
                    || expected_blockhash
                        .as_ref()
                        .is_some_and(|hash| hash != &block.blockhash)
                {
                    return Err(Error::BlockMismatch);
                }
                Ok(())
            }
            _ => Err(Error::OperationMismatch),
        }
    }
}

fn decode_json<T: DeserializeOwned>(bytes: &[u8], limit: usize) -> Result<T> {
    if bytes.len() > limit {
        return Err(Error::FrameTooLarge {
            bytes: bytes.len(),
            limit,
        });
    }
    if bytes.is_empty() {
        return Err(Error::Invalid("empty frame"));
    }
    Ok(serde_json::from_slice(bytes)?)
}
struct BoundedJson {
    bytes: Vec<u8>,
    limit: usize,
    overflow: Option<usize>,
}
impl Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let total = self.bytes.len().saturating_add(bytes.len());
        if total > self.limit {
            self.overflow = Some(total);
            return Err(io::Error::other("bridge JSON byte limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn encode_json(value: &impl Serialize, limit: usize) -> Result<Vec<u8>> {
    let mut buffer = BoundedJson {
        bytes: Vec::new(),
        limit,
        overflow: None,
    };
    if let Err(error) = serde_json::to_writer(&mut buffer, value) {
        if let Some(bytes) = buffer.overflow {
            return Err(Error::FrameTooLarge { bytes, limit });
        }
        return Err(error.into());
    }
    Ok(buffer.bytes)
}
pub fn encode_request(request: &Request) -> Result<Vec<u8>> {
    request.validate()?;
    encode_json(request, MAX_REQUEST_BYTES)
}
pub fn decode_request(bytes: &[u8]) -> Result<Request> {
    let request: Request = decode_json(bytes, MAX_REQUEST_BYTES)?;
    request.validate()?;
    Ok(request)
}
pub fn encode_response(response: &Response) -> Result<Vec<u8>> {
    response.validate()?;
    encode_json(response, MAX_RESPONSE_BYTES)
}
pub fn decode_response(bytes: &[u8]) -> Result<Response> {
    let response: Response = decode_json(bytes, MAX_RESPONSE_BYTES)?;
    response.validate()?;
    Ok(response)
}
fn read_frame(reader: &mut impl Read, limit: usize) -> Result<Vec<u8>> {
    let mut length = [0; 4];
    reader.read_exact(&mut length)?;
    let bytes = u32::from_be_bytes(length) as usize;
    if bytes > limit {
        return Err(Error::FrameTooLarge { bytes, limit });
    }
    if bytes == 0 {
        return Err(Error::Invalid("empty frame"));
    }
    let mut payload = vec![0; bytes];
    reader.read_exact(&mut payload)?;
    Ok(payload)
}
fn write_frame(writer: &mut impl Write, bytes: &[u8]) -> Result<()> {
    writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
    writer.write_all(bytes)?;
    writer.flush()?;
    Ok(())
}
pub fn read_request(reader: &mut impl Read) -> Result<Request> {
    decode_request(&read_frame(reader, MAX_REQUEST_BYTES)?)
}
pub fn write_request(writer: &mut impl Write, request: &Request) -> Result<()> {
    write_frame(writer, &encode_request(request)?)
}
pub fn read_response(reader: &mut impl Read) -> Result<Response> {
    decode_response(&read_frame(reader, MAX_RESPONSE_BYTES)?)
}
pub fn write_response(writer: &mut impl Write, response: &Response) -> Result<()> {
    write_frame(writer, &encode_response(response)?)
}

#[cfg(test)]
mod tests;
