//! Private Unix-socket client for owned account and rooted ledger block reads.
//!
//! Source identity is operator-pinned at construction. Describe checks that pin;
//! it never discovers and trusts a new instance. Requests are not retried, and a
//! missing Bank is never replaced with a newer Bank.

#[cfg(not(unix))]
compile_error!("blockzilla-account-client requires Unix domain sockets");

use blockzilla_account_bridge_protocol::{self as protocol, Outcome, Request, ResponseData};
pub use blockzilla_account_bridge_protocol::{
    Account, AccountEntry, BankContext, BridgeError, BridgeErrorCode, ExecutionMetadata,
    LedgerBlock, LedgerTransaction, LoadedAddresses, Operation, ProtocolLimits, ReturnData,
    SourceIdentity,
};
use std::{
    fmt, io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

static REQUEST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug)]
pub struct ClientOptions {
    /// One bound for connect, request transmission, and the complete response.
    pub timeout: Duration,
    pub max_response_bytes: usize,
}
impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(8),
            max_response_bytes: protocol::MAX_RESPONSE_BYTES,
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Configuration(&'static str),
    Io(io::Error),
    Timeout,
    Protocol(protocol::Error),
    Remote(BridgeError),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(reason) => {
                write!(f, "invalid native account client configuration: {reason}")
            }
            Self::Io(error) => write!(f, "native account bridge I/O: {error}"),
            Self::Timeout => f.write_str("native account bridge request timed out"),
            Self::Protocol(error) => write!(f, "native account bridge admission: {error}"),
            Self::Remote(error) => write!(
                f,
                "native account bridge {:?}: {}",
                error.code, error.message
            ),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Protocol(error) => Some(error),
            _ => None,
        }
    }
}
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<protocol::Error> for Error {
    fn from(error: protocol::Error) -> Self {
        Self::Protocol(error)
    }
}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug)]
pub struct AccountClient {
    socket: PathBuf,
    source: SourceIdentity,
    options: ClientOptions,
}
impl AccountClient {
    pub fn new(
        socket: impl Into<PathBuf>,
        source: SourceIdentity,
        options: ClientOptions,
    ) -> Result<Self> {
        let socket = socket.into();
        if !socket.is_absolute() {
            return Err(Error::Configuration("socket path must be absolute"));
        }
        if options.timeout.is_zero()
            || options.timeout > Duration::from_secs(60)
            || options.max_response_bytes == 0
            || options.max_response_bytes > protocol::MAX_RESPONSE_BYTES
        {
            return Err(Error::Configuration(
                "invalid timeout or response byte limit",
            ));
        }
        source.validate()?;
        Ok(Self {
            socket,
            source,
            options,
        })
    }
    pub fn source(&self) -> &SourceIdentity {
        &self.source
    }
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Validate the operator-pinned instance and obtain its advertised limits.
    pub async fn describe(&self) -> Result<ProtocolLimits> {
        match self.execute(Operation::Describe).await? {
            ResponseData::Describe { limits } => Ok(limits),
            _ => unreachable!("response operation was admitted"),
        }
    }
    pub async fn get_account(&self, bank: &BankContext, pubkey: &str) -> Result<Option<Account>> {
        match self
            .execute(Operation::GetAccount {
                bank: bank.clone(),
                pubkey: pubkey.into(),
            })
            .await?
        {
            ResponseData::GetAccount { entry, .. } => Ok(entry.account),
            _ => unreachable!("response operation was admitted"),
        }
    }
    /// Return one entry for each input, in input order, including duplicates.
    pub async fn get_multiple_accounts(
        &self,
        bank: &BankContext,
        pubkeys: &[String],
    ) -> Result<Vec<AccountEntry>> {
        match self
            .execute(Operation::GetMultipleAccounts {
                bank: bank.clone(),
                pubkeys: pubkeys.into(),
            })
            .await?
        {
            ResponseData::GetMultipleAccounts { entries, .. } => Ok(entries),
            _ => unreachable!("response operation was admitted"),
        }
    }
    /// Return one complete finalized ledger block, with an optional exact hash pin.
    /// An unavailable block is a typed error, never an empty or skipped block.
    pub async fn get_block(
        &self,
        slot: u64,
        expected_blockhash: Option<&str>,
    ) -> Result<LedgerBlock> {
        match self
            .execute(Operation::GetBlock {
                slot,
                expected_blockhash: expected_blockhash.map(str::to_owned),
            })
            .await?
        {
            ResponseData::GetBlock { block } => Ok(block),
            _ => unreachable!("response operation was admitted"),
        }
    }
    pub async fn execute(&self, operation: Operation) -> Result<ResponseData> {
        let request_id = REQUEST_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| Error::Configuration("request ID space exhausted"))?;
        let request = Request::new(request_id, self.source.clone(), operation);
        // Fail invalid requests before any connection. The body is bounded while
        // it is serialized, rather than after constructing an unbounded frame.
        let payload = protocol::encode_request(&request)?;
        let started = Instant::now();
        let response = tokio::time::timeout(self.options.timeout, async {
            let mut socket = UnixStream::connect(&self.socket).await?;
            socket
                .write_all(&(payload.len() as u32).to_be_bytes())
                .await?;
            socket.write_all(&payload).await?;
            let mut header = [0; 4];
            socket.read_exact(&mut header).await?;
            let bytes = u32::from_be_bytes(header) as usize;
            if bytes > self.options.max_response_bytes {
                return Err(Error::Protocol(protocol::Error::FrameTooLarge {
                    bytes,
                    limit: self.options.max_response_bytes,
                }));
            }
            if bytes == 0 {
                return Err(Error::Protocol(protocol::Error::Invalid("empty frame")));
            }
            let mut payload = vec![0; bytes];
            socket.read_exact(&mut payload).await?;
            let response = protocol::decode_response(&payload)?;
            response.validate_for(&request)?;
            Ok::<_, Error>(response)
        })
        .await
        .map_err(|_| Error::Timeout)??;
        // The JSON decoder is synchronous but byte-bounded. Do not return a
        // result if that last admission step passed the request's deadline.
        if started.elapsed() >= self.options.timeout {
            return Err(Error::Timeout);
        }
        match response.outcome {
            Outcome::Ok(data) => Ok(data),
            Outcome::Error(error) => Err(Error::Remote(error)),
        }
    }
}

#[cfg(test)]
mod tests;
