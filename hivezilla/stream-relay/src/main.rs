use anyhow::{Context, Result, ensure};
use clap::{Args, Parser, Subcommand};
use hivezilla_stream::{
    server::{Api, Tls},
    source::{Source, bounded_file},
    store::Store,
    upstream::Upstream,
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::Semaphore;

#[derive(Parser)]
#[command(about = "Read-only compact bank origin and shared Rust relay")]
struct Cli {
    #[command(subcommand)]
    command: Mode,
}
#[derive(Subcommand)]
enum Mode {
    /// Publish the same immutable feed frames to a separate native R2 namespace.
    Publish(hivezilla_stream::publisher::Options),
    /// Private native v2 origin; requires a separate durable spool.
    BankOrigin {
        #[command(flatten)]
        http: Http,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        spool: PathBuf,
        /// Fixed required consumers; acknowledgements cannot create consumers.
        #[arg(long = "ack-consumer")]
        ack_consumers: Vec<String>,
        /// Beam original frames from the producer-owned rolling window. No
        /// origin spool, application projection or consumer ACK is used.
        #[arg(long, conflicts_with = "ack_consumers", requires = "unix_socket")]
        direct_beam: bool,
    },
    /// Relay native v2 banks with a bounded replay window in memory.
    BankRelay {
        #[command(flatten)]
        http: Http,
        #[arg(long)]
        upstream: String,
        #[arg(long)]
        upstream_token_file: PathBuf,
        #[arg(long)]
        upstream_ca: Option<PathBuf>,
        #[arg(long)]
        upstream_identity: Option<PathBuf>,
        #[arg(long)]
        source_file: PathBuf,
        /// Serve public signing blockhashes and confirmed block signatures.
        #[arg(long)]
        public_bank_views: bool,
        #[arg(long, default_value_t = 8)]
        public_max_requests: usize,
    },
    Origin {
        #[command(flatten)]
        http: Http,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        start_slot: Option<u64>,
        #[arg(long, conflicts_with = "start_slot")]
        tail_slots: Option<u64>,
        #[arg(long, conflicts_with_all=["start_slot","tail_slots"])]
        processed: bool,
        #[arg(long, requires = "processed")]
        start_sequence: Option<u64>,
        #[arg(long, requires = "processed", conflicts_with = "start_sequence")]
        tail_events: Option<u64>,
    },
    Relay {
        #[command(flatten)]
        http: Http,
        #[arg(long)]
        upstream: String,
        #[arg(long)]
        upstream_token_file: PathBuf,
        #[arg(long)]
        upstream_ca: Option<PathBuf>,
        #[arg(long)]
        upstream_identity: Option<PathBuf>,
        #[arg(long)]
        spool: PathBuf,
        /// Permit api_key in the request URL for browser demos.
        #[arg(long)]
        allow_query_api_key: bool,
        /// Serve small processed bank identities without an API key.
        #[arg(long)]
        public_blockhashes: bool,
        #[arg(long, default_value_t = 8)]
        public_max_requests: usize,
        /// Add the separate v2 bank profile. The expected source is operator pinned.
        #[arg(long,requires_all=["banks_source_file","banks_spool"])]
        banks_upstream: Option<String>,
        #[arg(long, requires = "banks_upstream")]
        banks_source_file: Option<PathBuf>,
        #[arg(long, requires = "banks_upstream")]
        banks_spool: Option<PathBuf>,
        /// Serve public signing blockhashes and confirmed block signatures.
        #[arg(long, requires = "banks_upstream")]
        public_bank_views: bool,
        #[arg(long, default_value_t = 4096, requires = "banks_upstream")]
        banks_replay_mib: usize,
    },
}
#[derive(Args)]
struct Http {
    #[arg(long, default_value = "127.0.0.1:8870", conflicts_with = "unix_socket")]
    bind: SocketAddr,
    /// Private local HTTP/SSE socket instead of a TCP listener.
    #[arg(long, conflicts_with_all = ["bind", "tls_cert", "tls_key", "client_ca"])]
    unix_socket: Option<PathBuf>,
    #[arg(long)]
    token_file: PathBuf,
    #[arg(long)]
    tls_cert: Option<PathBuf>,
    #[arg(long)]
    tls_key: Option<PathBuf>,
    #[arg(long)]
    client_ca: Option<PathBuf>,
    #[arg(long)]
    cors_origin: Option<String>,
    #[arg(long, default_value_t = 128)]
    replay_mib: usize,
    #[arg(long, default_value_t = 32)]
    max_requests: usize,
}
fn token(p: &std::path::Path) -> Result<String> {
    let value = String::from_utf8(bounded_file(p, 4096)?)?.trim().to_owned();
    ensure!(
        (32..=256).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_graphic()),
        "invalid_token_file"
    );
    Ok(value)
}
fn api(http: &Http, store: Arc<Store>) -> Result<Api> {
    ensure!(
        (1..=1024).contains(&http.max_requests),
        "invalid_connection_budget"
    );
    if let Some(o) = &http.cors_origin {
        let u = reqwest::Url::parse(o)?;
        ensure!(
            matches!(u.scheme(), "http" | "https") && *o == u.origin().ascii_serialization(),
            "cors_requires_one_exact_origin"
        );
    }
    Ok(Api {
        store,
        token: Arc::new(token(&http.token_file)?),
        cors: http.cors_origin.clone(),
        requests: Arc::new(Semaphore::new(http.max_requests)),
        allow_query_api_key: false,
        public_blockhashes: false,
        public_requests: Arc::new(Semaphore::new(0)),
        banks: None,
        bank_only: false,
    })
}
async fn serve(http: Http, api: Api, origin: bool) -> Result<()> {
    if let Some(socket) = http.unix_socket {
        return tokio::select! {
            r=hivezilla_stream::server::serve_unix(socket,api)=>r,
            _=tokio::signal::ctrl_c()=>Ok(())
        };
    }
    let tls = Tls {
        cert: http.tls_cert,
        key: http.tls_key,
        client_ca: http.client_ca,
    };
    tokio::select! { r=hivezilla_stream::server::serve(http.bind,api,tls,origin)=>r,
    _=tokio::signal::ctrl_c()=>Ok(()) }
}
#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    match Cli::parse().command {
        Mode::Publish(options) => {
            tokio::task::spawn_blocking(move || hivezilla_stream::publisher::run(options)).await?
        }
        Mode::BankOrigin {
            http,
            output,
            spool,
            ack_consumers,
            direct_beam,
        } => {
            use blockzilla_bank_stream_v2::Frame;
            use hivezilla_stream::{
                bank_server::BankApi, bank_source::BankSource, bank_store::BankStore,
            };
            let output = output
                .canonicalize()
                .context("resolve bank origin output")?;
            let mut source = BankSource::open(&output)?;
            if !ack_consumers.is_empty() {
                hivezilla_stream::consumer_ack::configure(&output, &source.source, &ack_consumers)?;
            }
            let base = if direct_beam {
                source.validate_beam_authority()?;
                source.replay_floor_cursor()?
            } else {
                blockzilla_bank_stream_v2::cursor(&source.source.session_id, 0, "-")
            };
            let banks = if direct_beam {
                BankStore::open_memory(
                    source.source.clone(),
                    base,
                    blockzilla_bank_stream_v2::MAX_FRAME,
                )?
            } else {
                BankStore::open(
                    source.source.clone(),
                    base,
                    http.replay_mib
                        .checked_mul(1024 * 1024)
                        .context("budget_overflow")?,
                    spool,
                )?
            };
            let store = banks.clone();
            let (intake_failed, intake_failure) = tokio::sync::oneshot::channel::<String>();
            if !direct_beam {
                source.seek(&banks.latest())?;
                std::thread::spawn(move || {
                    loop {
                        let result = (|| -> Result<bool> {
                            let status = source.health()?;
                            store.set_health(status, None);
                            ensure!(status != "failed", "source_failed");
                            let mut batch: Vec<(Frame, Option<Frame>)> = Vec::new();
                            let mut batch_bytes = 0;
                            let mut progressed = false;
                            for _ in 0..hivezilla_stream::bank_store::MAX_BATCH_EVENTS {
                                let Some(f) = source.next()? else { break };
                                let dep = if let Some(sha) = &f.envelope.event.payload_frame_sha256
                                {
                                    if store.chunk(sha).is_none()
                                        && !batch.iter().any(|(f, dep)| {
                                            &f.sha256 == sha
                                                || dep.as_ref().is_some_and(|d| &d.sha256 == sha)
                                        })
                                    {
                                        source.chunk(sha)?
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                };
                                let bytes = f.wire.len() + dep.as_ref().map_or(0, |f| f.wire.len());
                                if batch_bytes + bytes
                                    > hivezilla_stream::bank_store::MAX_BATCH_BYTES
                                {
                                    store.admit_batch(std::mem::take(&mut batch))?;
                                    batch_bytes = 0;
                                }
                                batch_bytes += bytes;
                                batch.push((f, dep));
                                progressed = true;
                            }
                            if !batch.is_empty() {
                                store.admit_batch(batch)?;
                            }
                            Ok(progressed)
                        })();
                        if let Err(e) = result {
                            store.set_health("failed", Some(e.to_string()));
                            let _ = intake_failed.send(format!("{e:#}"));
                            return;
                        }
                        if !result.unwrap() {
                            std::thread::sleep(Duration::from_millis(20));
                        }
                    }
                });
            }
            let dummy = Store::open(
                format!("{}:0:-", banks.source.session_id),
                16 * 1024 * 1024 + 65552,
                None,
            )?;
            let mut a = api(&http, dummy)?;
            a.bank_only = true;
            a.banks = Some(BankApi {
                store: banks,
                origin: true,
                output: Some(output),
                public_views: None,
                hot_upstream: None,
                direct_beam,
            });
            tokio::select! {
                result=serve(http,a,true)=>result,
                failure=async { if direct_beam { std::future::pending::<std::result::Result<String,tokio::sync::oneshot::error::RecvError>>().await } else { intake_failure.await } }=>anyhow::bail!("bank_origin_intake_failed: {}", failure.unwrap_or_else(|_| "intake_thread_stopped".into())),
            }
        }
        Mode::BankRelay {
            http,
            upstream,
            upstream_token_file,
            upstream_ca,
            upstream_identity,
            source_file,
            public_bank_views,
            public_max_requests,
        } => {
            use hivezilla_stream::{bank_server::BankApi, bank_store::BankStore, bank_upstream};

            ensure!(
                (1..=128).contains(&public_max_requests),
                "invalid_public_request_budget"
            );
            let expected: blockzilla_bank_stream_v2::SourceIdentity =
                serde_json::from_slice(&bounded_file(&source_file, 65536)?)?;
            let base = blockzilla_bank_stream_v2::cursor(&expected.session_id, 0, "-");
            let banks = BankStore::open_memory(
                expected,
                base,
                http.replay_mib
                    .checked_mul(1024 * 1024)
                    .context("budget_overflow")?,
            )?;
            let u = Upstream {
                url: format!("{}/", upstream.trim_end_matches('/')),
                token: token(&upstream_token_file)?,
                ca: upstream_ca,
                identity: upstream_identity,
            };
            let client = u.client()?;
            let dummy = Store::open(
                format!("{}:0:-", banks.source.session_id),
                16 * 1024 * 1024 + 65552,
                None,
            )?;
            let mut a = api(&http, dummy)?;
            a.bank_only = true;
            a.public_requests = Arc::new(Semaphore::new(public_max_requests));
            a.banks = Some(BankApi {
                store: banks.clone(),
                origin: false,
                output: None,
                public_views: public_bank_views.then(Default::default),
                hot_upstream: Some((u.clone(), client.clone())),
                direct_beam: false,
            });
            tokio::spawn(bank_upstream::run(u, client, banks));
            serve(http, a, false).await
        }
        Mode::Origin {
            http,
            output,
            start_slot,
            tail_slots,
            processed,
            start_sequence,
            tail_events,
        } => {
            let source = if processed {
                Source::open_processed(&output, start_sequence, tail_events.unwrap_or(256))?
            } else {
                let start_slot = if let Some(s) = start_slot {
                    s
                } else {
                    let cursor: serde_json::Value =
                        serde_json::from_slice(&bounded_file(&output.join("CURSOR.json"), 65536)?)?;
                    let tail = tail_slots.unwrap_or(256);
                    ensure!((1..=4096).contains(&tail), "invalid_tail_window");
                    cursor["last_slot"]
                        .as_u64()
                        .context("missing_commit_cursor")?
                        .saturating_sub(tail)
                        .max(1)
                };
                Source::open(&output, start_slot)?
            };
            let store = Store::open(
                source.anchor(),
                http.replay_mib
                    .checked_mul(1024 * 1024)
                    .context("budget_overflow")?,
                None,
            )?;
            let reader_store = store.clone();
            std::thread::spawn(move || {
                let mut source = source;
                loop {
                    match source.next_chunk() {
                        Ok(Some(c)) => {
                            if let Err(e) = reader_store.admit(c) {
                                reader_store.set_status("FAILED", Some(e.to_string()));
                                return;
                            }
                        }
                        Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                        Err(e) => {
                            reader_store.set_status("FAILED", Some(e.to_string()));
                            return;
                        }
                    }
                }
            });
            let a = api(&http, store)?;
            serve(http, a, true).await
        }
        Mode::Relay {
            http,
            upstream,
            upstream_token_file,
            upstream_ca,
            upstream_identity,
            spool,
            allow_query_api_key,
            public_blockhashes,
            public_max_requests,
            banks_upstream,
            banks_source_file,
            banks_spool,
            public_bank_views,
            banks_replay_mib,
        } => {
            let u = Upstream {
                url: format!("{}/", upstream.trim_end_matches('/')),
                token: token(&upstream_token_file)?,
                ca: upstream_ca,
                identity: upstream_identity,
            };
            let client = u.client()?;
            let head = u.head(&client).await?;
            let base = head["latest_cursor"]
                .as_str()
                .context("missing_upstream_cursor")?
                .to_owned();
            let store = Store::open(
                base,
                http.replay_mib
                    .checked_mul(1024 * 1024)
                    .context("budget_overflow")?,
                Some(spool),
            )?;
            ensure!(
                (1..=128).contains(&public_max_requests),
                "invalid_public_request_budget"
            );
            let mut a = api(&http, store.clone())?;
            a.allow_query_api_key = allow_query_api_key;
            a.public_blockhashes = public_blockhashes;
            a.public_requests = Arc::new(Semaphore::new(public_max_requests));
            if let Some(url) = banks_upstream {
                use hivezilla_stream::{
                    bank_server::BankApi, bank_store::BankStore, bank_upstream,
                };
                let expected: blockzilla_bank_stream_v2::SourceIdentity = serde_json::from_slice(
                    &bounded_file(&banks_source_file.context("missing_banks_source")?, 65536)?,
                )?;
                let bu = Upstream {
                    url: format!("{}/", url.trim_end_matches('/')),
                    token: u.token.clone(),
                    ca: u.ca.clone(),
                    identity: u.identity.clone(),
                };
                let bc = bu.client()?;
                let base = blockzilla_bank_stream_v2::cursor(&expected.session_id, 0, "-");
                let banks = BankStore::open(
                    expected,
                    base,
                    banks_replay_mib
                        .checked_mul(1024 * 1024)
                        .context("budget_overflow")?,
                    banks_spool.context("missing_banks_spool")?,
                )?;
                a.banks = Some(BankApi {
                    store: banks.clone(),
                    origin: false,
                    output: None,
                    public_views: public_bank_views.then(Default::default),
                    hot_upstream: Some((bu.clone(), bc.clone())),
                    direct_beam: false,
                });
                tokio::spawn(bank_upstream::run(bu, bc, banks));
            }
            tokio::spawn(u.run(client, store));
            serve(http, a, false).await
        }
    }
}

#[cfg(test)]
mod transport_tests {
    use super::*;
    fn arguments() -> Vec<&'static str> {
        vec![
            "hivezilla-stream",
            "bank-origin",
            "--output",
            "/tmp/output",
            "--spool",
            "/tmp/spool",
            "--token-file",
            "/tmp/key",
        ]
    }
    #[test]
    fn private_socket_and_fixed_consumer_are_opt_in_and_do_not_change_tcp_defaults() {
        let Mode::BankOrigin {
            http,
            ack_consumers,
            ..
        } = Cli::try_parse_from(arguments()).unwrap().command
        else {
            panic!()
        };
        assert_eq!(http.bind, "127.0.0.1:8870".parse::<SocketAddr>().unwrap());
        assert!(http.unix_socket.is_none());
        assert!(ack_consumers.is_empty());
        let mut args = arguments();
        args.extend([
            "--unix-socket",
            "/tmp/origin.sock",
            "--ack-consumer",
            "sidecar-primary",
        ]);
        let Mode::BankOrigin {
            http,
            ack_consumers,
            ..
        } = Cli::try_parse_from(args.clone()).unwrap().command
        else {
            panic!()
        };
        assert_eq!(http.unix_socket, Some(PathBuf::from("/tmp/origin.sock")));
        assert_eq!(ack_consumers, ["sidecar-primary"]);
        args.extend(["--bind", "127.0.0.1:8890"]);
        assert!(Cli::try_parse_from(args).is_err());
        let mut args = arguments();
        args.extend([
            "--unix-socket",
            "/tmp/origin.sock",
            "--tls-cert",
            "/tmp/cert",
        ]);
        assert!(Cli::try_parse_from(args).is_err());
    }
}
