use anyhow::{Context, Result, ensure};
use blockzilla_bank_client::{BankClient, ClientConfig, SourceIdentity};
use blockzilla_stream_sidecar::{
    config::{WebhookTarget, private_token},
    consume::{self, Runtime},
    projection::PayloadMode,
    server::{self, Api},
    store::{Limits, Store},
    webhook,
};
use clap::{ArgGroup, Parser};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::sync::Semaphore;
#[derive(Parser)]
#[command(about = "Local durable consumer of one pinned Compact V2 bank stream")]
#[command(group(ArgGroup::new("upstream").required(true).multiple(false).args(["upstream_unix","upstream_https","upstream_ssh_host"])))]
struct Args {
    #[arg(long)]
    source_file: PathBuf,
    #[arg(long)]
    producer_generation: String,
    #[arg(long)]
    upstream_unix: Option<PathBuf>,
    #[arg(long)]
    upstream_https: Option<String>,
    #[arg(
        long,
        required_unless_present = "upstream_ssh_host",
        conflicts_with = "upstream_ssh_host"
    )]
    upstream_token_file: Option<PathBuf>,
    #[arg(long,requires_all=["upstream_ssh_helper","upstream_ssh_job","runtime_generation"])]
    upstream_ssh_host: Option<String>,
    #[arg(long, requires = "upstream_ssh_host")]
    upstream_ssh_helper: Option<String>,
    #[arg(long, requires = "upstream_ssh_host")]
    upstream_ssh_job: Option<String>,
    #[arg(long, requires = "upstream_ssh_host")]
    runtime_generation: Option<String>,
    /// Exact retained block recovery after an interrupted raw stream.
    #[arg(long, requires_all = ["upstream_ssh_host", "recovery_worker_api_key_file"])]
    recovery_worker_url: Option<String>,
    /// Read the Worker API key from a private file. The key is never a CLI value.
    #[arg(long, requires_all = ["upstream_ssh_host", "recovery_worker_url"])]
    recovery_worker_api_key_file: Option<PathBuf>,
    #[arg(long,requires="upstream_ssh_host",conflicts_with_all=["initial_after","join_head"])]
    bootstrap_file: Option<PathBuf>,
    #[arg(long)]
    token_file: PathBuf,
    #[arg(long)]
    reader_token_file: Option<PathBuf>,
    #[arg(long)]
    database: PathBuf,
    /// Compact-only stores original frames and disables expanded JSON views.
    #[arg(long, value_enum, default_value = "full")]
    payload_mode: PayloadMode,
    #[arg(long, default_value = "sidecar-primary")]
    consumer_id: String,
    /// First use of a new database only. Existing databases resume their cursor.
    #[arg(long, conflicts_with = "join_head")]
    initial_after: Option<String>,
    /// Join the current head on first use. Earlier events are not applied.
    #[arg(long)]
    join_head: bool,
    #[arg(long)]
    webhook_config: Option<PathBuf>,
    #[arg(long, default_value = "127.0.0.1:18890")]
    bind: SocketAddr,
    #[arg(long)]
    listen_unix: Option<PathBuf>,
    #[arg(long, default_value_t = 512)]
    replay_mib: u64,
    #[arg(long, default_value_t = 8192)]
    replay_events: u64,
    #[arg(long, default_value_t = 16384)]
    database_mib: u64,
    #[arg(long, default_value_t = 0)]
    disk_reserve_mib: u64,
    #[arg(long, default_value_t = 16)]
    max_clients: usize,
}
fn read_json<T: serde::de::DeserializeOwned>(path: &std::path::Path, limit: u64) -> Result<T> {
    let m = std::fs::symlink_metadata(path)?;
    ensure!(
        m.is_file() && !m.file_type().is_symlink() && m.len() <= limit,
        "invalid_config_file"
    );
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}
#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let args = Args::parse();
    ensure!((1..=32).contains(&args.max_clients), "invalid_client_limit");
    let source: SourceIdentity = read_json(&args.source_file, 4096)?;
    source.validate()?;
    let recovery = args
        .recovery_worker_url
        .as_deref()
        .map(|url| {
            let key = blockzilla_stream_sidecar::config::recovery_api_key(
                args.recovery_worker_api_key_file
                    .as_deref()
                    .context("recovery_worker_api_key_file_required")?,
            )?;
            Ok::<_, anyhow::Error>(blockzilla_bank_client::WorkerRecoveryClient::new(
                blockzilla_bank_client::WorkerRecoveryConfig::new(url, key, source.clone()),
            )?)
        })
        .transpose()?;
    let token = Arc::new(private_token(&args.token_file)?);
    let reader_token = args
        .reader_token_file
        .as_deref()
        .map(private_token)
        .transpose()?
        .map(Arc::new);
    ensure!(
        reader_token
            .as_ref()
            .is_none_or(|reader| reader.as_str() != token.as_str()),
        "reader_token_must_differ_from_admin_token"
    );
    let targets: Vec<WebhookTarget> = args
        .webhook_config
        .as_deref()
        .map(|p| read_json(p, 65536))
        .transpose()?
        .unwrap_or_default();
    let limits = Limits {
        replay_bytes: args
            .replay_mib
            .checked_mul(1024 * 1024)
            .context("budget_overflow")?,
        replay_events: args.replay_events,
        database_bytes: args
            .database_mib
            .checked_mul(1024 * 1024)
            .context("budget_overflow")?,
    };
    ensure!(
        args.database.parent().is_some_and(|p| p.is_dir()),
        "database_parent_missing"
    );
    let store = Store::open_with_mode(
        &args.database,
        source.clone(),
        args.producer_generation.clone(),
        targets,
        limits,
        args.payload_mode,
        args.disk_reserve_mib
            .checked_mul(1024 * 1024)
            .context("disk_reserve_overflow")?,
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&args.database, std::fs::Permissions::from_mode(0o600))?;
    }
    let runtime = Arc::new(Runtime::default());
    let raw_mode = args.upstream_ssh_host.is_some();
    let (mut intake, mut ack, mut coverage) = if let Some(host) = args.upstream_ssh_host {
        let config = blockzilla_bank_client::ssh_beam::SshConfig {
            host,
            helper: args.upstream_ssh_helper.context("ssh_helper_required")?,
            job: args.upstream_ssh_job.context("ssh_job_required")?,
            generation: args
                .runtime_generation
                .context("runtime_generation_required")?,
            producer_generation: args.producer_generation,
            source: source.clone(),
        };
        config.validate()?;
        let bootstrap = args
            .bootstrap_file
            .as_deref()
            .map(|p| read_json(p, 65536))
            .transpose()?;
        runtime.begin_beam(&config.generation);
        let input = blockzilla_stream_sidecar::input::RawSshInput {
            config: config.clone(),
            initial_after: args.initial_after,
            join_head: args.join_head,
            bootstrap,
            recovery,
        };
        let db = store.clone();
        let health = runtime.clone();
        let intake =
            tokio::spawn(
                async move { blockzilla_stream_sidecar::input::run(input, db, health).await },
            );
        let db = store.clone();
        let health = runtime.clone();
        let reconcile = tokio::spawn(async move {
            blockzilla_stream_sidecar::input::reconcile(config, db, health).await
        });
        (
            intake,
            tokio::spawn(std::future::pending::<Result<()>>()),
            reconcile,
        )
    } else {
        let url = if args.upstream_unix.is_some() {
            "http://localhost/".to_owned()
        } else {
            args.upstream_https.context("upstream_required")?
        };
        let upstream_token = private_token(
            args.upstream_token_file
                .as_deref()
                .context("upstream_token_required")?,
        )?;
        let mut config = ClientConfig::new(url, upstream_token, source.clone());
        let mut control_config = config.clone();
        control_config.retry.max_retries = 0;
        config.max_in_flight = 16;
        let cache = store.payloads.clone();
        config.preprocess = Some(Arc::new(move |frame| {
            let cache = cache.clone();
            Box::pin(async move {
                cache.prepare(frame).await.map_err(|e| {
                    blockzilla_bank_client::ClientError::Protocol(format!(
                        "payload_preprocess_failed:{e}"
                    ))
                })
            })
        }));
        let (client, controls) = if let Some(socket) = args.upstream_unix {
            (
                BankClient::new_unix(config, socket.clone())?,
                BankClient::new_unix(control_config, socket)?,
            )
        } else {
            (BankClient::new(config)?, BankClient::new(control_config)?)
        };
        (
            tokio::spawn(consume::run(
                client,
                store.clone(),
                runtime.clone(),
                args.initial_after,
                args.join_head,
            )),
            tokio::spawn(consume::ack_loop(
                controls.clone(),
                args.consumer_id,
                store.clone(),
                runtime.clone(),
            )),
            tokio::spawn(consume::coverage_loop(
                controls,
                store.clone(),
                runtime.clone(),
            )),
        )
    };
    let db = store.clone();
    let mut webhooks = tokio::spawn(async move {
        if db.targets.is_empty() {
            std::future::pending::<()>().await;
        }
        webhook::run(db).await
    });
    let router = server::router(Api {
        store: store.clone(),
        runtime: runtime.clone(),
        token,
        reader_token,
        clients: Arc::new(Semaphore::new(args.max_clients)),
        renderers: Arc::new(Semaphore::new(1)),
    });
    let mut socket_guard = None;
    let mut serving: std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>> =
        if let Some(socket) = args.listen_unix {
            let (listener, guard) = blockzilla_stream_sidecar::uds::bind(&socket)?;
            socket_guard = Some(guard);
            println!(
                "{}",
                serde_json::json!({"state":"STARTED","source":source,"transport":"unix"})
            );
            Box::pin(async move { axum::serve(listener, router).await.map_err(Into::into) })
        } else {
            ensure!(
                args.bind.ip().is_loopback(),
                "sidecar_listen_must_be_loopback_or_unix"
            );
            let listener = tokio::net::TcpListener::bind(args.bind).await?;
            println!(
                "{}",
                serde_json::json!({"state":"STARTED","source":source,"transport":"loopback"})
            );
            Box::pin(async move { axum::serve(listener, router).await.map_err(Into::into) })
        };
    let (mut intake_active, mut coverage_active) = (true, true);
    let result = loop {
        tokio::select! {
            r=&mut intake,if intake_active=>{let result=actor_result("intake",r);if raw_mode{intake_active=false;runtime.fail(&result.unwrap_err().to_string());store.notify.notify_waiters();}else{break result;}},
            r=&mut ack=>break actor_result("origin_ack",r),
            r=&mut coverage,if coverage_active=>{let result=actor_result(if raw_mode{"beam_reconciliation"}else{"coverage"},r);if raw_mode{coverage_active=false;runtime.fail(&result.unwrap_err().to_string());store.notify.notify_waiters();}else{break result;}},
            r=&mut webhooks=>break actor_result("webhooks",r),
            r=&mut serving=>break r.and_then(|_|Err(anyhow::anyhow!("http_server_stopped"))),
            r=shutdown()=>break r,
        }
    };
    if let Err(e) = &result {
        runtime.fail(&e.to_string());
        store.notify.notify_waiters();
    }
    intake.abort();
    ack.abort();
    coverage.abort();
    webhooks.abort();
    drop(serving);
    drop(socket_guard);
    result
}
fn actor_result(
    name: &str,
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
) -> Result<()> {
    match result {
        Ok(Err(e)) => Err(e.context(format!("{name}_failed"))),
        Ok(Ok(())) => Err(anyhow::anyhow!("{name}_stopped")),
        Err(e) => Err(anyhow::anyhow!("{name}_task_failed:{e}")),
    }
}
async fn shutdown() -> Result<()> {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {r=tokio::signal::ctrl_c()=>r?,_=term.recv()=>{}};
    Ok(())
}

#[cfg(test)]
mod input_args_tests {
    use super::*;
    fn arguments() -> Vec<String> {
        vec![
            "sidecar",
            "--source-file",
            "/source.json",
            "--producer-generation",
            &"b".repeat(64),
            "--database",
            "/private/db.sqlite",
            "--token-file",
            "/private/admin",
            "--reader-token-file",
            "/private/reader",
            "--upstream-ssh-host",
            "ubuntu@127.0.0.1",
            "--upstream-ssh-helper",
            "/private/helper.py",
            "--upstream-ssh-job",
            "/private/job",
            "--runtime-generation",
            &"a".repeat(32),
            "--join-head",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }
    #[test]
    fn raw_ssh_needs_no_origin_token_and_rejects_mixed_transport() {
        let args = Args::try_parse_from(arguments()).unwrap();
        assert!(args.upstream_token_file.is_none());
        assert!(args.join_head);
        assert!(args.upstream_unix.is_none());
        let mut mixed = arguments();
        mixed.extend(["--upstream-unix".into(), "/private/origin.sock".into()]);
        assert!(Args::try_parse_from(mixed).is_err());
        let mut leaked = arguments();
        leaked.extend([
            "--upstream-token-file".into(),
            "/private/origin-token".into(),
        ]);
        assert!(Args::try_parse_from(leaked).is_err());
    }
    #[test]
    fn exact_bootstrap_file_cannot_be_combined_with_head_join() {
        let mut args = arguments();
        args.extend(["--bootstrap-file".into(), "/private/bootstrap.json".into()]);
        assert!(Args::try_parse_from(args).is_err());
    }
    #[test]
    fn recovery_requires_raw_input_and_a_key_file() {
        let mut args = arguments();
        args.extend([
            "--recovery-worker-url".into(),
            "https://getblock.blockzilla.dev/".into(),
        ]);
        assert!(Args::try_parse_from(args.clone()).is_err());
        args.extend([
            "--recovery-worker-api-key-file".into(),
            "/private/worker-key".into(),
        ]);
        let parsed = Args::try_parse_from(args).unwrap();
        assert_eq!(
            parsed.recovery_worker_api_key_file,
            Some(PathBuf::from("/private/worker-key"))
        );
        let mut key_only = arguments();
        key_only.extend([
            "--recovery-worker-api-key-file".into(),
            "/private/worker-key".into(),
        ]);
        assert!(Args::try_parse_from(key_only).is_err());
    }
}
