use anyhow::{Context, Result, ensure};
use blockzilla_resolution_service::{catalog::Catalog, http, recent::RecentClient};
use clap::Parser;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    mirror_root: PathBuf,
    #[arg(long)]
    catalog: PathBuf,
    #[arg(long)]
    token_file: PathBuf,
    #[arg(long, default_value = "127.0.0.1:8766")]
    listen: SocketAddr,
    #[arg(long, default_value_t = 0)]
    cache_mib: usize,
    #[arg(long, default_value_t = 16)]
    max_concurrent: usize,
    /// Read original retained frames through the existing read-only BankSource.
    #[arg(long)]
    recent_config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    // The TLS proxy connects over loopback. Binding a public socket requires a
    // separate authenticated TLS deployment, which this service does not do.
    ensure!(
        args.listen.ip().is_loopback(),
        "listen must use a loopback address"
    );
    ensure!(
        args.cache_mib == 0,
        "result caching is disabled; --cache-mib must be 0"
    );
    let token = std::fs::read_to_string(&args.token_file).context("read private token file")?;
    let catalog = Arc::new(Catalog::load(&args.mirror_root, &args.catalog)?);
    let recent = args
        .recent_config
        .as_deref()
        .map(RecentClient::load)
        .transpose()?;
    let app = http::router_with_recent(
        catalog,
        token.trim_end(),
        args.cache_mib * 1024 * 1024,
        args.max_concurrent,
        recent.map(Arc::new),
    )?;
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    eprintln!("resolution service ready on {}", listener.local_addr()?);
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
