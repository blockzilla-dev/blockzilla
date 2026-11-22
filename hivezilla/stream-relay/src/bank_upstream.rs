//! One authenticated upstream. Durable admission precedes the resume cursor.
use crate::{
    bank_store::{BankStore, Bootstrap},
    upstream::Upstream,
};
use anyhow::{Context, Result, ensure};
use blockzilla_bank_stream_v2::{self as v2, Frame, Head, Notice, SourceIdentity};
use bytes::BytesMut;
use futures_util::StreamExt;
use std::{sync::Arc, time::Duration};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

const MAX_IN_FLIGHT: usize = 4;
const LIVE_BATCH_WAIT: Duration = Duration::from_millis(10);
const REPLAY_BATCH_WAIT: Duration = Duration::from_millis(100);
struct IntakeTask(tokio::task::JoinHandle<()>);
impl Drop for IntakeTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
enum Inbound {
    Status(Box<Head>),
    Chunk(Notice, String, u64),
}
enum Downloaded {
    Status(Box<Head>),
    Frame(Box<Frame>, OwnedSemaphorePermit),
}

#[derive(Default)]
pub struct Sse {
    pub pending: BytesMut,
    event: String,
    id: String,
    data: Vec<String>,
    size: usize,
}
impl Sse {
    pub fn line(&mut self, line: &[u8]) -> Result<Option<(String, String, String)>> {
        self.size += line.len() + 1;
        ensure!(self.size <= v2::MAX_META, "sse_event_too_large");
        let line = std::str::from_utf8(line)?.trim_end_matches('\r');
        if line.is_empty() {
            let result = (!self.data.is_empty())
                .then(|| (self.event.clone(), self.id.clone(), self.data.join("\n")));
            self.event.clear();
            self.id.clear();
            self.data.clear();
            self.size = 0;
            return Ok(result);
        }
        if line.starts_with(':') {
            return Ok(None);
        }
        let (field, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" => {
                ensure!(self.event.is_empty(), "duplicate_sse_event");
                self.event = value.into();
            }
            "id" => {
                ensure!(
                    self.id.is_empty() && !value.contains('\0'),
                    "invalid_sse_id"
                );
                self.id = value.into();
            }
            "data" => self.data.push(value.into()),
            _ => {}
        }
        Ok(None)
    }
}
pub async fn bounded(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    ensure!(
        !matches!(response.status().as_u16(), 400 | 401 | 403 | 410),
        "upstream_terminal_http_{}",
        response.status().as_u16()
    );
    response.error_for_status_ref()?;
    let mut bytes = Vec::new();
    while let Some(part) = response.chunk().await? {
        ensure!(bytes.len() + part.len() <= limit, "response_too_large");
        bytes.extend_from_slice(&part);
    }
    Ok(bytes)
}
pub async fn fetch(
    u: &Upstream,
    client: &reqwest::Client,
    sha: &str,
    source: &SourceIdentity,
) -> Result<Frame> {
    fetch_bounded(u, client, sha, source, v2::MAX_FRAME).await
}
async fn fetch_bounded(
    u: &Upstream,
    client: &reqwest::Client,
    sha: &str,
    source: &SourceIdentity,
    limit: usize,
) -> Result<Frame> {
    ensure!(v2::is_digest(sha), "invalid_digest");
    let r = client
        .get(format!("{}v2/banks/chunks/{sha}", u.url))
        .bearer_auth(&u.token)
        .send()
        .await?;
    ensure!(
        !matches!(r.status().as_u16(), 400 | 401 | 403 | 410),
        "upstream_terminal_http_{}",
        r.status().as_u16()
    );
    r.error_for_status_ref()?;
    ensure!(
        r.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            == Some("application/vnd.blockzilla.stream.v2"),
        "chunk_content_type_mismatch"
    );
    let f = v2::decode(bounded(r, limit).await?.into())?;
    ensure!(
        f.sha256 == sha && &f.source == source,
        "source_or_digest_changed"
    );
    Ok(f)
}
pub async fn head(u: &Upstream, client: &reqwest::Client, source: &SourceIdentity) -> Result<Head> {
    let r = client
        .get(format!("{}v2/banks/head", u.url))
        .bearer_auth(&u.token)
        .send()
        .await?;
    let h: Head = serde_json::from_slice(&bounded(r, v2::MAX_META).await?)?;
    h.validate(source, crate::store::now_ms(), v2::DEFAULT_MAX_LAG_MS)?;
    Ok(h)
}
pub async fn bootstrap(
    u: &Upstream,
    client: &reqwest::Client,
    source: &SourceIdentity,
) -> Result<Bootstrap> {
    let r = client
        .get(format!("{}v2/banks/state", u.url))
        .bearer_auth(&u.token)
        .send()
        .await?;
    let b: Bootstrap = serde_json::from_slice(&bounded(r, 16 * 1024 * 1024).await?)?;
    ensure!(&b.source == source, "source_changed");
    b.chain.validate(source, &b.cursor)?;
    Ok(b)
}
pub async fn install(
    u: &Upstream,
    client: &reqwest::Client,
    store: &Arc<BankStore>,
    b: Bootstrap,
) -> Result<()> {
    let mut dependencies = Vec::new();
    if let Some(h) = &b.chain.latest {
        let control = fetch(
            u,
            client,
            v2::parse_cursor(&h.event_cursor)?.2,
            &store.source,
        )
        .await?;
        ensure!(
            v2::ConfirmedObservation::from_frame(&control)? == *h,
            "bootstrap_head_changed"
        );
        let payload = fetch(u, client, &h.payload_frame_sha256, &store.source).await?;
        control.envelope.event.matches_payload(&payload)?;
        dependencies.push(control);
        dependencies.push(payload);
    }
    let s = store.clone();
    tokio::task::spawn_blocking(move || s.install_bootstrap(b, dependencies)).await??;
    Ok(())
}
async fn receive(u: &Upstream, client: &reqwest::Client, store: &Arc<BankStore>) -> Result<()> {
    let after = store.latest();
    let mut url = reqwest::Url::parse(&format!("{}v2/banks/events", u.url))?;
    url.query_pairs_mut().append_pair("after", &after);
    let r = client.get(url).bearer_auth(&u.token).send().await?;
    ensure!(
        !matches!(r.status().as_u16(), 400 | 401 | 403 | 410),
        "upstream_terminal_http_{}",
        r.status().as_u16()
    );
    let r = r.error_for_status()?;
    ensure!(
        r.headers()
            .get("x-blockzilla-start-cursor")
            .and_then(|v| v.to_str().ok())
            == Some(&after),
        "upstream_cursor_mismatch"
    );
    ensure!(
        r.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|s| s.starts_with("text/event-stream")),
        "upstream_content_type_mismatch"
    );
    let (sender, mut input) = mpsc::channel(MAX_IN_FLIGHT);
    let requests = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    let intake_requests = requests.clone();
    let intake_upstream = u.clone();
    let intake_client = client.clone();
    let source = store.source.clone();
    let intake = IntakeTask(tokio::spawn(async move {
        if let Err(error) = download(
            r,
            intake_upstream,
            intake_client,
            source,
            after,
            intake_requests,
            &sender,
        )
        .await
        {
            let _ = sender.send(Err(error)).await;
        }
    }));
    let mut batch: Vec<(Frame, Option<Frame>)> = Vec::new();
    let mut permits = Vec::new();
    let mut batch_bytes = 0;
    let mut announced_sequence = 0;
    let mut flush_due = tokio::time::Instant::now();
    loop {
        let next = if batch.is_empty() {
            input.recv().await
        } else {
            tokio::select! {
                value=input.recv()=>value,
                _=tokio::time::sleep_until(flush_due)=>{
                    flush(store,&mut batch).await?;
                    permits.clear();batch_bytes=0;continue;
                }
            }
        };
        let Some(event) = next else { break };
        match event? {
            Downloaded::Status(h) => {
                flush(store, &mut batch).await?;
                permits.clear();
                batch_bytes = 0;
                ensure!(h.status != "failed", "source_failed");
                announced_sequence = h
                    .cursor
                    .as_deref()
                    .map(v2::parse_cursor)
                    .transpose()?
                    .map_or(0, |(_, n, _)| n);
                store.set_health(&h.status, None);
            }
            Downloaded::Frame(frame, permit) => {
                let frame = *frame;
                let dependency = if let Some(sha) = &frame.envelope.event.payload_frame_sha256 {
                    if store.chunk(sha).is_none()
                        && !batch.iter().any(|(f, dep)| {
                            &f.sha256 == sha || dep.as_ref().is_some_and(|d| &d.sha256 == sha)
                        })
                    {
                        let _request = requests.acquire().await?;
                        Some(fetch(u, client, sha, &store.source).await?)
                    } else {
                        None
                    }
                } else {
                    None
                };
                let bytes = frame.wire.len() + dependency.as_ref().map_or(0, |f| f.wire.len());
                if batch_bytes + bytes > crate::bank_store::MAX_BATCH_BYTES {
                    flush(store, &mut batch).await?;
                    permits.clear();
                    batch_bytes = 0;
                }
                if batch.is_empty() {
                    let backlog = announced_sequence.saturating_sub(frame.envelope.event.sequence);
                    let wait = if backlog >= crate::bank_store::MAX_BATCH_EVENTS as u64 {
                        REPLAY_BATCH_WAIT
                    } else {
                        LIVE_BATCH_WAIT
                    };
                    flush_due = tokio::time::Instant::now() + wait;
                }
                batch_bytes += bytes;
                batch.push((frame, dependency));
                permits.push(permit);
                if batch.len() >= crate::bank_store::MAX_BATCH_EVENTS
                    || tokio::time::Instant::now() >= flush_due
                {
                    flush(store, &mut batch).await?;
                    permits.clear();
                    batch_bytes = 0;
                }
            }
        }
    }
    drop(intake);
    flush(store, &mut batch).await?;
    anyhow::bail!("upstream_closed")
}
fn require(condition: bool, error: &str) -> Result<()> {
    ensure!(condition, "{error}");
    Ok(())
}
async fn download(
    response: reqwest::Response,
    u: Upstream,
    client: reqwest::Client,
    source: SourceIdentity,
    mut after: String,
    requests: Arc<Semaphore>,
    sender: &mpsc::Sender<Result<Downloaded>>,
) -> Result<()> {
    let budget = Arc::new(Semaphore::new(crate::bank_store::MAX_BATCH_BYTES));
    let mut input = response.bytes_stream();
    let mut sse = Sse::default();
    let mut initial = true;
    let notice_source = source.clone();
    let events = async_stream::try_stream! {
      while let Some(part) = input.next().await {
        let part = part?;
        require(
            sse.pending.len() + part.len() <= 2 * v2::MAX_META,
            "sse_read_too_large"
        )?;
        sse.pending.extend_from_slice(&part);
        while let Some(end) = sse.pending.iter().position(|b| *b == b'\n') {
            let line = sse.pending.split_to(end + 1);
            let Some((event, id, data)) = sse.line(&line[..end])? else {
                continue;
            };
            if initial {
                require(event == "status" && id.is_empty(), "missing_initial_status")?;
                initial = false;
            }
            match event.as_str() {
                "status" => {
                    require(id.is_empty(), "status_has_id")?;
                    let h: Head = serde_json::from_str(&data)?;
                    h.validate(
                        &notice_source,
                        crate::store::now_ms(),
                        v2::DEFAULT_MAX_LAG_MS,
                    )?;
                    yield Inbound::Status(Box::new(h));
                }
                "gap" => {
                    require(id.is_empty(), "gap_has_id")?;
                    let gap: serde_json::Value = serde_json::from_str(&data)?;
                    let h: Head = serde_json::from_value(gap["head"].clone())?;
                    h.validate(
                        &notice_source,
                        crate::store::now_ms(),
                        v2::DEFAULT_MAX_LAG_MS,
                    )?;
                    let error = gap["error"].as_str().context("invalid_gap")?;
                    require(
                        matches!(
                            error,
                            "source_changed"
                                | "replay_unavailable"
                                | "source_failed"
                                | "dependency_unavailable"
                        ),
                        "invalid_gap"
                    )?;
                    Err(anyhow::anyhow!("{error}"))?;
                }
                "chunk" => {
                    let notice: Notice = serde_json::from_str(&data)?;
                    let sequence = v2::parse_cursor(&after)?
                        .1
                        .checked_add(1)
                        .context("sequence_overflow")?;
                    notice.preflight(&id, sequence, &notice_source)?;
                    after = notice.cursor.clone();
                    yield Inbound::Chunk(notice, id, sequence);
                }
                _ => Err(anyhow::anyhow!("unsupported_sse_event"))?,
            }
        }
      }
      require(sse.pending.is_empty() && sse.size == 0, "upstream_truncated_sse")?;
    };
    let downloads = events
        .map(|event: Result<Inbound>| {
            let budget = budget.clone();
            let u = &u;
            let client = &client;
            let source = &source;
            let requests = &requests;
            async move {
                match event? {
                    Inbound::Status(h) => Ok(Downloaded::Status(h)),
                    Inbound::Chunk(notice, id, sequence) => {
                        // Reserve advertised bytes before GET. The permit covers
                        // primary frames in downloads, ordered results, queued
                        // delivery and the pending disk batch until durable commit.
                        // Missing control dependencies have a separate finite bound.
                        let permit = budget.acquire_many_owned(notice.bytes as u32).await?;
                        let _request = requests.acquire().await?;
                        let frame =
                            fetch_bounded(u, client, &notice.sha256, source, notice.bytes).await?;
                        notice.validate(&id, &frame, sequence, source)?;
                        Ok(Downloaded::Frame(Box::new(frame), permit))
                    }
                }
            }
        })
        .buffered(MAX_IN_FLIGHT);
    futures_util::pin_mut!(downloads);
    while let Some(event) = downloads.next().await {
        sender
            .send(event)
            .await
            .map_err(|_| anyhow::anyhow!("intake_cancelled"))?;
    }
    Ok(())
}
async fn flush(store: &Arc<BankStore>, batch: &mut Vec<(Frame, Option<Frame>)>) -> Result<()> {
    if !batch.is_empty() {
        let s = store.clone();
        let frames = std::mem::take(batch);
        tokio::task::spawn_blocking(move || s.admit_batch(frames)).await??;
    }
    Ok(())
}
pub async fn run(u: Upstream, client: reqwest::Client, store: Arc<BankStore>) {
    let mut delay = 1;
    loop {
        let before = store.latest();
        let result = async {
            // A saved checkpoint is already an admitted boundary. Bootstrap only a
            // fresh store, and retry transient startup I/O without changing its base.
            if store.needs_bootstrap() {
                let b = bootstrap(&u, &client, &store.source).await?;
                install(&u, &client, &store, b).await?;
            }
            receive(&u, &client, &store).await
        }
        .await;
        if let Err(e) = result {
            let msg = e.to_string();
            let retry = e.downcast_ref::<reqwest::Error>().is_some()
                || matches!(msg.as_str(), "upstream_closed" | "upstream_truncated_sse");
            store.set_health(if retry { "stale" } else { "failed" }, Some(msg));
            if !retry {
                return;
            }
        }
        if store.latest() != before {
            delay = 1;
        }
        tokio::time::sleep(Duration::from_secs(delay)).await;
        delay = (delay * 2).min(10);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bank_server::BankApi,
        server::{self, Api},
        store::Store,
    };
    use tokio::sync::Semaphore;
    use v2::fixtures::*;
    fn fresh(f: Frame) -> Frame {
        let n = u32::from_le_bytes(f.wire[8..12].try_into().unwrap()) as usize;
        let mut e = f.envelope;
        e.event.observed_at_unix_ms = crate::store::now_ms();
        v2::encode(e, &f.wire[16 + n..]).unwrap()
    }
    fn api(banks: Arc<BankStore>, origin: bool) -> Api {
        Api {
            store: Store::open("fixture-session:0:-".into(), v2::MAX_FRAME, None).unwrap(),
            token: Arc::new("k".repeat(32)),
            cors: None,
            requests: Arc::new(Semaphore::new(16)),
            allow_query_api_key: false,
            public_blockhashes: false,
            public_requests: Arc::new(Semaphore::new(0)),
            banks: Some(BankApi {
                store: banks,
                origin,
                output: None,
                public_views: None,
                hot_upstream: None,
                direct_beam: false,
            }),
            bank_only: true,
        }
    }
    fn upstream(addr: std::net::SocketAddr) -> Upstream {
        Upstream {
            url: format!("http://{addr}/"),
            token: "k".repeat(32),
            ca: None,
            identity: None,
        }
    }
    fn store(path: &std::path::Path) -> Arc<BankStore> {
        BankStore::open(
            source(),
            v2::cursor(&source().session_id, 0, "-"),
            v2::MAX_FRAME,
            path.into(),
        )
        .unwrap()
    }
    async fn wait_sequence(s: &Arc<BankStore>, sequence: u64) {
        tokio::time::timeout(Duration::from_secs(4), async {
            loop {
                if v2::parse_cursor(&s.latest()).unwrap().1 >= sequence {
                    break;
                }
                assert_ne!(s.head().status, "failed");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn fresh_bootstrap_retries_connection_refusal_without_reset() {
        let t = tempfile::tempdir().unwrap();
        let origin = store(&t.path().join("origin"));
        let relay = store(&t.path().join("relay"));
        let b = fresh(block(1, 9, 1, 8, 9));
        origin.admit(b.clone(), None).unwrap();
        origin
            .admit(control(&b, 2, "root", crate::store::now_ms()), None)
            .unwrap();
        origin.set_health("live", None);
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = reservation.local_addr().unwrap();
        drop(reservation);
        let u = upstream(addr);
        let task = tokio::spawn(run(u.clone(), u.client().unwrap(), relay.clone()));
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(v2::parse_cursor(&relay.latest()).unwrap().1, 0);
        assert_ne!(relay.head().status, "failed");
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let app = server::router(api(origin.clone(), true));
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        wait_sequence(&relay, 2).await;
        assert!(relay.chunk(&b.sha256).is_some());
        assert_eq!(
            relay.head().latest_confirmed.unwrap().bank,
            b.envelope.event.bank
        );
        let next = fresh(block(3, 17, 2, 9, 10));
        origin.admit(next.clone(), None).unwrap();
        origin
            .admit(control(&next, 4, "confirmed", crate::store::now_ms()), None)
            .unwrap();
        wait_sequence(&relay, 4).await;
        assert_eq!(relay.head().status, "live");
        task.abort();
        server.abort();
    }
    #[tokio::test]
    async fn restart_uses_saved_boundary_without_bootstrap_route() {
        let t = tempfile::tempdir().unwrap();
        let origin = store(&t.path().join("origin"));
        let relay = store(&t.path().join("relay"));
        let b = fresh(block(1, 9, 1, 8, 9));
        let root = control(&b, 2, "root", crate::store::now_ms());
        for s in [&origin, &relay] {
            s.admit(b.clone(), None).unwrap();
            s.admit(root.clone(), None).unwrap();
        }
        drop(relay);
        let relay = store(&t.path().join("relay"));
        origin.set_health("live", None);
        let next = fresh(block(3, 17, 2, 9, 10));
        origin.admit(next.clone(), None).unwrap();
        origin
            .admit(control(&next, 4, "confirmed", crate::store::now_ms()), None)
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // No private state route: restoration must not request another bootstrap.
        let app = server::router(api(origin, false));
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let u = upstream(addr);
        let task = tokio::spawn(run(u.clone(), u.client().unwrap(), relay.clone()));
        wait_sequence(&relay, 4).await;
        assert!(relay.chunk(&b.sha256).is_some());
        assert_eq!(relay.head().status, "live");
        task.abort();
        server.abort();
    }
    #[tokio::test]
    async fn concurrent_downloads_keep_durable_order_and_the_saved_boundary() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let t = tempfile::tempdir().unwrap();
        let origin = store(&t.path().join("origin"));
        let relay = store(&t.path().join("relay"));
        let mut frames = Vec::new();
        for bank in 1..=120 {
            let b = fresh(block(2 * bank - 1, bank + 8, bank, bank + 7, bank + 8));
            let root = control(&b, 2 * bank, "root", crate::store::now_ms());
            frames.extend([b, root]);
        }
        for batch in frames.chunks(crate::bank_store::MAX_BATCH_EVENTS) {
            origin
                .admit_batch(batch.iter().cloned().map(|f| (f, None)).collect())
                .unwrap();
        }
        relay
            .admit_batch(frames[..2].iter().cloned().map(|f| (f, None)).collect())
            .unwrap();
        origin.set_health("live", None);
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let active_requests = active.clone();
        let maximum_requests = maximum.clone();
        let slow = frames[2].sha256.clone();
        let middleware = axum::middleware::from_fn(
            move |request: axum::extract::Request, next: axum::middleware::Next| {
                let active = active_requests.clone();
                let maximum = maximum_requests.clone();
                let slow = slow.clone();
                async move {
                    let chunk = request.uri().path().starts_with("/v2/banks/chunks/");
                    if chunk {
                        maximum
                            .fetch_max(active.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(
                            if request.uri().path().ends_with(&slow) {
                                80
                            } else {
                                20
                            },
                        ))
                        .await;
                    }
                    let response = next.run(request).await;
                    if chunk {
                        active.fetch_sub(1, Ordering::SeqCst);
                    }
                    response
                }
            },
        );
        let app = server::router(api(origin, false)).layer(middleware);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let u = upstream(addr);
        let task = tokio::spawn(run(u.clone(), u.client().unwrap(), relay.clone()));
        wait_sequence(&relay, 240).await;
        assert!((2..=MAX_IN_FLIGHT).contains(&maximum.load(Ordering::SeqCst)));
        let mut cursor = v2::cursor(&source().session_id, 0, "-");
        for expected in frames {
            let actual = relay.after(&cursor).unwrap().unwrap();
            assert_eq!(actual.cursor, expected.cursor);
            cursor = actual.cursor.clone();
        }
        assert!(relay.after(&cursor).unwrap().is_none());
        task.abort();
        server.abort();
    }
}
