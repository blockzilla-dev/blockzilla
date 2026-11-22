//! Actual child-process restart checks. Every origin is a private test socket.
use axum::{
    Json, Router,
    body::Body,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use blockzilla_bank_stream_v2::{self as v2, Head, fixtures::source};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};
const KEY: &str = "sidecar-local-test-token-0000000000000000";
#[derive(Clone)]
struct Origin {
    authorized: bool,
}
fn head() -> Head {
    let base = v2::cursor(&source().session_id, 0, "-");
    Head {
        schema: v2::HEAD.into(),
        profile: v2::PROFILE.into(),
        source: source(),
        cursor: Some(base.clone()),
        earliest_after: Some(base),
        status: "starting".into(),
        sampled_at_unix_ms: blockzilla_bank_client::now_ms(),
        source_observed_at_unix_ms: None,
        source_lag_ms: None,
        latest_confirmed: None,
    }
}
async fn get_head(State(s): State<Origin>) -> Response {
    if !s.authorized {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Json(head()).into_response()
}
#[derive(Deserialize)]
struct Position {
    after: String,
}
async fn events(Query(p): Query<Position>) -> Response {
    let text = format!(
        "event: status\ndata: {}\n\n",
        serde_json::to_string(&head()).unwrap()
    );
    let stream = async_stream::stream! {yield Ok::<_,std::io::Error>(bytes::Bytes::from(text));std::future::pending::<()>().await;};
    (
        [
            ("content-type", "text/event-stream"),
            ("x-blockzilla-start-cursor", p.after.as_str()),
        ],
        Body::from_stream(stream),
    )
        .into_response()
}
async fn ack(Json(v): Json<Value>) -> Json<Value> {
    Json(
        json!({"schema":"blockzilla-consumer-ack-receipt-v1","state":"ACKED","consumer_id":v["consumer_id"],"source":v["source"],"cursor":v["cursor"],"coverage_gap_sequence":v["coverage_gap_sequence"]}),
    )
}
async fn gaps() -> Json<Value> {
    Json(
        json!({"schema":"blockzilla-coverage-gaps-v1","source":source(),"producer_generation":"fixture-generation","base_sequence":0,"latest_sequence":0,"gaps":[]}),
    )
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Fixture {
    directory: tempfile::TempDir,
    origin: PathBuf,
    output: PathBuf,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Fixture {
    async fn new(authorized: bool, coverage: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let origin = directory.path().join("origin.sock");
        let output = directory.path().join("sidecar.sock");
        let mut router = Router::new()
            .route("/v2/banks/head", get(get_head))
            .route("/v2/banks/events", get(events))
            .route("/v2/banks/ack", post(ack));
        if coverage {
            router = router.route("/v2/banks/coverage-gaps", get(gaps));
        }
        let router = router.with_state(Origin { authorized });
        let listener = tokio::net::UnixListener::bind(&origin).unwrap();
        std::fs::set_permissions(&origin, std::fs::Permissions::from_mode(0o600)).unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        std::fs::write(
            directory.path().join("source.json"),
            serde_json::to_vec(&source()).unwrap(),
        )
        .unwrap();
        std::fs::write(directory.path().join("token"), KEY).unwrap();
        Self {
            directory,
            origin,
            output,
            task,
        }
    }
    fn start(&self) -> Process {
        let base = v2::cursor(&source().session_id, 0, "-");
        Process(
            Command::new(env!("CARGO_BIN_EXE_blockzilla-stream-sidecar"))
                .args(["--source-file"])
                .arg(self.directory.path().join("source.json"))
                .args([
                    "--producer-generation",
                    "fixture-generation",
                    "--upstream-unix",
                ])
                .arg(&self.origin)
                .arg("--upstream-token-file")
                .arg(self.directory.path().join("token"))
                .arg("--token-file")
                .arg(self.directory.path().join("token"))
                .arg("--database")
                .arg(self.directory.path().join("sidecar.sqlite"))
                .arg("--listen-unix")
                .arg(&self.output)
                .args(["--initial-after", &base])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        )
    }
    async fn ready(&self) -> Value {
        let client = reqwest::Client::builder()
            .unix_socket(self.output.as_path())
            .no_proxy()
            .build()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(r) = client
                    .get("http://localhost/v1/head")
                    .header("authorization", format!("Bearer {KEY}"))
                    .send()
                    .await
                {
                    if let Ok(v) = r.json::<Value>().await {
                        if v["outputCursor"].is_string() {
                            return v;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        })
        .await
        .unwrap()
    }
}
async fn exited(process: &mut Process) -> std::process::ExitStatus {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(status) = process.0.try_wait().unwrap() {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap()
}
fn signal(process: &Process, signal: i32) {
    assert_eq!(
        unsafe { libc::kill(process.0.id() as libc::pid_t, signal) },
        0
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigterm_and_crash_restart_reuse_exact_database_and_owned_socket() {
    let f = Fixture::new(true, true).await;
    let mut first = f.start();
    let initial = f.ready().await;
    signal(&first, libc::SIGTERM);
    assert!(exited(&mut first).await.success());
    assert!(!f.output.exists());
    let mut second = f.start();
    assert_eq!(f.ready().await["outputCursor"], initial["outputCursor"]);
    signal(&second, libc::SIGKILL);
    assert!(!exited(&mut second).await.success());
    assert!(f.output.exists());
    let mut third = f.start();
    assert_eq!(f.ready().await["outputCursor"], initial["outputCursor"]);
    signal(&third, libc::SIGTERM);
    assert!(exited(&mut third).await.success());
    assert!(!f.output.exists());
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fatal_intake_or_coverage_failure_exits_nonzero() {
    let f = Fixture::new(false, true).await;
    let mut child = f.start();
    assert!(!exited(&mut child).await.success());
    assert!(!f.output.exists());
    let f = Fixture::new(true, false).await;
    let mut child = f.start();
    assert!(!exited(&mut child).await.success());
    assert!(!f.output.exists());
}
