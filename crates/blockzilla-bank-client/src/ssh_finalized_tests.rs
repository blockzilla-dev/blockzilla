use super::*;
use v2::fixtures::{block, control, source};

fn config() -> SshConfig {
    SshConfig {
        host: "ubuntu@127.0.0.1".into(),
        helper: "/private/helper's path.py".into(),
        job: "/private/job".into(),
        generation: "a".repeat(32),
        producer_generation: "b".repeat(64),
        source: source(),
    }
}
fn base() -> String {
    v2::cursor(&source().session_id, 0, "-")
}
fn header(frame: &Frame, id: &v2::finalized::BlockId) -> Value {
    let cfg = config();
    serde_json::json!({"schema":"blockzilla-ssh-beam-v1","status":200,"source":cfg.source,
        "generation":cfg.generation,"producer_generation":cfg.producer_generation,
        "block_id":id.to_string(),"content_type":"application/vnd.blockzilla.stream.v2",
        "frame_sha256":frame.sha256,"frame_bytes":frame.wire.len(),"commitment":"finalized",
        "retention":"rolling-native-only","complete_epoch_coverage":false})
}
async fn make_connection(bytes: &[u8], exit: &str) -> (SshBeam, tempfile::NamedTempFile) {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), bytes).unwrap();
    let mut process = Command::new("/bin/sh")
        .args(["-c", "cat \"$1\"; exit \"$2\"", "finite-helper"])
        .arg(file.path())
        .arg(exit)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let stdout = process.stdout.take().unwrap();
    (
        SshBeam {
            process,
            frames: FrameReader::new(BufReader::new(stdout), source(), &base()).unwrap(),
            stderr: tokio::spawn(async { Vec::new() }),
        },
        file,
    )
}

#[tokio::test]
async fn exact_finalized_lookup_preserves_original_frame_and_requires_successful_helper_exit() {
    let cfg = config();
    // Point reads are independent of the stream event sequence.
    let frame = block(25, 99, 10, 98, 50);
    let id = v2::finalized::BlockId::from(&frame.envelope.event.bank);
    for exit in ["0", "75"] {
        let (mut connection, _file) = make_connection(&frame.wire, exit).await;
        let got = read_finalized(&mut connection, &header(&frame, &id), &cfg, &id)
            .await
            .unwrap();
        assert_eq!(got.wire, frame.wire);
        assert_eq!(got.envelope.event.kind, "block");
        assert_eq!(
            got.envelope.event.commitment, frame.envelope.event.commitment,
            "the original event must not be rewritten"
        );
        assert_eq!(
            connection.cursor(),
            base(),
            "a point read must not change a live resume cursor"
        );
        if exit == "0" {
            connection.finish_finite().await.unwrap();
        } else {
            assert!(connection.finish_finite().await.is_err());
        }
    }
    let command = cfg.finalized_command(&id).unwrap();
    for argument in [
        "'finalized-block'",
        "'--block-id'",
        "'--source-json'",
        "'--generation'",
    ] {
        assert!(command.contains(argument));
    }
    assert!(command.contains("'/private/helper'\\''s path.py'"));
    assert!(
        cfg.finalized_command(&v2::finalized::BlockId {
            slot: v2::SAFE + 1,
            ..id
        })
        .is_err()
    );
}

#[tokio::test]
async fn finalized_headers_cannot_admit_a_different_source_scope_identity_or_digest() {
    let cfg = config();
    let frame = block(1, 9, 1, 8, 1);
    let id = v2::finalized::BlockId::from(&frame.envelope.event.bank);
    for (field, value) in [
        ("generation", serde_json::json!("c".repeat(32))),
        ("producer_generation", serde_json::json!("c".repeat(64))),
        ("source", serde_json::json!({})),
        ("commitment", serde_json::json!("processed")),
        (
            "block_id",
            serde_json::json!(format!(
                "10:{}",
                v2::hash(&source().genesis_hash)
                    .unwrap()
                    .iter()
                    .map(|_| "1")
                    .collect::<String>()
            )),
        ),
        ("frame_sha256", serde_json::json!("c".repeat(64))),
        ("content_type", serde_json::json!("application/json")),
        ("retention", serde_json::json!("archive")),
        ("complete_epoch_coverage", serde_json::json!(true)),
        ("frame_bytes", serde_json::json!(v2::MAX_FRAME + 1)),
    ] {
        let mut changed = header(&frame, &id);
        changed[field] = value;
        let (mut connection, _file) = make_connection(&frame.wire, "0").await;
        assert!(
            read_finalized(&mut connection, &changed, &cfg, &id)
                .await
                .is_err(),
            "header {field}"
        );
        connection.close().await;
    }
    let mut wrong = id;
    wrong.slot += 1;
    let (mut connection, _file) = make_connection(&frame.wire, "0").await;
    assert!(
        read_finalized(&mut connection, &header(&frame, &wrong), &cfg, &wrong)
            .await
            .is_err()
    );
    connection.close().await;
    let control = control(&frame, 2, "root", 1000);
    let (mut connection, _file) = make_connection(&control.wire, "0").await;
    assert!(
        read_finalized(&mut connection, &header(&control, &id), &cfg, &id)
            .await
            .is_err()
    );
    connection.close().await;
}

#[tokio::test]
async fn finalized_binary_truncation_trailing_bytes_and_corrupt_objects_fail_closed() {
    let cfg = config();
    let frame = block(1, 9, 1, 8, 1);
    let id = v2::finalized::BlockId::from(&frame.envelope.event.bank);
    let truncated = frame.wire[..frame.wire.len() - 1].to_vec();
    let mut extra = frame.wire.to_vec();
    extra.push(0);
    let mut corrupt = frame.wire.to_vec();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    for bytes in [truncated, extra, corrupt] {
        let (mut connection, _file) = make_connection(&bytes, "0").await;
        assert!(
            read_finalized(&mut connection, &header(&frame, &id), &cfg, &id)
                .await
                .is_err()
        );
        connection.close().await;
    }
}

#[tokio::test]
async fn unavailable_finalized_block_preserves_checked_rolling_head_without_skip_proof() {
    let cfg = config();
    let frame = block(1, 9, 1, 8, 1);
    let id = v2::finalized::BlockId::from(&frame.envelope.event.bank);
    let head = v2::Head {
        schema: v2::HEAD.into(),
        profile: v2::PROFILE.into(),
        source: source(),
        cursor: Some(base()),
        earliest_after: Some(base()),
        status: "starting".into(),
        sampled_at_unix_ms: crate::now_ms(),
        source_observed_at_unix_ms: None,
        source_lag_ms: None,
        latest_confirmed: None,
    };
    let h = serde_json::json!({"schema":"blockzilla-ssh-beam-v1","status":410,"reason":"block_unavailable","head":head});
    let (mut connection, _file) = make_connection(&[], "78").await;
    assert!(
        matches!(read_finalized(&mut connection,&h,&cfg,&id).await,Err(ClientError::Gap {reason,head:Some(head)}) if reason=="finalized_block_unavailable" && head.earliest_after==Some(base()))
    );
    let mut changed = h;
    changed["head"]["source"]["session_id"] = serde_json::json!("wrong-source");
    assert!(matches!(
        read_finalized(&mut connection, &changed, &cfg, &id).await,
        Err(ClientError::Source(_))
    ));
    connection.close().await;
}

#[tokio::test]
async fn cancelled_queued_lookup_cannot_start_unbounded_reads_or_lose_its_permit() {
    let first = FINALIZED_READS.acquire().await.unwrap();
    let second = FINALIZED_READS.acquire().await.unwrap();
    let cfg = config();
    let frame = block(1, 9, 1, 8, 1);
    let id = v2::finalized::BlockId::from(&frame.envelope.event.bank);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), cfg.fetch_finalized(&id))
            .await
            .is_err()
    );
    let anchor = v2::finalized::BlockId {
        slot: 8,
        blockhash: [8; 32],
    };
    assert!(
        tokio::time::timeout(
            Duration::from_millis(10),
            cfg.fetch_finalized_path(&id, &anchor, 1024, MAX_FINALIZED_PATH_BYTES)
        )
        .await
        .is_err()
    );
    assert_eq!(FINALIZED_READS.available_permits(), 0);
    drop(first);
    drop(second);
    assert_eq!(FINALIZED_READS.available_permits(), 2);
}

fn path_header(
    target: &v2::finalized::BlockId,
    anchor: &v2::finalized::BlockId,
    count: usize,
    bytes: usize,
) -> Value {
    let cfg = config();
    serde_json::json!({"schema":"blockzilla-ssh-beam-v1","status":200,"source":cfg.source,
        "generation":cfg.generation,"producer_generation":cfg.producer_generation,
        "target_id":target.to_string(),"anchor_id":anchor.to_string(),"max_blocks":count,"max_wire_bytes":bytes,
        "content_type":"application/vnd.blockzilla.finalized-path.v1","framing":"sha256-raw32+bzstrm01",
        "commitment":"finalized","retention":"rolling-native-only","complete_epoch_coverage":false})
}
fn path_wire(frames: &[Frame]) -> Vec<u8> {
    let mut wire = Vec::new();
    for frame in frames {
        for pair in frame.sha256.as_bytes().chunks_exact(2) {
            wire.push(u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap());
        }
        wire.extend_from_slice(&frame.wire);
    }
    wire
}
fn path_fixture() -> (
    Vec<Frame>,
    v2::finalized::BlockId,
    v2::finalized::BlockId,
    usize,
) {
    let frames = vec![block(25, 11, 11, 10, 50), block(22, 10, 10, 9, 49)];
    let target = v2::finalized::BlockId::from(&frames[0].envelope.event.bank);
    let anchor = v2::finalized::BlockId {
        slot: 9,
        blockhash: [9; 32],
    };
    let bytes = frames.iter().map(|frame| frame.wire.len()).sum();
    (frames, target, anchor, bytes)
}

#[tokio::test]
async fn one_session_finalized_path_checks_all_original_bytes_and_parent_links_before_success() {
    let cfg = config();
    let (frames, target, anchor, bytes) = path_fixture();
    let wire = path_wire(&frames);
    for exit in ["0", "75"] {
        let (mut connection, _file) = make_connection(&wire, exit).await;
        let got = read_finalized_path(
            &mut connection,
            &path_header(&target, &anchor, 2, bytes),
            &cfg,
            &target,
            &anchor,
            2,
            bytes,
        )
        .await
        .unwrap();
        assert_eq!(
            got.iter().map(|f| f.wire.as_ref()).collect::<Vec<_>>(),
            frames.iter().map(|f| f.wire.as_ref()).collect::<Vec<_>>()
        );
        assert_eq!(connection.cursor(), base());
        if exit == "0" {
            connection.finish_finite().await.unwrap();
        } else {
            assert!(connection.finish_finite().await.is_err());
        }
    }
    let command = cfg
        .finalized_path_command(&target, &anchor, 1024, MAX_FINALIZED_PATH_BYTES)
        .unwrap();
    for argument in [
        "'finalized-path'",
        "'--anchor-id'",
        "'--max-blocks'",
        "'--max-wire-bytes'",
    ] {
        assert!(command.contains(argument));
    }
    for (count, budget) in [
        (0, bytes),
        (1025, bytes),
        (2, 16),
        (2, MAX_FINALIZED_PATH_BYTES + 1),
    ] {
        assert!(
            cfg.finalized_path_command(&target, &anchor, count, budget)
                .is_err()
        );
    }
    assert!(
        cfg.finalized_path_command(&anchor, &target, 2, bytes)
            .is_err()
    );
}

#[tokio::test]
async fn finalized_path_rejects_partial_records_wrong_digests_missing_ancestors_and_trailing_bytes()
{
    let cfg = config();
    let (frames, target, anchor, bytes) = path_fixture();
    let all = path_wire(&frames);
    let mut corrupt_digest = all.clone();
    corrupt_digest[0] ^= 1;
    let mut corrupt_object = all.clone();
    let last = corrupt_object.len() - 1;
    corrupt_object[last] ^= 1;
    for wire in [
        path_wire(&frames[..1]),
        all[..all.len() - 1].to_vec(),
        corrupt_digest,
        corrupt_object,
    ] {
        let (mut connection, _file) = make_connection(&wire, "0").await;
        assert!(
            read_finalized_path(
                &mut connection,
                &path_header(&target, &anchor, 2, bytes),
                &cfg,
                &target,
                &anchor,
                2,
                bytes
            )
            .await
            .is_err()
        );
        assert_eq!(connection.cursor(), base());
        connection.close().await;
    }
    let mut trailing = all;
    trailing.push(0);
    let (mut connection, _file) = make_connection(&trailing, "0").await;
    read_finalized_path(
        &mut connection,
        &path_header(&target, &anchor, 2, bytes),
        &cfg,
        &target,
        &anchor,
        2,
        bytes,
    )
    .await
    .unwrap();
    assert!(connection.finish_finite().await.is_err());
}

#[tokio::test]
async fn finalized_path_limits_and_anchor_identity_cannot_be_relaxed_by_the_helper() {
    let cfg = config();
    let (frames, target, anchor, bytes) = path_fixture();
    let wire = path_wire(&frames);
    for (count, budget) in [(1, bytes), (2, frames[0].wire.len())] {
        let (mut connection, _file) = make_connection(&wire, "0").await;
        assert!(
            read_finalized_path(
                &mut connection,
                &path_header(&target, &anchor, count, budget),
                &cfg,
                &target,
                &anchor,
                count,
                budget
            )
            .await
            .is_err()
        );
        connection.close().await;
    }
    let wrong_anchor = v2::finalized::BlockId {
        blockhash: [42; 32],
        ..anchor
    };
    let (mut connection, _file) = make_connection(&wire, "0").await;
    assert!(
        read_finalized_path(
            &mut connection,
            &path_header(&target, &wrong_anchor, 2, bytes),
            &cfg,
            &target,
            &wrong_anchor,
            2,
            bytes
        )
        .await
        .is_err()
    );
    connection.close().await;
    let mut changed = path_header(&target, &anchor, 2, bytes);
    changed["max_blocks"] = serde_json::json!(1024);
    let (mut connection, _file) = make_connection(&wire, "0").await;
    assert!(
        read_finalized_path(&mut connection, &changed, &cfg, &target, &anchor, 2, bytes)
            .await
            .is_err()
    );
    connection.close().await;
    let wrong = vec![frames[0].clone(), block(22, 8, 8, 7, 47)];
    let (mut connection, _file) = make_connection(&path_wire(&wrong), "0").await;
    assert!(
        read_finalized_path(
            &mut connection,
            &path_header(&target, &anchor, 2, bytes),
            &cfg,
            &target,
            &anchor,
            2,
            bytes
        )
        .await
        .is_err()
    );
    connection.close().await;
}
