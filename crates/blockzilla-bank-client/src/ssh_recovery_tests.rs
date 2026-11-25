use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
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
    v2::cursor("fixture-session", 0, "-")
}
fn entry(frame: &Frame) -> Value {
    let mut entry = serde_json::to_value(crate::RecoveryNotice::from_frame(frame)).unwrap();
    if frame.envelope.event.kind != "block" {
        entry["control_wire_base64"] = STANDARD.encode(&frame.wire).into();
    }
    entry
}
fn header(frames: &[Frame]) -> Value {
    let cfg = config();
    serde_json::json!({"schema":"blockzilla-ssh-beam-v1","status":200,"source":cfg.source,"generation":cfg.generation,"producer_generation":cfg.producer_generation,"start_cursor":base(),"until_cursor":frames.last().unwrap().cursor,"end_cursor":frames.last().unwrap().cursor,"entry_count":frames.len(),"framing":"recovery-plan-ndjson-v1","content_type":"application/vnd.blockzilla.recovery-plan.v1+ndjson"})
}
async fn connection(entries: &[Value], exit: &str) -> (SshBeam, tempfile::NamedTempFile) {
    let file = tempfile::NamedTempFile::new().unwrap();
    let bytes = entries
        .iter()
        .map(|entry| format!("{}\n", serde_json::to_string(entry).unwrap()))
        .collect::<String>();
    std::fs::write(file.path(), bytes).unwrap();
    let mut process = Command::new("/bin/sh")
        .args(["-c", "cat \"$1\"; exit \"$2\"", "recovery-helper"])
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
async fn finite_plan_has_only_metadata_for_blocks_and_exact_original_controls() {
    let block = block(1, 12, 3, 11, 100);
    let frames = vec![
        block.clone(),
        control(&block, 2, "confirmed", 1001),
        control(&block, 3, "root", 1002),
    ];
    let entries = frames.iter().map(entry).collect::<Vec<_>>();
    for exit in ["0", "75"] {
        let (mut connection, _file) = connection(&entries, exit).await;
        let plan = read_recovery_plan(
            &mut connection,
            &header(&frames),
            &config(),
            &base(),
            &frames[2].cursor,
            128,
        )
        .await
        .unwrap();
        assert_eq!(plan.len(), 3);
        assert!(plan[0].control.is_none());
        assert_eq!(plan[1].control.as_ref().unwrap().wire, frames[1].wire);
        assert_eq!(plan[2].control.as_ref().unwrap().wire, frames[2].wire);
        assert_eq!(connection.cursor(), base());
        assert_eq!(connection.finish_finite().await.is_ok(), exit == "0");
    }
    let command = config()
        .recovery_plan_command(&base(), &frames[2].cursor, 128)
        .unwrap();
    assert!(command.contains("'recovery-plan'"));
    assert!(command.contains("'--until'"));
    assert!(
        config()
            .recovery_plan_command(&base(), &frames[2].cursor, 129)
            .is_err()
    );
}

#[tokio::test]
async fn duplicate_gap_forged_control_block_copy_and_changed_pins_fail_closed() {
    let block = block(1, 12, 3, 11, 100);
    let frames = vec![block.clone(), control(&block, 2, "root", 1001)];
    for fault in [
        "duplicate",
        "gap",
        "source",
        "control",
        "block-copy",
        "until",
        "end",
        "count",
        "expiry",
    ] {
        let mut entries = frames.iter().map(entry).collect::<Vec<_>>();
        let mut head = header(&frames);
        match fault {
            "duplicate" => entries[1] = entries[0].clone(),
            "gap" => {
                entries.remove(0);
            }
            "source" => entries[0]["source"]["session_id"] = "changed-source".into(),
            "control" => entries[1]["control_wire_base64"] = STANDARD.encode(&block.wire).into(),
            "block-copy" => entries[0]["control_wire_base64"] = STANDARD.encode(&block.wire).into(),
            "until" => head["until_cursor"] = base().into(),
            "end" => head["end_cursor"] = base().into(),
            "count" => head["entry_count"] = 3.into(),
            "expiry" => head["status"] = 410.into(),
            _ => unreachable!(),
        };
        let (mut connection, _file) = connection(&entries, "0").await;
        assert!(
            read_recovery_plan(
                &mut connection,
                &head,
                &config(),
                &base(),
                &frames[1].cursor,
                128
            )
            .await
            .is_err(),
            "{fault}"
        );
        assert_eq!(connection.cursor(), base());
        connection.close().await;
    }
}
