use super::*;
use blockzilla_archive_v2::{BlockzillaGetBlockBlobEncoding, BlockzillaGetBlockBundleV1};
use serde_json::json;
use std::{fs, os::unix::fs::PermissionsExt};

pub(crate) fn frame() -> Vec<u8> {
    let bundle = BlockzillaGetBlockBundleV1 {
        version: 1,
        slot: 100,
        hot_block_encoding: BlockzillaGetBlockBlobEncoding::ZstdWincode,
        hot_block: vec![1, 2],
        block_access_encoding: BlockzillaGetBlockBlobEncoding::Wincode,
        block_access: Some(vec![3]),
    };
    let body = wincode::config::serialize(&bundle, blockzilla_primitives::wincode_leb128_config())
        .unwrap();
    let metadata = json!({"version":1,"slot":100,"parent_slot":99,"blockhash":bs58::encode([9;32]).into_string(),"previous_blockhash":bs58::encode([8;32]).into_string(),"tx_count":0,"hot":{"block_id":1,"slot":100,"compressed_offset":0,"compressed_len":2,"uncompressed_len":1,"tx_count":0,"first_tx_ordinal":0,"first_signature_ordinal":0,"signature_count":0},"sha256":hex::encode(Sha256::digest(&body)),"length":body.len(),"message_schema":0,"metadata_schema":0,"rooted":true,"metadata_complete":true});
    framed(&metadata, &body)
}

fn framed(metadata: &serde_json::Value, body: &[u8]) -> Vec<u8> {
    let raw = serde_json::to_vec(metadata).unwrap();
    let mut frame = b"BZLGR01!".to_vec();
    frame.extend_from_slice(&(raw.len() as u32).to_le_bytes());
    frame.extend_from_slice(&raw);
    frame.extend_from_slice(body);
    frame
}

pub(crate) fn fixture(action: &str, wall: u64) -> (tempfile::TempDir, Config) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let ledger = root.join("ledger with spaces");
    fs::create_dir(&ledger).unwrap();
    let helper = root.join("helper");
    fs::copy(native_helper(), &helper).unwrap();
    fs::write(helper.with_extension("config"), action).unwrap();
    fs::write(ledger.join("fixture.frame"), frame()).unwrap();
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
    let config = Config {
        helper_sha256: hex::encode(Sha256::digest(fs::read(&helper).unwrap())),
        helper,
        ledger,
        minimum_slot: 100,
        max_wall_ms: wall,
        generation: "ledger-compact-v1".into(),
    };
    (directory, config)
}

fn native_helper() -> &'static std::path::Path {
    static HELPER: std::sync::OnceLock<(tempfile::TempDir, std::path::PathBuf)> =
        std::sync::OnceLock::new();
    &HELPER
        .get_or_init(|| {
            let directory = tempfile::tempdir().unwrap();
            let executable = directory.path().join("ledger-helper");
            let result = std::process::Command::new("rustc")
                .args(["--edition=2024", "-O"])
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/ledger-helper.rs"
                ))
                .arg("-o")
                .arg(&executable)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            (directory, executable)
        })
        .1
}

#[test]
fn ledger_helper_reads_one_borrowed_outer_bundle_and_preserves_metadata() {
    let (_directory, config) = fixture("emit", 1000);
    let client = Client::new(config).unwrap();
    let block = client.read(100).unwrap().unwrap();
    assert_eq!(block.metadata.slot, 100);
    assert_eq!(block.generation, "ledger-compact-v1");
    assert!(block.metadata.rooted && block.metadata.metadata_complete);
    assert_eq!(
        hex::encode(Sha256::digest(&block.body)),
        block.metadata.sha256
    );
    assert!(client.read(99).unwrap().is_none());
}

#[test]
fn ledger_helper_only_absence_and_nonfinality_have_typed_outcomes() {
    for (action, expected) in [
        ("absent", None),
        ("unrooted", Some("ledger_not_rooted")),
        ("incomplete", Some("ledger_compact_unavailable")),
    ] {
        let (_directory, config) = fixture(action, 1000);
        let result = Client::new(config).unwrap().read(100);
        if let Some(expected) = expected {
            assert_eq!(result.err().unwrap().to_string(), expected)
        } else {
            assert!(result.unwrap().is_none())
        }
    }
}

#[test]
fn ledger_helper_rejects_replaced_binary_or_invalid_pins_before_execution() {
    let (_directory, mut config) = fixture("emit", 1000);
    config.helper_sha256 = "b".repeat(64);
    assert!(Client::new(config).is_err());
    let (_directory, config) = fixture("emit", 1000);
    let client = Client::new(config.clone()).unwrap();
    fs::write(&config.helper, b"changed release").unwrap();
    assert!(client.read(100).is_err());
    assert!(!config.ledger.join("helper.pid").exists());
}

#[test]
fn ledger_helper_bounds_both_pipes_and_reaps_timed_out_children() {
    for action in ["stdout", "stderr", "timeout"] {
        let (_directory, config) = fixture(action, 300);
        let client = Client::new(config.clone()).unwrap();
        let start = Instant::now();
        assert!(client.read(100).is_err(), "accepted {action}");
        assert!(start.elapsed() < Duration::from_secs(3));
        if let Ok(pid) = fs::read_to_string(config.ledger.join("helper.pid")) {
            assert_eq!(
                unsafe { libc::kill(pid.parse::<i32>().unwrap(), 0) },
                -1,
                "helper remained alive after {action}"
            );
        }
    }
}

#[test]
fn ledger_helper_busy_gate_is_held_until_the_original_child_is_reaped() {
    let (_directory, config) = fixture("wait_release", 3000);
    let client = std::sync::Arc::new(Client::new(config.clone()).unwrap());
    let worker = {
        let client = client.clone();
        std::thread::spawn(move || client.read(100))
    };
    let deadline = Instant::now() + Duration::from_secs(2);
    while !config.ledger.join("helper.pid").exists() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    }
    let pid = fs::read_to_string(config.ledger.join("helper.pid")).unwrap();
    assert_eq!(
        client.read(100).err().unwrap().to_string(),
        "ledger_compact_unavailable"
    );
    assert_eq!(
        pid,
        fs::read_to_string(config.ledger.join("helper.pid")).unwrap()
    );
    fs::write(config.ledger.join("release"), []).unwrap();
    assert!(worker.join().unwrap().unwrap().is_some());
    assert_eq!(unsafe { libc::kill(pid.parse::<i32>().unwrap(), 0) }, -1);
    assert!(
        client.read(100).unwrap().is_some(),
        "helper gate did not release after reaping"
    );
}

#[test]
fn ledger_metadata_rejects_wrong_slot_missing_root_bad_hash_and_unbounded_rows() {
    let output = frame();
    let n = u32::from_le_bytes(output[8..12].try_into().unwrap()) as usize;
    let original: serde_json::Value = serde_json::from_slice(&output[12..12 + n]).unwrap();
    let body = &output[12 + n..];
    for field in [
        "slot", "root", "metadata", "hash", "length", "parent", "schema", "hot", "unknown",
    ] {
        let mut metadata = original.clone();
        match field {
            "slot" => metadata["slot"] = json!(101),
            "root" => metadata["rooted"] = json!(false),
            "metadata" => metadata["metadata_complete"] = json!(false),
            "hash" => metadata["sha256"] = json!("b".repeat(64)),
            "length" => metadata["length"] = json!(body.len() + 1),
            "parent" => metadata["parent_slot"] = json!(100),
            "schema" => metadata["metadata_schema"] = json!(1),
            "hot" => metadata["hot"]["uncompressed_len"] = json!(32 * 1024 * 1024 + 1),
            "unknown" => metadata["source_session"] = json!("not-a-stream-source"),
            _ => unreachable!(),
        }
        assert!(
            parse(Bytes::from(framed(&metadata, body)), 100, "test".into()).is_err(),
            "accepted {field}"
        );
    }
    let mut trailing = body.to_vec();
    trailing.push(0);
    let mut metadata = original;
    metadata["length"] = json!(trailing.len());
    metadata["sha256"] = json!(hex::encode(Sha256::digest(&trailing)));
    assert!(
        parse(
            Bytes::from(framed(&metadata, &trailing)),
            100,
            "test".into()
        )
        .is_err()
    );
    assert!(
        parse(
            Bytes::from_static(b"BZLGR01!\x01\x10\x00\x00"),
            100,
            "test".into()
        )
        .is_err()
    );
}
