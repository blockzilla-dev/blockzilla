//! Compare the SDK's captured projection and filter results with finalized RPC.

use std::{collections::BTreeMap, fs::File, io::Read, path::PathBuf, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const MAX_JSON_BYTES: u64 = 64 * 1024 * 1024;
const MAX_BLOCKS: usize = 1000;

#[derive(Args, Debug)]
pub(crate) struct CompareSdkRpcArgs {
    /// JSON capture with program, all, programMatches and accountMatches fields.
    pub input: PathBuf,
    /// JSON-RPC endpoint used for finalized getBlock reads.
    #[arg(long, default_value = "http://127.0.0.1:8899")]
    pub rpc_url: reqwest::Url,
    /// Save the successful comparison report to a new file.
    #[arg(long)]
    pub report: Option<PathBuf>,
    /// Timeout for each RPC request, in seconds.
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=300))]
    pub timeout_seconds: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Capture {
    program: String,
    all: Vec<Block>,
    program_matches: Vec<Block>,
    account_matches: Vec<Block>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Block {
    slot: u64,
    parent_slot: u64,
    blockhash: String,
    parent_blockhash: String,
    transaction_count: usize,
    transactions: Vec<Transaction>,
}

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct Transaction {
    index: usize,
    signature: String,
    signatures: Vec<String>,
    success: Option<bool>,
    top_level_programs: Vec<String>,
    inner_programs: Vec<String>,
    inner_coverage: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RpcBlock {
    blockhash: String,
    previous_blockhash: String,
    parent_slot: u64,
    transactions: Vec<RpcTransaction>,
}

#[derive(Deserialize)]
struct RpcTransaction {
    transaction: RpcSignedTransaction,
    meta: Value,
    version: Option<Value>,
}

#[derive(Deserialize)]
struct RpcSignedTransaction {
    signatures: Vec<String>,
    message: RpcMessage,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RpcMessage {
    account_keys: Vec<String>,
    instructions: Vec<Instruction>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Instruction {
    program_id_index: usize,
}

#[derive(Deserialize)]
struct InnerInstructions {
    instructions: Vec<Instruction>,
}

#[derive(Deserialize)]
struct LoadedAddresses {
    writable: Vec<String>,
    readonly: Vec<String>,
}

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    state: &'static str,
    capture_sha256: String,
    blocks: usize,
    transactions: usize,
    program_matches: usize,
    account_matches: usize,
    failed_transactions: usize,
    rpc_commitment: &'static str,
    checks: [&'static str; 7],
    cryptographic_verification: bool,
}

fn bounded_json(mut input: impl Read) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    (&mut input)
        .take(MAX_JSON_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= MAX_JSON_BYTES, "JSON exceeds 64 MiB");
    Ok(bytes)
}

fn program_names(instructions: &[Instruction], accounts: &[String]) -> Result<Vec<String>> {
    let mut names = instructions
        .iter()
        .map(|ix| {
            accounts
                .get(ix.program_id_index)
                .cloned()
                .context("RPC program index is outside the account list")
        })
        .collect::<Result<Vec<_>>>()?;
    names.sort();
    names.dedup();
    Ok(names)
}

fn project_rpc(row: RpcTransaction, index: usize) -> Result<(Transaction, Vec<String>)> {
    let mut accounts = row.transaction.message.account_keys;
    if let Some(value) = row
        .meta
        .get("loadedAddresses")
        .filter(|value| !value.is_null())
    {
        let loaded: LoadedAddresses =
            serde_json::from_value(value.clone()).context("RPC loaded addresses are incomplete")?;
        accounts.extend(loaded.writable);
        accounts.extend(loaded.readonly);
    } else {
        ensure!(
            !row.version.as_ref().is_some_and(Value::is_number),
            "RPC versioned transaction has no loaded addresses"
        );
    }
    let error = row
        .meta
        .get("err")
        .context("RPC execution status is absent")?;
    let inner = row
        .meta
        .get("innerInstructions")
        .filter(|value| !value.is_null())
        .context("RPC inner-instruction coverage is unavailable")?;
    let groups: Vec<InnerInstructions> =
        serde_json::from_value(inner.clone()).context("RPC inner instructions are invalid")?;
    let inner: Vec<_> = groups
        .into_iter()
        .flat_map(|group| group.instructions)
        .collect();
    let signature = row
        .transaction
        .signatures
        .first()
        .filter(|value| !value.is_empty())
        .context("RPC primary signature is absent")?
        .clone();
    let projected = Transaction {
        index,
        signature,
        signatures: row.transaction.signatures,
        success: Some(error.is_null()),
        top_level_programs: program_names(&row.transaction.message.instructions, &accounts)?,
        inner_programs: program_names(&inner, &accounts)?,
        inner_coverage: "recorded".into(),
    };
    Ok((projected, accounts))
}

fn by_slot(blocks: &[Block]) -> Result<BTreeMap<u64, &Block>> {
    let mut slots = BTreeMap::new();
    for block in blocks {
        ensure!(
            slots.insert(block.slot, block).is_none(),
            "Duplicate SDK slot {}",
            block.slot
        );
    }
    Ok(slots)
}

fn same_header(expected: &Block, actual: &Block) -> Result<()> {
    ensure!(
        actual.blockhash == expected.blockhash
            && actual.parent_blockhash == expected.parent_blockhash
            && actual.parent_slot == expected.parent_slot
            && actual.transaction_count == expected.transaction_count,
        "slot {}: filtered block identity or transaction count differs",
        expected.slot
    );
    Ok(())
}

fn compare_transaction(got: &Transaction, expected: &Transaction) -> Result<()> {
    ensure!(got.index == expected.index, "transaction index differs");
    ensure!(
        got.signature == expected.signature && got.signatures == expected.signatures,
        "transaction signatures differ"
    );
    ensure!(
        got.success == expected.success,
        "execution status differs or is unknown"
    );
    ensure!(
        got.inner_coverage == "recorded",
        "SDK inner-instruction coverage is unavailable"
    );
    // Program lists are sets, but duplicates are invalid SDK output.
    let mut top = got.top_level_programs.clone();
    top.sort();
    let mut inner = got.inner_programs.clone();
    inner.sort();
    ensure!(
        top == expected.top_level_programs,
        "top-level program references differ"
    );
    ensure!(
        inner == expected.inner_programs,
        "inner program references differ"
    );
    Ok(())
}

fn compare(
    capture: Capture,
    digest: String,
    mut fetch: impl FnMut(u64) -> Result<RpcBlock>,
) -> Result<Report> {
    ensure!(!capture.program.is_empty(), "Capture filter key is empty");
    ensure!(
        !capture.all.is_empty() && capture.all.len() <= MAX_BLOCKS,
        "Capture must contain 1 through {MAX_BLOCKS} blocks"
    );
    let all = by_slot(&capture.all)?;
    let programs = by_slot(&capture.program_matches)?;
    let accounts = by_slot(&capture.account_matches)?;
    ensure!(
        all.keys().eq(programs.keys()) && all.keys().eq(accounts.keys()),
        "Filtered captures must contain exactly the same slots as the full capture"
    );
    let mut report = Report {
        schema: "blockzilla-sdk-rpc-comparison-v1",
        state: "PASS",
        capture_sha256: digest,
        blocks: 0,
        transactions: 0,
        program_matches: 0,
        account_matches: 0,
        failed_transactions: 0,
        rpc_commitment: "finalized",
        checks: [
            "block and parent hashes",
            "transaction order and count",
            "all transaction signatures",
            "execution status",
            "top-level and inner program references",
            "program filter results",
            "loaded-address account filter results",
        ],
        cryptographic_verification: false,
    };
    for block in &capture.all {
        let slot = block.slot;
        let rpc = fetch(slot).with_context(|| format!("slot {slot}: finalized getBlock failed"))?;
        ensure!(
            block.blockhash == rpc.blockhash
                && block.parent_blockhash == rpc.previous_blockhash
                && block.parent_slot == rpc.parent_slot,
            "slot {slot}: block or parent identity differs"
        );
        ensure!(
            block.transaction_count == rpc.transactions.len()
                && block.transactions.len() == rpc.transactions.len(),
            "slot {slot}: transaction count differs"
        );
        same_header(block, programs[&slot])?;
        same_header(block, accounts[&slot])?;
        let mut want_programs = Vec::new();
        let mut want_accounts = Vec::new();
        for (index, (got, row)) in block.transactions.iter().zip(rpc.transactions).enumerate() {
            let (expected, keys) = project_rpc(row, index)
                .with_context(|| format!("slot {slot}, transaction {index}"))?;
            compare_transaction(got, &expected)
                .with_context(|| format!("slot {slot}, transaction {index}"))?;
            if expected.top_level_programs.contains(&capture.program)
                || expected.inner_programs.contains(&capture.program)
            {
                want_programs.push(expected.clone());
            }
            if keys.contains(&capture.program) {
                want_accounts.push(expected.clone());
            }
            report.failed_transactions += usize::from(expected.success == Some(false));
            report.transactions += 1;
        }
        for (kind, got, expected) in [
            ("program", programs[&slot], want_programs),
            ("account", accounts[&slot], want_accounts),
        ] {
            ensure!(
                got.transactions.len() == expected.len(),
                "slot {slot}: {kind} filter count differs"
            );
            for (index, (got, expected)) in got.transactions.iter().zip(&expected).enumerate() {
                compare_transaction(got, expected)
                    .with_context(|| format!("slot {slot}, {kind} filter row {index}"))?;
            }
            if kind == "program" {
                report.program_matches += expected.len();
            } else {
                report.account_matches += expected.len();
            }
        }
        report.blocks += 1;
    }
    Ok(report)
}

fn fetch_rpc(
    client: &reqwest::blocking::Client,
    url: &reqwest::Url,
    slot: u64,
) -> Result<RpcBlock> {
    let body = json!({"jsonrpc":"2.0","id":1,"method":"getBlock","params":[slot,{
        "commitment":"finalized","encoding":"json","transactionDetails":"full","rewards":false,"maxSupportedTransactionVersion":1
    }]});
    let response = client
        .post(url.clone())
        .header("Content-Type", "application/json")
        .body(serde_json::to_vec(&body)?)
        .send()
        .map_err(|e| anyhow::anyhow!(e.without_url()))?;
    ensure!(
        response.status().is_success(),
        "RPC HTTP status {}",
        response.status()
    );
    let envelope: Value = serde_json::from_slice(&bounded_json(response)?)?;
    ensure!(
        envelope["jsonrpc"] == "2.0" && envelope["id"] == 1,
        "Invalid RPC response envelope"
    );
    if let Some(error) = envelope.get("error").filter(|value| !value.is_null()) {
        let code = error
            .get("code")
            .and_then(Value::as_i64)
            .context("Invalid RPC error code")?;
        bail!("RPC returned error code {code}");
    }
    let block = envelope
        .get("result")
        .filter(|value| !value.is_null())
        .context("Finalized RPC block is unavailable")?;
    serde_json::from_value(block.clone()).context("Invalid finalized RPC block")
}

pub(crate) fn run(args: CompareSdkRpcArgs) -> Result<()> {
    run_with_output(args, &mut std::io::stdout().lock())
}

fn run_with_output(args: CompareSdkRpcArgs, output: &mut impl std::io::Write) -> Result<()> {
    ensure!(
        matches!(args.rpc_url.scheme(), "http" | "https")
            && args.rpc_url.username().is_empty()
            && args.rpc_url.password().is_none()
            && args.rpc_url.fragment().is_none(),
        "Use an HTTP(S) RPC URL without user information or a fragment"
    );
    if let Some(path) = &args.report {
        ensure!(
            !path.try_exists()?,
            "Report already exists; select a new file"
        );
    }
    let bytes = bounded_json(File::open(&args.input).context("Open SDK capture")?)?;
    let capture: Capture = serde_json::from_slice(&bytes).context("Invalid SDK capture JSON")?;
    let digest = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(args.timeout_seconds))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let report = compare(capture, digest, |slot| {
        fetch_rpc(&client, &args.rpc_url, slot)
    })?;
    let mut bytes = serde_json::to_vec_pretty(&report)?;
    bytes.push(b'\n');
    if let Some(path) = args.report {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        if let Err(error) = file.write_all(&bytes).and_then(|_| file.sync_all()) {
            drop(file);
            let _ = std::fs::remove_file(&path);
            return Err(error.into());
        }
    }
    output.write_all(&bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sdk_transaction(index: usize) -> Value {
        json!({"index":index,"signature":format!("signature-{index}"),
            "signatures":[format!("signature-{index}"),format!("cosigner-{index}")],
            "success":index==0,"topLevelPrograms":[if index==0 {"program"} else {"other"}],
            "innerPrograms":if index==0 {vec!["other"]} else {vec![]},"innerCoverage":"recorded"})
    }

    fn input() -> Value {
        let block = json!({"slot":42,"parentSlot":41,"blockhash":"block","parentBlockhash":"parent",
            "transactionCount":2,"transactions":[sdk_transaction(0),sdk_transaction(1)]});
        let mut filtered = block.clone();
        filtered["transactions"] = json!([sdk_transaction(0)]);
        json!({"program":"program","all":[block.clone()],"programMatches":[filtered],"accountMatches":[block]})
    }

    fn rpc_block() -> Value {
        let rows: Vec<_> = (0..2).map(|index| json!({"version":0,
            "transaction":{"signatures":[format!("signature-{index}"),format!("cosigner-{index}")],
                "message":{"accountKeys":["wallet", if index==0 {"program"} else {"other"}],
                    "instructions":[{"programIdIndex":1}]}},
            "meta":{"err":if index==0 {Value::Null} else {json!({"InstructionError":[0,{"Custom":7}]})},
                "loadedAddresses":{"writable":[if index==0 {"other"} else {"program"}],"readonly":[]},
                "innerInstructions":if index==0 {json!([{"index":0,"instructions":[{"programIdIndex":2}]}])} else {json!([])}}})).collect();
        json!({"blockhash":"block","previousBlockhash":"parent","parentSlot":41,"transactions":rows})
    }

    fn check(input: Value, rpc: Value) -> Result<Report> {
        compare(serde_json::from_value(input)?, "test-digest".into(), |_| {
            Ok(serde_json::from_value(rpc.clone())?)
        })
    }

    #[test]
    fn compares_failed_transactions_loaded_accounts_cpi_and_all_signatures() {
        let report = check(input(), rpc_block()).unwrap();
        assert_eq!(
            (
                report.blocks,
                report.transactions,
                report.failed_transactions
            ),
            (1, 2, 1)
        );
        assert_eq!((report.program_matches, report.account_matches), (1, 2));
        assert!(!report.cryptographic_verification);
    }

    #[test]
    fn rejects_identity_order_signature_status_and_program_mismatches() {
        for (pointer, value) in [
            ("/all/0/blockhash", json!("wrong")),
            ("/all/0/parentBlockhash", json!("wrong")),
            ("/all/0/parentSlot", json!(40)),
            ("/all/0/transactionCount", json!(1)),
            ("/all/0/transactions/0/index", json!(1)),
            ("/all/0/transactions/0/signatures/1", json!("wrong")),
            ("/all/0/transactions/1/success", Value::Null),
            ("/all/0/transactions/0/topLevelPrograms", json!(["other"])),
            ("/all/0/transactions/0/innerPrograms", json!([])),
            ("/all/0/transactions/0/innerCoverage", json!("unavailable")),
        ] {
            let mut capture = input();
            *capture.pointer_mut(pointer).unwrap() = value;
            assert!(check(capture, rpc_block()).is_err(), "accepted {pointer}");
        }
    }

    #[test]
    fn checks_filtered_records_and_rejects_missing_extra_and_duplicate_slots() {
        for pointer in ["/programMatches", "/accountMatches"] {
            let mut capture = input();
            *capture.pointer_mut(pointer).unwrap() = json!([]);
            assert!(check(capture, rpc_block()).is_err());
            let mut capture = input();
            let duplicate = capture.pointer(pointer).unwrap()[0].clone();
            capture
                .pointer_mut(pointer)
                .unwrap()
                .as_array_mut()
                .unwrap()
                .push(duplicate);
            assert!(check(capture, rpc_block()).is_err());
            let mut capture = input();
            capture.pointer_mut(pointer).unwrap()[0]["transactions"][0]["success"] = json!(false);
            assert!(check(capture, rpc_block()).is_err());
            let mut capture = input();
            capture.pointer_mut(pointer).unwrap()[0]["slot"] = json!(43);
            assert!(check(capture, rpc_block()).is_err());
        }
        let mut capture = input();
        capture["accountMatches"][0]["transactions"]
            .as_array_mut()
            .unwrap()
            .reverse();
        assert!(check(capture, rpc_block()).is_err());
    }

    #[test]
    fn incomplete_rpc_metadata_and_invalid_indexes_cannot_pass() {
        for (pointer, value) in [
            ("/transactions/0/meta", Value::Null),
            ("/transactions/0/meta/innerInstructions", Value::Null),
            ("/transactions/0/meta/loadedAddresses", Value::Null),
            (
                "/transactions/0/transaction/message/instructions/0/programIdIndex",
                json!(8),
            ),
            ("/transactions/0/transaction/signatures", json!([])),
        ] {
            let mut rpc = rpc_block();
            *rpc.pointer_mut(pointer).unwrap() = value;
            assert!(check(input(), rpc).is_err(), "accepted {pointer}");
        }
        let mut rpc = rpc_block();
        rpc["transactions"][0]["meta"]
            .as_object_mut()
            .unwrap()
            .remove("err");
        assert!(check(input(), rpc).is_err());
    }

    #[test]
    fn invalid_capture_is_rejected_before_any_rpc_request() {
        for capture in [
            json!({"program":"program","all":[],"programMatches":[],"accountMatches":[]}),
            {
                let mut capture = input();
                let block = capture["all"][0].clone();
                capture["all"].as_array_mut().unwrap().push(block);
                capture
            },
        ] {
            let result = compare(
                serde_json::from_value(capture).unwrap(),
                String::new(),
                |_| panic!("RPC must not be called"),
            );
            assert!(result.is_err());
        }
    }

    fn server(body: Value, status: &str) -> (reqwest::Url, std::thread::JoinHandle<()>) {
        use std::{
            io::{BufRead, BufReader, Write},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!(
            "http://{}/?token=not-logged",
            listener.local_addr().unwrap()
        )
        .parse()
        .unwrap();
        let status = status.to_owned();
        let task = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(line.starts_with("POST /?token=not-logged "));
            let mut length = None;
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = Some(value.trim().parse::<usize>().unwrap());
                }
            }
            let mut bytes = vec![0; length.unwrap()];
            reader.read_exact(&mut bytes).unwrap();
            let request: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(request["method"], "getBlock");
            assert_eq!(request["params"][0], 42);
            assert_eq!(
                request["params"][1],
                json!({"commitment":"finalized","encoding":"json","transactionDetails":"full","rewards":false,"maxSupportedTransactionVersion":1})
            );
            let bytes = serde_json::to_vec(&body).unwrap();
            write!(stream,"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",bytes.len()).unwrap();
            stream.write_all(&bytes).unwrap();
        });
        (url, task)
    }

    #[test]
    fn rpc_transport_requests_finalized_json_and_rejects_errors_without_leaking_url() {
        for (body, status, ok) in [
            (
                json!({"jsonrpc":"2.0","id":1,"result":rpc_block()}),
                "200 OK",
                true,
            ),
            (
                json!({"jsonrpc":"2.0","id":1,"result":null}),
                "200 OK",
                false,
            ),
            (
                json!({"jsonrpc":"2.0","id":1,"error":{"code":-32009,"message":"not available"}}),
                "200 OK",
                false,
            ),
            (
                json!({"jsonrpc":"2.0","id":2,"result":rpc_block()}),
                "200 OK",
                false,
            ),
            (json!({"error":"unavailable"}), "503 Unavailable", false),
            (
                json!({"jsonrpc":"2.0","id":1,"result":rpc_block()}),
                "307 Temporary Redirect",
                false,
            ),
        ] {
            let (url, server) = server(body, status);
            let client = reqwest::blocking::Client::builder()
                .no_proxy()
                .build()
                .unwrap();
            let result = fetch_rpc(&client, &url, 42);
            assert_eq!(result.is_ok(), ok);
            if let Err(error) = result {
                assert!(!format!("{error:#}").contains("not-logged"));
            }
            server.join().unwrap();
        }
    }

    #[test]
    fn existing_report_is_preserved_without_reading_or_requesting_input() {
        let directory = tempfile::tempdir().unwrap();
        let report = directory.path().join("report.json");
        std::fs::write(&report, b"existing").unwrap();
        let error = run(CompareSdkRpcArgs {
            input: directory.path().join("missing"),
            rpc_url: "http://127.0.0.1:1".parse().unwrap(),
            report: Some(report.clone()),
            timeout_seconds: 1,
        })
        .unwrap_err();
        assert!(error.to_string().contains("already exists"));
        assert_eq!(std::fs::read(report).unwrap(), b"existing");
    }

    #[test]
    fn command_writes_bound_report_only_after_a_complete_match() {
        for matches in [true, false] {
            let directory = tempfile::tempdir().unwrap();
            let capture_path = directory.path().join("capture.json");
            let report_path = directory.path().join("report.json");
            let mut capture = input();
            if !matches {
                capture["all"][0]["transactions"][0]["signature"] = json!("wrong");
            }
            let bytes = serde_json::to_vec(&capture).unwrap();
            std::fs::write(&capture_path, &bytes).unwrap();
            let (url, server) = server(
                json!({"jsonrpc":"2.0","id":1,"result":rpc_block()}),
                "200 OK",
            );
            let mut output = Vec::new();
            let result = run_with_output(
                CompareSdkRpcArgs {
                    input: capture_path,
                    rpc_url: url,
                    report: Some(report_path.clone()),
                    timeout_seconds: 5,
                },
                &mut output,
            );
            server.join().unwrap();
            assert_eq!(result.is_ok(), matches);
            if matches {
                assert_eq!(std::fs::read(&report_path).unwrap(), output);
                let report: Value = serde_json::from_slice(&output).unwrap();
                assert_eq!(report["state"], "PASS");
                assert_eq!(report["transactions"], 2);
                let digest: String = Sha256::digest(&bytes)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                assert_eq!(report["capture_sha256"], digest);
            } else {
                assert!(!report_path.exists());
                assert!(output.is_empty());
            }
        }
    }
}
