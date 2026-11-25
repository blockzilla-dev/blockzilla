use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use protocol::{Response, read_request, write_response};
use std::{
    io::Write,
    os::unix::net::{UnixListener, UnixStream as StdUnixStream},
    thread,
};
use tempfile::TempDir;

fn hash(byte: u8) -> String {
    bs58::encode([byte; 32]).into_string()
}
fn source() -> SourceIdentity {
    SourceIdentity {
        instance_id: "client-test-instance-01".into(),
        genesis_hash: hash(1),
        node_identity: hash(2),
        agave_revision: "testrevision1234".into(),
    }
}
fn bank() -> BankContext {
    BankContext {
        slot: 15,
        bank_id: 8,
        blockhash: hash(3),
        parent_slot: 13,
        parent_blockhash: Some(hash(4)),
    }
}
fn value() -> Account {
    Account {
        lamports: u64::MAX,
        owner: hash(7),
        executable: false,
        rent_epoch: u64::MAX,
        data_base64: STANDARD.encode([0, 255, 8]),
    }
}
fn mock(
    handler: impl FnOnce(Request, &mut StdUnixStream) + Send + 'static,
) -> (TempDir, PathBuf, thread::JoinHandle<()>) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bridge.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let request = read_request(&mut stream).unwrap();
        handler(request, &mut stream);
    });
    (directory, path, handle)
}
fn client(path: PathBuf) -> AccountClient {
    AccountClient::new(path, source(), ClientOptions::default()).unwrap()
}
fn account_response(request: &Request) -> Response {
    let Operation::GetAccount { bank, pubkey } = &request.operation else {
        panic!("unexpected operation")
    };
    Response::ok(
        request,
        source(),
        ResponseData::GetAccount {
            bank: bank.clone(),
            entry: AccountEntry {
                pubkey: pubkey.clone(),
                account: Some(value()),
            },
        },
    )
}

fn block_value() -> LedgerBlock {
    let execution = ExecutionMetadata {
        error: None,
        fee: u64::MAX,
        pre_balances: vec![u64::MAX, 0],
        post_balances: vec![u64::MAX - 1, 1],
        inner_instructions: Some(serde_json::json!([])),
        pre_token_balances: None,
        post_token_balances: None,
        rewards: None,
        log_messages: Some(vec!["Program success".into()]),
        loaded_addresses: LoadedAddresses {
            writable: vec![hash(5)],
            readonly: vec![hash(6)],
        },
        return_data: Some(ReturnData {
            program_id: hash(7),
            data_base64: STANDARD.encode([8, 9]),
        }),
        compute_units_consumed: Some(97),
        cost_units: None,
    };
    let mut failed = execution.clone();
    failed.error = Some(serde_json::json!({"InstructionError":[1,{"Custom":42}]}));
    failed.log_messages = Some(vec!["Program failed".into()]);
    LedgerBlock {
        slot: 15,
        blockhash: hash(3),
        previous_blockhash: hash(4),
        parent_slot: 13,
        block_time: 1_234_567_890,
        block_height: u64::MAX,
        transactions: vec![
            LedgerTransaction {
                transaction_base64: STANDARD.encode([1, 2, 3]),
                execution,
            },
            LedgerTransaction {
                transaction_base64: STANDARD.encode([4, 5, 6]),
                execution: failed,
            },
        ],
        rewards: serde_json::json!([]),
        num_partitions: None,
    }
}

fn block_response(request: &Request) -> Response {
    Response::ok(
        request,
        source(),
        ResponseData::GetBlock {
            block: block_value(),
        },
    )
}

fn write_unchecked(socket: &mut StdUnixStream, response: &serde_json::Value) {
    let bytes = serde_json::to_vec(response).unwrap();
    socket
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .unwrap();
    socket.write_all(&bytes).unwrap();
}

#[tokio::test]
async fn ledger_block_preserves_complete_success_and_failed_execution() {
    for expected_blockhash in [None, Some(hash(3))] {
        let expected = expected_blockhash.clone();
        let (_directory, path, server) = mock(move |request, socket| {
            assert_eq!(
                request.operation,
                Operation::GetBlock {
                    slot: 15,
                    expected_blockhash: expected,
                }
            );
            write_response(socket, &block_response(&request)).unwrap();
        });
        let block = client(path)
            .get_block(15, expected_blockhash.as_deref())
            .await
            .unwrap();
        assert_eq!(block, block_value());
        assert!(block.transactions[0].execution.error.is_none());
        assert!(block.transactions[1].execution.error.is_some());
        server.join().unwrap();
    }
}

#[tokio::test]
async fn ledger_block_rejects_wrong_source_slot_hash_operation_and_request_id() {
    for case in 0..5 {
        let (_directory, path, server) = mock(move |request, socket| {
            let mut response = block_response(&request);
            match case {
                0 => response.source.instance_id = "foreign-instance-02".into(),
                1 | 2 => {
                    let Outcome::Ok(ResponseData::GetBlock { block }) = &mut response.outcome
                    else {
                        unreachable!()
                    };
                    if case == 1 {
                        block.slot += 1;
                    } else {
                        block.blockhash = hash(9);
                    }
                }
                3 => {
                    response.outcome = Outcome::Ok(ResponseData::Describe {
                        limits: ProtocolLimits::default(),
                    })
                }
                _ => response.request_id += 1,
            }
            write_response(socket, &response).unwrap();
        });
        let error = client(path)
            .get_block(15, Some(&hash(3)))
            .await
            .unwrap_err();
        assert!(matches!(
            (case, error),
            (0, Error::Protocol(protocol::Error::SourceMismatch))
                | (1 | 2, Error::Protocol(protocol::Error::BlockMismatch))
                | (3, Error::Protocol(protocol::Error::OperationMismatch))
                | (4, Error::Protocol(protocol::Error::RequestIdMismatch))
        ));
        server.join().unwrap();
    }
}

#[tokio::test]
async fn ledger_unavailable_unrooted_incomplete_and_hash_errors_are_distinct() {
    for code in [
        BridgeErrorCode::BlockUnavailable,
        BridgeErrorCode::BlockNotFinalized,
        BridgeErrorCode::BlockMetadataIncomplete,
        BridgeErrorCode::BlockHashMismatch,
    ] {
        let (_directory, path, server) = mock(move |request, socket| {
            write_response(
                socket,
                &Response::error(&request, source(), code, "block unavailable"),
            )
            .unwrap();
        });
        let Error::Remote(error) = client(path).get_block(15, None).await.unwrap_err() else {
            panic!("expected typed ledger error")
        };
        assert_eq!(error.code, code);
        server.join().unwrap();
    }
}

#[tokio::test]
async fn malformed_or_omitted_block_execution_is_never_accepted() {
    for case in 0..8 {
        let (_directory, path, server) = mock(move |request, socket| {
            let mut value = serde_json::to_value(block_response(&request)).unwrap();
            let block = &mut value["outcome"]["value"]["block"];
            match case {
                0 => {
                    block["transactions"][0]
                        .as_object_mut()
                        .unwrap()
                        .remove("execution");
                }
                1 => {
                    block["transactions"][0]["execution"]
                        .as_object_mut()
                        .unwrap()
                        .remove("error");
                }
                2 => {
                    block["transactions"][0]["execution"] = serde_json::Value::Null;
                }
                3 => {
                    block["transactions"][0]["execution"]["inner_instructions"] =
                        serde_json::json!({});
                }
                4 => {
                    block["transactions"][0]["transaction_base64"] = "Zh==".into();
                }
                5 => {
                    block["transactions"][0]["execution"]["loaded_addresses"]["writable"] =
                        serde_json::json!(["invalid"]);
                }
                6 => {
                    block["transactions"][0]["execution"]["return_data"]["data_base64"] =
                        "Zg".into();
                }
                _ => {
                    value["outcome"]["status"] = "processed".into();
                }
            }
            write_unchecked(socket, &value);
        });
        assert!(
            matches!(
                client(path).get_block(15, None).await,
                Err(Error::Protocol(_))
            ),
            "malformed case {case}"
        );
        server.join().unwrap();
    }
}

#[tokio::test]
async fn invalid_block_hash_fails_before_socket_access() {
    let client = client(PathBuf::from("/a/socket/that/does/not/exist"));
    assert!(matches!(
        client.get_block(15, Some("invalid")).await,
        Err(Error::Protocol(protocol::Error::Invalid(_)))
    ));
}

#[tokio::test]
async fn describe_checks_operator_pin_and_returns_bounded_capabilities() {
    let (_directory, path, server) = mock(|request, socket| {
        assert_eq!(request.operation, Operation::Describe);
        let response = Response::ok(
            &request,
            source(),
            ResponseData::Describe {
                limits: ProtocolLimits::default(),
            },
        );
        write_response(socket, &response).unwrap();
    });
    assert_eq!(
        client(path).describe().await.unwrap(),
        ProtocolLimits::default()
    );
    server.join().unwrap();
}

#[tokio::test]
async fn one_bank_batch_preserves_order_duplicates_absence_and_owned_values() {
    let keys = vec![hash(5), hash(6), hash(5)];
    let expected = keys.clone();
    let (_directory, path, server) = mock(move |request, socket| {
        let Operation::GetMultipleAccounts {
            bank: actual,
            pubkeys,
        } = &request.operation
        else {
            panic!("unexpected operation")
        };
        assert_eq!(actual, &bank());
        assert_eq!(pubkeys, &expected);
        let entries = pubkeys
            .iter()
            .map(|pubkey| AccountEntry {
                pubkey: pubkey.clone(),
                account: (pubkey != &hash(6)).then(value),
            })
            .collect();
        write_response(
            socket,
            &Response::ok(
                &request,
                source(),
                ResponseData::GetMultipleAccounts {
                    bank: actual.clone(),
                    entries,
                },
            ),
        )
        .unwrap();
    });
    let entries = client(path)
        .get_multiple_accounts(&bank(), &keys)
        .await
        .unwrap();
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.pubkey.clone())
            .collect::<Vec<_>>(),
        keys
    );
    assert_eq!(entries[0].account.as_ref().unwrap().lamports, u64::MAX);
    assert_eq!(entries[0].account.as_ref().unwrap().rent_epoch, u64::MAX);
    assert_eq!(entries[0], entries[2]);
    assert!(entries[1].account.is_none());
    server.join().unwrap();
}

#[tokio::test]
async fn foreign_source_and_wrong_bank_never_become_results() {
    for foreign in [true, false] {
        let (_directory, path, server) = mock(move |request, socket| {
            let mut response = account_response(&request);
            if foreign {
                response.source.instance_id = "foreign-instance-02".into();
            } else if let Outcome::Ok(ResponseData::GetAccount { bank, .. }) = &mut response.outcome
            {
                bank.bank_id += 1;
            }
            write_response(socket, &response).unwrap();
        });
        let error = client(path)
            .get_account(&bank(), &hash(5))
            .await
            .unwrap_err();
        assert!(matches!(
            (foreign, error),
            (true, Error::Protocol(protocol::Error::SourceMismatch))
                | (false, Error::Protocol(protocol::Error::BankMismatch))
        ));
        server.join().unwrap();
    }
}

#[tokio::test]
async fn server_cannot_drop_a_requested_parent_constraint() {
    let (_directory, path, server) = mock(|request, socket| {
        let mut response = account_response(&request);
        if let Outcome::Ok(ResponseData::GetAccount { bank, .. }) = &mut response.outcome {
            bank.parent_blockhash = None;
        }
        write_response(socket, &response).unwrap();
    });
    assert!(matches!(
        client(path).get_account(&bank(), &hash(5)).await,
        Err(Error::Protocol(protocol::Error::BankMismatch))
    ));
    server.join().unwrap();
}

#[tokio::test]
async fn omitted_parent_constraint_is_explicit_and_still_uses_exact_bank() {
    let (_directory, path, server) = mock(|request, socket| {
        let Operation::GetAccount { bank, .. } = &request.operation else {
            panic!("unexpected operation")
        };
        assert!(bank.parent_blockhash.is_none());
        write_response(socket, &account_response(&request)).unwrap();
    });
    let mut requested = bank();
    requested.parent_blockhash = None;
    assert_eq!(
        client(path)
            .get_account(&requested, &hash(5))
            .await
            .unwrap(),
        Some(value())
    );
    server.join().unwrap();
}

#[tokio::test]
async fn reordered_batch_and_wrong_operation_or_id_are_rejected() {
    for case in 0..3 {
        let (_directory, path, server) = mock(move |request, socket| {
            let response = match case {
                0 => Response::ok(
                    &request,
                    source(),
                    ResponseData::GetMultipleAccounts {
                        bank: bank(),
                        entries: vec![
                            AccountEntry {
                                pubkey: hash(6),
                                account: None,
                            },
                            AccountEntry {
                                pubkey: hash(5),
                                account: None,
                            },
                        ],
                    },
                ),
                1 => Response::ok(
                    &request,
                    source(),
                    ResponseData::Describe {
                        limits: ProtocolLimits::default(),
                    },
                ),
                _ => {
                    let mut response = Response::error(
                        &request,
                        source(),
                        BridgeErrorCode::BankRemoved,
                        "Bank removed",
                    );
                    response.request_id += 1;
                    response
                }
            };
            write_response(socket, &response).unwrap();
        });
        let result = client(path)
            .get_multiple_accounts(&bank(), &[hash(5), hash(6)])
            .await;
        assert!(matches!(
            (case, result),
            (
                0,
                Err(Error::Protocol(protocol::Error::AccountOrderMismatch))
            ) | (1, Err(Error::Protocol(protocol::Error::OperationMismatch)))
                | (2, Err(Error::Protocol(protocol::Error::RequestIdMismatch)))
        ));
        server.join().unwrap();
    }
}

#[tokio::test]
async fn removed_stale_source_budget_and_invalid_errors_stay_distinct() {
    for code in [
        BridgeErrorCode::BankRemoved,
        BridgeErrorCode::StaleBank,
        BridgeErrorCode::SourceMismatch,
        BridgeErrorCode::BudgetExceeded,
        BridgeErrorCode::InvalidRequest,
    ] {
        let (_directory, path, server) = mock(move |request, socket| {
            write_response(
                socket,
                &Response::error(&request, source(), code, "read unavailable"),
            )
            .unwrap();
        });
        let Error::Remote(error) = client(path)
            .get_account(&bank(), &hash(5))
            .await
            .unwrap_err()
        else {
            panic!("expected typed native error")
        };
        assert_eq!(error.code, code);
        server.join().unwrap();
    }
}

#[tokio::test]
async fn oversized_prefix_is_rejected_without_reading_a_body() {
    let (_directory, path, server) = mock(|_, socket| {
        socket
            .write_all(&((protocol::MAX_RESPONSE_BYTES + 1) as u32).to_be_bytes())
            .unwrap();
    });
    assert!(matches!(
        client(path).describe().await,
        Err(Error::Protocol(protocol::Error::FrameTooLarge { .. }))
    ));
    server.join().unwrap();
    let (_directory, path, server) = mock(|_, socket| {
        socket.write_all(&1025u32.to_be_bytes()).unwrap();
    });
    let client = AccountClient::new(
        path,
        source(),
        ClientOptions {
            max_response_bytes: 1024,
            ..ClientOptions::default()
        },
    )
    .unwrap();
    assert!(matches!(
        client.describe().await,
        Err(Error::Protocol(protocol::Error::FrameTooLarge {
            bytes: 1025,
            limit: 1024
        }))
    ));
    server.join().unwrap();
}

#[tokio::test]
async fn truncated_header_and_body_are_not_absent_accounts() {
    for header_only in [true, false] {
        let (_directory, path, server) = mock(move |_, socket| {
            if header_only {
                socket.write_all(&[0, 0]).unwrap();
            } else {
                socket.write_all(&100u32.to_be_bytes()).unwrap();
                socket.write_all(b"{}").unwrap();
            }
        });
        assert!(
            matches!(client(path).get_account(&bank(), &hash(5)).await, Err(Error::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof)
        );
        server.join().unwrap();
    }
}

#[tokio::test]
async fn one_deadline_covers_a_stalled_complete_response() {
    let (_directory, path, server) = mock(|_, _| {
        thread::sleep(Duration::from_millis(100));
    });
    let client = AccountClient::new(
        path,
        source(),
        ClientOptions {
            timeout: Duration::from_millis(20),
            ..ClientOptions::default()
        },
    )
    .unwrap();
    assert!(matches!(client.describe().await, Err(Error::Timeout)));
    server.join().unwrap();
}

#[tokio::test]
async fn invalid_requests_fail_before_socket_access() {
    let client = client(PathBuf::from("/a/socket/that/does/not/exist"));
    assert!(matches!(
        client
            .get_multiple_accounts(&bank(), &vec![hash(5); 101])
            .await,
        Err(Error::Protocol(protocol::Error::Invalid(_)))
    ));
    assert!(matches!(
        client.get_account(&bank(), "invalid").await,
        Err(Error::Protocol(protocol::Error::Invalid(_)))
    ));
}

#[test]
fn constructor_requires_an_operator_pin_and_finite_bounds() {
    assert!(AccountClient::new("relative.sock", source(), ClientOptions::default()).is_err());
    assert!(
        AccountClient::new(
            "/private/bridge.sock",
            source(),
            ClientOptions {
                timeout: Duration::ZERO,
                ..ClientOptions::default()
            }
        )
        .is_err()
    );
    assert!(
        AccountClient::new(
            "/private/bridge.sock",
            source(),
            ClientOptions {
                max_response_bytes: protocol::MAX_RESPONSE_BYTES + 1,
                ..ClientOptions::default()
            }
        )
        .is_err()
    );
    let mut invalid = source();
    invalid.instance_id.clear();
    assert!(AccountClient::new("/private/bridge.sock", invalid, ClientOptions::default()).is_err());
}
