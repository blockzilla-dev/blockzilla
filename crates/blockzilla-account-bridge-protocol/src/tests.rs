use super::*;
use std::io::Cursor;

fn hash(byte: u8) -> String {
    bs58::encode([byte; 32]).into_string()
}
fn source() -> SourceIdentity {
    SourceIdentity {
        instance_id: "test-instance-0001".into(),
        genesis_hash: hash(1),
        node_identity: hash(2),
        agave_revision: "testrev123456789".into(),
    }
}
fn bank() -> BankContext {
    BankContext {
        slot: 12,
        bank_id: 4,
        blockhash: hash(3),
        parent_slot: 10,
        parent_blockhash: Some(hash(4)),
    }
}
fn request() -> Request {
    Request::new(
        7,
        source(),
        Operation::GetMultipleAccounts {
            bank: bank(),
            pubkeys: vec![hash(5), hash(6), hash(5)],
        },
    )
}
fn account() -> Account {
    Account {
        lamports: u64::MAX,
        owner: hash(7),
        executable: true,
        rent_epoch: u64::MAX,
        data_base64: STANDARD.encode([0, 255, 4]),
    }
}
fn response(request: &Request) -> Response {
    Response::ok(
        request,
        source(),
        ResponseData::GetMultipleAccounts {
            bank: bank(),
            entries: vec![
                AccountEntry {
                    pubkey: hash(5),
                    account: Some(account()),
                },
                AccountEntry {
                    pubkey: hash(6),
                    account: None,
                },
                AccountEntry {
                    pubkey: hash(5),
                    account: Some(account()),
                },
            ],
        },
    )
}

#[test]
fn framed_round_trip_preserves_order_duplicates_nulls_and_full_u64() {
    let request = request();
    let mut wire = vec![];
    write_request(&mut wire, &request).unwrap();
    assert_eq!(
        u32::from_be_bytes(wire[..4].try_into().unwrap()) as usize,
        wire.len() - 4
    );
    assert_eq!(read_request(&mut Cursor::new(wire)).unwrap(), request);
    let response = response(&request);
    let mut wire = vec![];
    write_response(&mut wire, &response).unwrap();
    let actual = read_response(&mut Cursor::new(wire)).unwrap();
    actual.validate_for(&request).unwrap();
    assert_eq!(actual, response);
}

#[test]
fn exact_source_bank_operation_id_and_key_order_are_required() {
    let request = request();
    let original = response(&request);
    let mut changed = original.clone();
    changed.source.instance_id = "other-instance-002".into();
    assert!(matches!(
        changed.validate_for(&request),
        Err(Error::SourceMismatch)
    ));
    let mut changed = original.clone();
    changed.request_id += 1;
    assert!(matches!(
        changed.validate_for(&request),
        Err(Error::RequestIdMismatch)
    ));
    let mut changed = original.clone();
    if let Outcome::Ok(ResponseData::GetMultipleAccounts { bank, .. }) = &mut changed.outcome {
        bank.bank_id += 1;
    }
    assert!(matches!(
        changed.validate_for(&request),
        Err(Error::BankMismatch)
    ));
    let mut changed = original.clone();
    if let Outcome::Ok(ResponseData::GetMultipleAccounts { bank, .. }) = &mut changed.outcome {
        bank.parent_blockhash = None;
    }
    assert!(matches!(
        changed.validate_for(&request),
        Err(Error::BankMismatch)
    ));
    let mut changed = original.clone();
    if let Outcome::Ok(ResponseData::GetMultipleAccounts { entries, .. }) = &mut changed.outcome {
        entries.swap(0, 1);
    }
    assert!(matches!(
        changed.validate_for(&request),
        Err(Error::AccountOrderMismatch)
    ));
    let changed = Response::ok(
        &request,
        source(),
        ResponseData::Describe {
            limits: ProtocolLimits::default(),
        },
    );
    assert!(matches!(
        changed.validate_for(&request),
        Err(Error::OperationMismatch)
    ));
}

#[test]
fn duplicate_keys_cannot_return_conflicting_values_at_one_bank() {
    let request = request();
    let mut changed = response(&request);
    if let Outcome::Ok(ResponseData::GetMultipleAccounts { entries, .. }) = &mut changed.outcome {
        entries[2].account = None;
    }
    assert!(matches!(
        changed.validate_for(&request),
        Err(Error::AccountOrderMismatch)
    ));
}

#[test]
fn malformed_and_truncated_frames_fail_before_admission() {
    assert!(matches!(
        read_request(&mut Cursor::new(
            ((MAX_REQUEST_BYTES + 1) as u32).to_be_bytes()
        )),
        Err(Error::FrameTooLarge { .. })
    ));
    assert!(matches!(
        read_response(&mut Cursor::new(
            ((MAX_RESPONSE_BYTES + 1) as u32).to_be_bytes()
        )),
        Err(Error::FrameTooLarge { .. })
    ));
    assert!(read_request(&mut Cursor::new([0, 1])).is_err());
    let mut truncated = 20u32.to_be_bytes().to_vec();
    truncated.extend_from_slice(b"{}");
    assert!(read_response(&mut Cursor::new(truncated)).is_err());
    assert!(read_response(&mut Cursor::new(0u32.to_be_bytes())).is_err());
    let mut value = serde_json::to_value(request()).unwrap();
    value["extra"] = true.into();
    assert!(decode_request(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut value = serde_json::to_value(request()).unwrap();
    value["operation"]["bank"]
        .as_object_mut()
        .unwrap()
        .remove("parent_blockhash");
    assert!(decode_request(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut value = serde_json::to_value(response(&request())).unwrap();
    value["outcome"]["value"]["entries"][1]
        .as_object_mut()
        .unwrap()
        .remove("account");
    assert!(decode_response(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn key_count_base64_and_advertised_limits_are_bounded() {
    let mut request = request();
    request.operation = Operation::GetMultipleAccounts {
        bank: bank(),
        pubkeys: vec![hash(5); MAX_ACCOUNTS + 1],
    };
    assert!(request.validate().is_err());
    request.operation = Operation::GetMultipleAccounts {
        bank: bank(),
        pubkeys: vec![],
    };
    assert!(request.validate().is_err());
    let mut value = account();
    value.data_base64 = "Zg".into();
    assert!(value.validate().is_err());
    value.data_base64 = "Zh==".into();
    assert!(value.validate().is_err());
    assert!(
        ProtocolLimits {
            max_accounts: 101,
            ..ProtocolLimits::default()
        }
        .validate()
        .is_err()
    );
    let mut output = BoundedJson {
        bytes: vec![],
        limit: 4,
        overflow: None,
    };
    assert!(serde_json::to_writer(&mut output, "long string").is_err());
    assert!(output.bytes.len() <= 4);
}

#[test]
fn error_codes_remain_distinct_and_error_source_still_must_match() {
    let request = request();
    for code in [
        BridgeErrorCode::BankRemoved,
        BridgeErrorCode::StaleBank,
        BridgeErrorCode::SourceMismatch,
        BridgeErrorCode::BudgetExceeded,
        BridgeErrorCode::InvalidRequest,
        BridgeErrorCode::BlockUnavailable,
        BridgeErrorCode::BlockNotFinalized,
        BridgeErrorCode::BlockMetadataIncomplete,
        BridgeErrorCode::BlockHashMismatch,
        BridgeErrorCode::Internal,
    ] {
        let response = Response::error(&request, source(), code, "request unavailable");
        let actual = decode_response(&encode_response(&response).unwrap()).unwrap();
        actual.validate_for(&request).unwrap();
        assert_eq!(actual, response);
    }
}

fn ledger_block() -> LedgerBlock {
    LedgerBlock {
        slot: 12,
        blockhash: hash(3),
        previous_blockhash: hash(4),
        parent_slot: 10,
        block_time: -1,
        block_height: u64::MAX,
        transactions: vec![LedgerTransaction {
            transaction_base64: STANDARD.encode([1, 2, 3]),
            execution: ExecutionMetadata {
                error: Some(serde_json::json!({"InstructionError":[0,"Custom"]})),
                fee: u64::MAX,
                pre_balances: vec![u64::MAX, 0],
                post_balances: vec![u64::MAX - 1, 1],
                inner_instructions: Some(serde_json::json!([])),
                pre_token_balances: None,
                post_token_balances: Some(serde_json::json!([])),
                rewards: None,
                log_messages: Some(vec!["Program failed".into()]),
                loaded_addresses: LoadedAddresses {
                    writable: vec![hash(5)],
                    readonly: vec![hash(6)],
                },
                return_data: Some(ReturnData {
                    program_id: hash(7),
                    data_base64: STANDARD.encode([0, 255]),
                }),
                compute_units_consumed: Some(19),
                cost_units: None,
            },
        }],
        rewards: serde_json::json!([]),
        num_partitions: None,
    }
}

#[test]
fn rooted_block_round_trip_preserves_transaction_failure_metadata_and_u64() {
    for expected_blockhash in [None, Some(hash(3))] {
        let request = Request::new(
            17,
            source(),
            Operation::GetBlock {
                slot: 12,
                expected_blockhash,
            },
        );
        let decoded = decode_request(&encode_request(&request).unwrap()).unwrap();
        assert_eq!(decoded, request);
        let response = Response::ok(
            &request,
            source(),
            ResponseData::GetBlock {
                block: ledger_block(),
            },
        );
        let mut wire = vec![];
        write_response(&mut wire, &response).unwrap();
        let actual = read_response(&mut Cursor::new(wire)).unwrap();
        actual.validate_for(&request).unwrap();
        assert_eq!(actual, response);
        assert_eq!(VERSION, 1);
    }
}

#[test]
fn block_identity_must_match_slot_and_optional_hash() {
    let request = Request::new(
        18,
        source(),
        Operation::GetBlock {
            slot: 12,
            expected_blockhash: Some(hash(3)),
        },
    );
    for changed_slot in [false, true] {
        let mut block = ledger_block();
        if changed_slot {
            block.slot += 1;
        } else {
            block.blockhash = hash(8);
        }
        let response = Response::ok(&request, source(), ResponseData::GetBlock { block });
        assert!(matches!(
            response.validate_for(&request),
            Err(Error::BlockMismatch)
        ));
    }
    let unpinned = Request::new(
        18,
        source(),
        Operation::GetBlock {
            slot: 12,
            expected_blockhash: None,
        },
    );
    let mut block = ledger_block();
    block.blockhash = hash(8);
    Response::ok(&unpinned, source(), ResponseData::GetBlock { block })
        .validate_for(&unpinned)
        .unwrap();
}

#[test]
fn block_options_and_execution_metadata_require_explicit_fields() {
    let request = Request::new(
        19,
        source(),
        Operation::GetBlock {
            slot: 12,
            expected_blockhash: None,
        },
    );
    let mut value = serde_json::to_value(&request).unwrap();
    value["operation"]
        .as_object_mut()
        .unwrap()
        .remove("expected_blockhash");
    assert!(decode_request(&serde_json::to_vec(&value).unwrap()).is_err());
    let response = Response::ok(
        &request,
        source(),
        ResponseData::GetBlock {
            block: ledger_block(),
        },
    );
    let original = serde_json::to_value(&response).unwrap();
    for field in [
        "error",
        "fee",
        "pre_balances",
        "post_balances",
        "inner_instructions",
        "pre_token_balances",
        "post_token_balances",
        "rewards",
        "log_messages",
        "loaded_addresses",
        "return_data",
        "compute_units_consumed",
        "cost_units",
    ] {
        let mut value = original.clone();
        value["outcome"]["value"]["block"]["transactions"][0]["execution"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(
            decode_response(&serde_json::to_vec(&value).unwrap()).is_err(),
            "omitted {field}"
        );
    }
    let mut value = original;
    value["outcome"]["value"]["block"]
        .as_object_mut()
        .unwrap()
        .remove("num_partitions");
    assert!(decode_response(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn ledger_block_rejects_invalid_metadata_addresses_and_transaction_encoding() {
    let original = ledger_block();
    for bytes in [
        "".to_owned(),
        "Zg".into(),
        "Zh==".into(),
        STANDARD.encode(vec![0; MAX_TRANSACTION_BYTES + 1]),
    ] {
        let mut block = original.clone();
        block.transactions[0].transaction_base64 = bytes;
        assert!(block.validate().is_err());
    }
    let mut block = original.clone();
    block.transactions[0].transaction_base64 =
        STANDARD.encode(vec![0; MAX_LEGACY_TRANSACTION_BYTES]);
    block.validate().unwrap();
    for field in [
        "inner_instructions",
        "pre_token_balances",
        "post_token_balances",
        "rewards",
    ] {
        let mut value = serde_json::to_value(&original).unwrap();
        value["transactions"][0]["execution"][field] = serde_json::json!({"wrong":"object"});
        assert!(
            serde_json::from_value::<LedgerBlock>(value)
                .unwrap()
                .validate()
                .is_err(),
            "non-array {field}"
        );
    }
    let mut block = original.clone();
    block.transactions[0].execution.loaded_addresses.readonly[0] = "invalid".into();
    assert!(block.validate().is_err());
    let mut block = original.clone();
    block.transactions[0]
        .execution
        .return_data
        .as_mut()
        .unwrap()
        .data_base64 = "Zg".into();
    assert!(block.validate().is_err());
    let mut block = original.clone();
    block.transactions[0].execution.post_balances.pop();
    assert!(block.validate().is_err());
    let mut block = original.clone();
    block.rewards = serde_json::json!({});
    assert!(block.validate().is_err());
    let mut block = original;
    block.transactions = vec![block.transactions[0].clone(); MAX_BLOCK_TRANSACTIONS + 1];
    assert!(block.validate().is_err());
}

#[test]
fn ledger_block_accepts_extended_v1_transactions_without_relaxing_legacy_or_v0() {
    for length in [
        MAX_LEGACY_TRANSACTION_BYTES + 1,
        2731,
        MAX_TRANSACTION_BYTES,
    ] {
        let mut block = ledger_block();
        let mut bytes = vec![0; length];
        bytes[0] = V1_TRANSACTION_PREFIX;
        block.transactions[0].transaction_base64 = STANDARD.encode(&bytes);
        block.validate().unwrap();
        let response = Response::ok(
            &Request::new(
                7,
                source(),
                Operation::GetBlock {
                    slot: block.slot,
                    expected_blockhash: Some(block.blockhash.clone()),
                },
            ),
            source(),
            ResponseData::GetBlock { block },
        );
        decode_response(&encode_response(&response).unwrap()).unwrap();
        for first_byte in [0, 1, 0x7f, 0x80, 0x82] {
            let mut legacy = ledger_block();
            bytes[0] = first_byte;
            legacy.transactions[0].transaction_base64 = STANDARD.encode(&bytes);
            assert!(
                legacy.validate().is_err(),
                "non-V1 wire must keep the legacy bound"
            );
        }
    }
    let mut block = ledger_block();
    let mut bytes = vec![0; MAX_TRANSACTION_BYTES + 1];
    bytes[0] = V1_TRANSACTION_PREFIX;
    block.transactions[0].transaction_base64 = STANDARD.encode(bytes);
    assert!(block.validate().is_err());
}
