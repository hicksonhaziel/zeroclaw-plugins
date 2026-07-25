use std::collections::VecDeque;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use realms_execution_audit::core::audit::{AuditComplete, AuditOutcome};
use realms_execution_audit::core::audit_error::AuditError;
use realms_execution_audit::core::evidence::{
    fingerprint_evidence_v1, EvidenceSnapshot, FinalObservation, ObservationRole,
    EVIDENCE_V1_DOMAIN,
};
use realms_execution_audit::core::execution::Fingerprint;
use realms_execution_audit::core::governance::pda::derive_proposal_transaction;
use realms_execution_audit::core::limits::{
    MAX_AUDIT_OUTPUT_BYTES, MAX_FINAL_BATCH_RESPONSE_BYTES, MAX_SINGLE_ACCOUNT_RESPONSE_BYTES,
};
use realms_execution_audit::core::output::render_audit_outcome;
use realms_execution_audit::core::policy::{
    InstructionLocation, UnresolvedInstruction, UnresolvedReason,
};
use realms_execution_audit::core::pubkey::{Pubkey, MAINNET_GOVERNANCE_PROGRAM};
use realms_execution_audit::core::rpc::{
    account_info_request, multiple_accounts_request, AccountObservation, HttpResponse, RpcRequest,
    RpcTransport,
};
use realms_execution_audit::execute_audit_with_transport;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const REALM: &str = "49STYcijF8oCwrUqM48sqWAoRL57p9KpXfHGvGiaRfDY";
const GOVERNANCE: &str = "5huMP3kiScHL2Lr4mFLo4BWDBzLCTvgnwaQ3YepjASLv";
const PROPOSAL: &str = "A35WTABGwuqJZkSEsSwrACCzXK2jPeT7jZRmbq4JR7dY";
const TRANSACTION_0: &str = "41MAfVcmwtGGzTP12xUaDo2w4grednxyXaDcvZcpnVMp";
const TRANSACTION_1: &str = "76xgDiVSqaGC6pHH8ucQ8xuUYhQPibYUdWYum7emhEFd";
const TRANSACTION_2: &str = "G7grzkzR5JM8ntLM1UymioBZ6sMTd4duZukuTGDvNeGM";
const OWNER: &str = "GovER5Lthms3bLBqWub97yVrMmEogzX7xNjdXpPPCVZw";

const REALM_HEX: &str = include_str!("../../../crates/mandate-core/tests/fixtures/realm_v2.hex");
const GOVERNANCE_HEX: &str =
    include_str!("../../../crates/mandate-core/tests/fixtures/mint_governance_v2.hex");
const PROPOSAL_HEX: &str =
    include_str!("../../../crates/mandate-core/tests/fixtures/proposal_v2.hex");
const TRANSACTION_0_HEX: &str =
    include_str!("../../../crates/mandate-core/tests/fixtures/proposal_transaction_0_v2.hex");
const TRANSACTION_1_HEX: &str =
    include_str!("../../../crates/mandate-core/tests/fixtures/proposal_transaction_1_v2.hex");

#[derive(Default)]
struct MockTransport {
    responses: VecDeque<HttpResponse>,
    requests: Vec<RpcRequest>,
}

impl MockTransport {
    fn new(responses: Vec<HttpResponse>) -> Self {
        Self {
            responses: responses.into(),
            requests: Vec::new(),
        }
    }
}

impl RpcTransport for MockTransport {
    fn send(&mut self, request: &RpcRequest) -> Result<HttpResponse, AuditError> {
        self.requests.push(request.clone());
        self.responses.pop_front().ok_or(AuditError::Transport)
    }
}

fn pubkey(value: &str) -> Pubkey {
    Pubkey::from_base58(value).unwrap()
}

fn decode_hex(value: &str) -> Vec<u8> {
    let value = value.trim();
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn account(data: &[u8], lamports: u64, rent_epoch: u64) -> Value {
    json!({
        "data": [STANDARD.encode(data), "base64"],
        "executable": false,
        "lamports": lamports,
        "owner": OWNER,
        "rentEpoch": rent_epoch,
        "space": data.len()
    })
}

fn envelope(id: u64, slot: u64, value: Value) -> HttpResponse {
    HttpResponse {
        status: 200,
        body: serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "result": {"context":{"apiVersion":"3.1.8","slot":slot},"value":value},
            "id": id
        }))
        .unwrap(),
    }
}

fn standard_responses() -> Vec<HttpResponse> {
    let proposal = decode_hex(PROPOSAL_HEX);
    let governance = decode_hex(GOVERNANCE_HEX);
    let realm = decode_hex(REALM_HEX);
    let transaction_0 = decode_hex(TRANSACTION_0_HEX);
    let transaction_1 = decode_hex(TRANSACTION_1_HEX);
    vec![
        envelope(1, 100, account(&proposal, 31, 301)),
        envelope(2, 101, account(&governance, 21, 201)),
        envelope(3, 102, account(&realm, 11, 101)),
        envelope(
            4,
            103,
            json!([
                account(&proposal, 3000, 30),
                account(&governance, 2000, 20),
                account(&realm, 1000, 10),
                account(&transaction_0, 4000, 40),
                account(&transaction_1, 5000, 50)
            ]),
        ),
    ]
}

fn complete(transport: &mut MockTransport) -> AuditComplete {
    let dispatch = execute_audit_with_transport(pubkey(PROPOSAL), transport).unwrap();
    match dispatch.outcome {
        AuditOutcome::Complete(complete) => *complete,
        other => panic!("unexpected outcome: {other:?}"),
    }
}

#[test]
fn coherent_fixture_runs_exact_four_call_component_dispatch() {
    let mut transport = MockTransport::new(standard_responses());
    let dispatch = execute_audit_with_transport(pubkey(PROPOSAL), &mut transport).unwrap();
    let complete = match &dispatch.outcome {
        AuditOutcome::Complete(complete) => complete,
        other => panic!("unexpected outcome: {other:?}"),
    };
    assert_eq!(transport.requests.len(), 4);
    assert_eq!(
        transport.requests[0].response_limit,
        MAX_SINGLE_ACCOUNT_RESPONSE_BYTES
    );
    assert_eq!(
        transport.requests[3].response_limit,
        MAX_FINAL_BATCH_RESPONSE_BYTES
    );
    let request_bodies = transport
        .requests
        .iter()
        .map(|request| serde_json::from_slice::<Value>(&request.body).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(request_bodies[0]["method"], "getAccountInfo");
    assert_eq!(request_bodies[1]["params"][1]["minContextSlot"], 100);
    assert_eq!(request_bodies[2]["params"][1]["minContextSlot"], 101);
    assert_eq!(request_bodies[3]["method"], "getMultipleAccounts");
    assert_eq!(request_bodies[3]["params"][0].as_array().unwrap().len(), 5);
    assert_eq!(request_bodies[3]["params"][1]["minContextSlot"], 102);
    for request in &request_bodies {
        assert_eq!(request["params"][1]["commitment"], "finalized");
        assert_eq!(request["params"][1]["encoding"], "base64");
    }
    assert!(!transport.requests.iter().any(|request| {
        std::str::from_utf8(&request.body)
            .unwrap()
            .contains("getProgramAccounts")
    }));

    assert_eq!(
        hex(complete.execution_fingerprint.0),
        "4fb663823e32d7abc5162ddf0c29cf234e604311e0a316bdf09a892cea518691"
    );
    assert_eq!(
        hex(complete.evidence_fingerprint.0),
        "f67bad3d151a0ee7723fbecb278fd60541662f394f26220c7fb5667a358909f4"
    );
    assert_eq!(complete.instruction_count, 2);
    assert!(dispatch.output.len() <= MAX_AUDIT_OUTPUT_BYTES);
    let output: Value = serde_json::from_str(&dispatch.output).unwrap();
    assert_eq!(output["retrieval_status"], "complete");
    assert_eq!(output["analysis_status"], "unresolved");
    assert!(output["risk_level"].is_null());
    assert_eq!(output["risk_reason"], "no_supported_effects");
    assert_eq!(output["proposal"], PROPOSAL);
    assert_eq!(output["governance"], GOVERNANCE);
    assert_eq!(output["realm"], REALM);
    assert!(!dispatch.output.contains("91bd4499"));
    assert!(!dispatch.output.to_ascii_lowercase().contains("safe"));
}

#[test]
fn pda_vectors_match_pinned_governance_source() {
    for (index, expected, bump) in [
        (0, TRANSACTION_0, 255),
        (1, TRANSACTION_1, 255),
        (2, TRANSACTION_2, 252),
    ] {
        let (address, actual_bump) =
            derive_proposal_transaction(MAINNET_GOVERNANCE_PROGRAM, pubkey(PROPOSAL), 0, index)
                .unwrap();
        assert_eq!(address.to_base58(), expected);
        assert_eq!(actual_bump, bump);
    }
}

#[test]
fn canonical_transaction_gap_is_retrieved_and_reconstructed() {
    let mut proposal = decode_hex(PROPOSAL_HEX);
    proposal[129..131].copy_from_slice(&3u16.to_le_bytes());
    let governance = decode_hex(GOVERNANCE_HEX);
    let realm = decode_hex(REALM_HEX);
    let transaction_0 = decode_hex(TRANSACTION_0_HEX);
    let mut transaction_2 = decode_hex(TRANSACTION_1_HEX);
    transaction_2[34..36].copy_from_slice(&2u16.to_le_bytes());
    let responses = vec![
        envelope(1, 100, account(&proposal, 1, 1)),
        envelope(2, 101, account(&governance, 1, 1)),
        envelope(3, 102, account(&realm, 1, 1)),
        envelope(
            4,
            103,
            json!([
                account(&proposal, 1, 1),
                account(&governance, 1, 1),
                account(&realm, 1, 1),
                account(&transaction_0, 1, 1),
                null,
                account(&transaction_2, 1, 1)
            ]),
        ),
    ];
    let mut transport = MockTransport::new(responses);
    let complete = complete(&mut transport);
    assert_eq!(complete.transaction_slot_count, 3);
    assert_eq!(complete.surviving_transaction_count, 2);
}

#[test]
fn aggregate_discovery_span_over_64_stops_before_final_batch() {
    let mut proposal = decode_hex(PROPOSAL_HEX);
    let option = proposal[105..131].to_vec();
    proposal[101..105].copy_from_slice(&2u32.to_le_bytes());
    proposal[129..131].copy_from_slice(&32u16.to_le_bytes());
    proposal.splice(131..131, option);
    proposal[155..157].copy_from_slice(&33u16.to_le_bytes());

    let mut responses = standard_responses();
    responses[0] = envelope(1, 100, account(&proposal, 31, 301));
    let mut transport = MockTransport::new(responses);
    let dispatch = execute_audit_with_transport(pubkey(PROPOSAL), &mut transport).unwrap();
    assert!(matches!(
        dispatch.outcome,
        AuditOutcome::Incomplete(failure) if failure.error == AuditError::DiscoveryLimit
    ));
    assert_eq!(transport.requests.len(), 3);
    assert!(!transport.requests.iter().any(|request| {
        std::str::from_utf8(&request.body)
            .unwrap()
            .contains("getMultipleAccounts")
    }));
}

#[test]
fn preliminary_lamports_and_rent_do_not_affect_authoritative_fingerprints() {
    let mut baseline = MockTransport::new(standard_responses());
    let expected = complete(&mut baseline);
    let mut changed = standard_responses();
    for response in changed.iter_mut().take(3) {
        let mut value: Value = serde_json::from_slice(&response.body).unwrap();
        value["result"]["context"]["slot"] = json!(1);
        value["result"]["value"]["lamports"] = json!(u64::MAX);
        value["result"]["value"]["rentEpoch"] = json!(u64::MAX);
        response.body = serde_json::to_vec(&value).unwrap();
    }
    let mut changed = MockTransport::new(changed);
    let actual = complete(&mut changed);
    assert_eq!(actual.execution_fingerprint, expected.execution_fingerprint);
    assert_eq!(actual.evidence_fingerprint, expected.evidence_fingerprint);
}

#[test]
fn preliminary_security_field_change_is_incomplete() {
    for field in ["owner", "executable", "data"] {
        let mut responses = standard_responses();
        let mut final_response: Value = serde_json::from_slice(&responses[3].body).unwrap();
        match field {
            "owner" => {
                final_response["result"]["value"][0]["owner"] =
                    json!("GTesTBiEWE32WHXXE2S4XbZvA5CrEc4xs6ZgRe895dP")
            }
            "executable" => final_response["result"]["value"][0]["executable"] = json!(true),
            "data" => {
                final_response["result"]["value"][0]["data"][0] =
                    json!(STANDARD.encode([14u8; 32]));
                final_response["result"]["value"][0]["space"] = json!(32);
            }
            _ => unreachable!(),
        }
        responses[3].body = serde_json::to_vec(&final_response).unwrap();
        let mut transport = MockTransport::new(responses);
        assert!(matches!(
            execute_audit_with_transport(pubkey(PROPOSAL), &mut transport)
                .unwrap()
                .outcome,
            AuditOutcome::Incomplete(_)
        ));
    }
}

#[test]
fn final_proposal_transaction_wrong_owner_fails_closed() {
    let mut responses = standard_responses();
    let mut value: Value = serde_json::from_slice(&responses[3].body).unwrap();
    value["result"]["value"][3]["owner"] = json!("11111111111111111111111111111111");
    responses[3].body = serde_json::to_vec(&value).unwrap();

    let mut transport = MockTransport::new(responses);
    let dispatch = execute_audit_with_transport(pubkey(PROPOSAL), &mut transport).unwrap();
    assert!(matches!(
        dispatch.outcome,
        AuditOutcome::Incomplete(failure) if failure.error == AuditError::WrongOwner
    ));
}

#[test]
fn final_proposal_transaction_wrong_layout_fails_closed() {
    let mut responses = standard_responses();
    let mut transaction = decode_hex(TRANSACTION_0_HEX);
    transaction[0] = 14;
    let mut value: Value = serde_json::from_slice(&responses[3].body).unwrap();
    value["result"]["value"][3] = account(&transaction, 4000, 40);
    responses[3].body = serde_json::to_vec(&value).unwrap();

    let mut transport = MockTransport::new(responses);
    let dispatch = execute_audit_with_transport(pubkey(PROPOSAL), &mut transport).unwrap();
    assert!(matches!(
        dispatch.outcome,
        AuditOutcome::Incomplete(failure) if failure.error == AuditError::Governance
    ));
}

#[test]
fn malformed_rpc_protocol_cases_fail_closed() {
    let cases = [
        b"not-json".to_vec(),
        br#"{"jsonrpc":"2.0","id":1,"id":1,"result":{"context":{"slot":100},"value":null}}"#.to_vec(),
        serde_json::to_vec(&json!({"jsonrpc":"1.0","id":1,"result":{"context":{"slot":100},"value":null}})).unwrap(),
        serde_json::to_vec(&json!({"jsonrpc":"2.0","id":9,"result":{"context":{"slot":100},"value":null}})).unwrap(),
        serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"no"}})).unwrap(),
        serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"result":{"context":{"slot":100},"value":null},"error":{"code":-1,"message":"no"}})).unwrap(),
        serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1})).unwrap(),
        serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"result":{"value":null}})).unwrap(),
        serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"result":{"context":{"slot":100}}})).unwrap(),
    ];
    for body in cases {
        let mut responses = standard_responses();
        responses[0].body = body;
        let mut transport = MockTransport::new(responses);
        assert!(!matches!(
            execute_audit_with_transport(pubkey(PROPOSAL), &mut transport)
                .unwrap()
                .outcome,
            AuditOutcome::Complete(_)
        ));
    }
}

#[test]
fn hostile_account_encoding_and_sizes_fail_closed() {
    for mutation in ["encoding", "base64", "encoded", "decoded", "owner"] {
        let mut responses = standard_responses();
        let mut value: Value = serde_json::from_slice(&responses[0].body).unwrap();
        match mutation {
            "encoding" => value["result"]["value"]["data"][1] = json!("base64+zstd"),
            "base64" => value["result"]["value"]["data"][0] = json!("!!!!"),
            "encoded" => value["result"]["value"]["data"][0] = json!("A".repeat(5_465)),
            "decoded" => {
                value["result"]["value"]["data"][0] = json!(STANDARD.encode(vec![0u8; 4_097]))
            }
            "owner" => value["result"]["value"]["owner"] = json!("!!!!"),
            _ => unreachable!(),
        }
        responses[0].body = serde_json::to_vec(&value).unwrap();
        let mut transport = MockTransport::new(responses);
        assert!(matches!(
            execute_audit_with_transport(pubkey(PROPOSAL), &mut transport)
                .unwrap()
                .outcome,
            AuditOutcome::Failed(_)
        ));
    }
}

#[test]
fn missing_extra_wrong_type_owner_and_slot_cases_fail_closed() {
    for mutation in [
        "missing_parent",
        "missing_survivor",
        "extra",
        "wrong_type",
        "wrong_owner",
        "slot",
    ] {
        let mut responses = standard_responses();
        match mutation {
            "missing_parent" => responses[1] = envelope(2, 101, Value::Null),
            "missing_survivor" => {
                let mut value: Value = serde_json::from_slice(&responses[3].body).unwrap();
                value["result"]["value"][4] = Value::Null;
                responses[3].body = serde_json::to_vec(&value).unwrap();
            }
            "extra" => {
                let mut proposal = decode_hex(PROPOSAL_HEX);
                proposal[127..129].copy_from_slice(&1u16.to_le_bytes());
                responses[0] = envelope(1, 100, account(&proposal, 31, 301));
                let mut value: Value = serde_json::from_slice(&responses[3].body).unwrap();
                value["result"]["value"][0] = account(&proposal, 3000, 30);
                responses[3].body = serde_json::to_vec(&value).unwrap();
            }
            "wrong_type" => {
                let mut proposal = decode_hex(PROPOSAL_HEX);
                proposal[0] = 16;
                responses[0] = envelope(1, 100, account(&proposal, 31, 301));
            }
            "wrong_owner" => {
                let response = responses.remove(0);
                responses.insert(
                    0,
                    rewrite_owner(response, "11111111111111111111111111111111"),
                );
            }
            "slot" => {
                let response = responses.remove(1);
                responses.insert(1, rewrite_slot(response, 99));
            }
            _ => unreachable!(),
        }
        let mut transport = MockTransport::new(responses);
        assert!(!matches!(
            execute_audit_with_transport(pubkey(PROPOSAL), &mut transport)
                .unwrap()
                .outcome,
            AuditOutcome::Complete(_)
        ));
    }
}

#[test]
fn response_and_request_bounds_and_duplicate_addresses_are_enforced() {
    let mut responses = standard_responses();
    responses[0].body = vec![b' '; MAX_SINGLE_ACCOUNT_RESPONSE_BYTES + 1];
    let mut transport = MockTransport::new(responses);
    assert!(matches!(
        execute_audit_with_transport(pubkey(PROPOSAL), &mut transport)
            .unwrap()
            .outcome,
        AuditOutcome::Failed(_)
    ));

    let duplicate = [pubkey(PROPOSAL), pubkey(PROPOSAL)];
    assert_eq!(
        multiple_accounts_request(4, &duplicate, 1, MAX_FINAL_BATCH_RESPONSE_BYTES).unwrap_err(),
        AuditError::DuplicateAddress
    );
    assert!(
        account_info_request(1, pubkey(PROPOSAL), None, 1)
            .unwrap()
            .body
            .len()
            < 4_096
    );
    let request = account_info_request(1, pubkey(PROPOSAL), None, 1).unwrap();
    let debug = format!("{request:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains(PROPOSAL));
}

#[test]
fn positional_length_and_embedded_transaction_coordinates_fail_closed() {
    let mut shortened = standard_responses();
    let mut value: Value = serde_json::from_slice(&shortened[3].body).unwrap();
    value["result"]["value"].as_array_mut().unwrap().pop();
    shortened[3].body = serde_json::to_vec(&value).unwrap();
    let mut transport = MockTransport::new(shortened);
    assert!(matches!(
        execute_audit_with_transport(pubkey(PROPOSAL), &mut transport)
            .unwrap()
            .outcome,
        AuditOutcome::Failed(_)
    ));

    let mut mismatched = standard_responses();
    let mut transaction = decode_hex(TRANSACTION_1_HEX);
    transaction[34..36].copy_from_slice(&7u16.to_le_bytes());
    let mut value: Value = serde_json::from_slice(&mismatched[3].body).unwrap();
    value["result"]["value"][4] = account(&transaction, 5000, 50);
    mismatched[3].body = serde_json::to_vec(&value).unwrap();
    let mut transport = MockTransport::new(mismatched);
    assert!(matches!(
        execute_audit_with_transport(pubkey(PROPOSAL), &mut transport)
            .unwrap()
            .outcome,
        AuditOutcome::Incomplete(_)
    ));
}

#[test]
fn worst_case_bounded_output_caps_unresolved_samples() {
    let mut transport = MockTransport::new(standard_responses());
    let mut complete = complete(&mut transport);
    complete.instruction_count = 512;
    complete.analysis.unresolved_instruction_count = 512;
    complete.analysis.unresolved_samples = (0..8)
        .map(|instruction_index| UnresolvedInstruction {
            location: InstructionLocation {
                option_index: 0,
                transaction_index: 1,
                instruction_index,
                program: pubkey(PROPOSAL),
            },
            reason: UnresolvedReason::UnsupportedProgram,
        })
        .collect();
    let output = render_audit_outcome(&AuditOutcome::Complete(Box::new(complete))).unwrap();
    assert!(output.len() <= MAX_AUDIT_OUTPUT_BYTES);
    let value: Value = serde_json::from_str(&output).unwrap();
    assert_eq!(value["unresolved_samples"].as_array().unwrap().len(), 1);
    assert_eq!(value["unresolved_samples_truncated"], true);
}

#[test]
fn normal_success_output_meets_the_agent_size_target() {
    let mut transport = MockTransport::new(standard_responses());
    let output =
        render_audit_outcome(&AuditOutcome::Complete(Box::new(complete(&mut transport)))).unwrap();
    assert!(
        output.len() <= 1_600,
        "normal output was {} bytes",
        output.len()
    );
    let value: Value = serde_json::from_str(&output).unwrap();
    assert_eq!(value["counts"]["unresolved_instructions"], 2);
    assert_eq!(value["unresolved_samples"].as_array().unwrap().len(), 1);
    assert_eq!(value["unresolved_samples_truncated"], true);
}

#[test]
fn evidence_golden_is_independent_and_sensitive_only_to_authoritative_snapshot() {
    let snapshot = golden_evidence_snapshot();
    let expected = "f67bad3d151a0ee7723fbecb278fd60541662f394f26220c7fb5667a358909f4";
    assert_eq!(hex(reference_evidence(&snapshot)), expected);
    assert_eq!(hex(fingerprint_evidence_v1(&snapshot).unwrap().0), expected);
    for _ in 0..16 {
        assert_eq!(hex(fingerprint_evidence_v1(&snapshot).unwrap().0), expected);
    }

    let mut mutations = Vec::new();
    let mut changed = snapshot.clone();
    changed.authoritative_slot += 1;
    mutations.push(changed);
    for field in 0..6 {
        let mut changed = snapshot.clone();
        let account = changed.observations[0].account.as_mut().unwrap();
        match field {
            0 => account.owner = pubkey("11111111111111111111111111111111"),
            1 => account.executable = true,
            2 => account.lamports += 1,
            3 => account.rent_epoch += 1,
            4 => account.data[0] ^= 1,
            5 => changed.observations[3].account = None,
            _ => unreachable!(),
        }
        mutations.push(changed);
    }
    for changed in mutations {
        assert_ne!(
            fingerprint_evidence_v1(&changed).unwrap(),
            fingerprint_evidence_v1(&snapshot).unwrap()
        );
    }
}

#[test]
fn preliminary_transcript_metadata_is_not_an_evidence_input() {
    let snapshot = golden_evidence_snapshot();
    let expected = fingerprint_evidence_v1(&snapshot).unwrap();
    let metadata_a = (
        [1u64, 2, 3],
        [100u64, 101, 102],
        [(31u64, 301u64), (21, 201), (11, 101)],
    );
    let metadata_b = (
        [91u64, 92, 93],
        [1u64, 1, 1],
        [(u64::MAX, 0u64), (0, u64::MAX), (7, 9)],
    );
    assert_ne!(metadata_a, metadata_b);
    assert_eq!(fingerprint_evidence_v1(&snapshot).unwrap(), expected);
}

#[test]
fn debug_and_errors_never_expose_rpc_or_account_material() {
    let account = observation(PROPOSAL, PROPOSAL_HEX, 3000, 30);
    let debug = format!("{account:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("Grant testing"));
    for error in [
        AuditError::InvalidJson,
        AuditError::Transport,
        AuditError::WrongOwner,
    ] {
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("https://"));
        assert!(!rendered.contains("91bd4499"));
        assert!(error.code().len() < 96);
    }
}

fn rewrite_slot(response: HttpResponse, slot: u64) -> HttpResponse {
    let mut value: Value = serde_json::from_slice(&response.body).unwrap();
    value["result"]["context"]["slot"] = json!(slot);
    HttpResponse {
        status: 200,
        body: serde_json::to_vec(&value).unwrap(),
    }
}

fn rewrite_owner(response: HttpResponse, owner: &str) -> HttpResponse {
    let mut value: Value = serde_json::from_slice(&response.body).unwrap();
    value["result"]["value"]["owner"] = json!(owner);
    HttpResponse {
        status: 200,
        body: serde_json::to_vec(&value).unwrap(),
    }
}

fn observation(address: &str, fixture: &str, lamports: u64, rent_epoch: u64) -> AccountObservation {
    AccountObservation {
        address: pubkey(address),
        owner: MAINNET_GOVERNANCE_PROGRAM,
        executable: false,
        lamports,
        rent_epoch,
        data: decode_hex(fixture),
    }
}

fn golden_evidence_snapshot() -> EvidenceSnapshot {
    EvidenceSnapshot {
        execution_fingerprint: Fingerprint([
            0x4f, 0xb6, 0x63, 0x82, 0x3e, 0x32, 0xd7, 0xab, 0xc5, 0x16, 0x2d, 0xdf, 0x0c, 0x29,
            0xcf, 0x23, 0x4e, 0x60, 0x43, 0x11, 0xe0, 0xa3, 0x16, 0xbd, 0xf0, 0x9a, 0x89, 0x2c,
            0xea, 0x51, 0x86, 0x91,
        ]),
        governance_program: MAINNET_GOVERNANCE_PROGRAM,
        authoritative_slot: 103,
        observations: vec![
            final_observation(ObservationRole::Proposal, PROPOSAL, PROPOSAL_HEX, 3000, 30),
            final_observation(
                ObservationRole::Governance,
                GOVERNANCE,
                GOVERNANCE_HEX,
                2000,
                20,
            ),
            final_observation(ObservationRole::Realm, REALM, REALM_HEX, 1000, 10),
            final_observation(
                ObservationRole::ProposalTransaction {
                    option_index: 0,
                    transaction_index: 0,
                },
                TRANSACTION_0,
                TRANSACTION_0_HEX,
                4000,
                40,
            ),
            final_observation(
                ObservationRole::ProposalTransaction {
                    option_index: 0,
                    transaction_index: 1,
                },
                TRANSACTION_1,
                TRANSACTION_1_HEX,
                5000,
                50,
            ),
        ],
    }
}

fn final_observation(
    role: ObservationRole,
    address: &str,
    fixture: &str,
    lamports: u64,
    rent_epoch: u64,
) -> FinalObservation {
    FinalObservation {
        role,
        address: pubkey(address),
        account: Some(observation(address, fixture, lamports, rent_epoch)),
    }
}

fn reference_evidence(snapshot: &EvidenceSnapshot) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(EVIDENCE_V1_DOMAIN);
    bytes.extend_from_slice(&snapshot.execution_fingerprint.0);
    bytes.extend_from_slice(snapshot.governance_program.as_bytes());
    bytes.push(1);
    bytes.extend_from_slice(&snapshot.authoritative_slot.to_le_bytes());
    bytes.extend_from_slice(
        &u16::try_from(snapshot.observations.len())
            .unwrap()
            .to_le_bytes(),
    );
    for observation in &snapshot.observations {
        match observation.role {
            ObservationRole::Proposal => bytes.push(1),
            ObservationRole::Governance => bytes.push(2),
            ObservationRole::Realm => bytes.push(3),
            ObservationRole::ProposalTransaction {
                option_index,
                transaction_index,
            } => {
                bytes.extend_from_slice(&[4, option_index]);
                bytes.extend_from_slice(&transaction_index.to_le_bytes());
            }
        }
        bytes.extend_from_slice(observation.address.as_bytes());
        match &observation.account {
            None => bytes.push(0),
            Some(account) => {
                bytes.push(1);
                bytes.extend_from_slice(account.owner.as_bytes());
                bytes.push(u8::from(account.executable));
                bytes.extend_from_slice(&account.lamports.to_le_bytes());
                bytes.extend_from_slice(&account.rent_epoch.to_le_bytes());
                bytes.extend_from_slice(&u32::try_from(account.data.len()).unwrap().to_le_bytes());
                bytes.extend_from_slice(&Sha256::digest(&account.data));
            }
        }
    }
    Sha256::digest(bytes).into()
}

fn hex(bytes: [u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
