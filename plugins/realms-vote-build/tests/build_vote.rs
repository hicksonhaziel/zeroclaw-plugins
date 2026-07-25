use std::collections::VecDeque;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use mandate_core::core::audit_error::AuditError;
use mandate_core::core::governance::pda::{
    derive_realm_config, derive_token_owner_record, derive_vote_record,
};
use mandate_core::core::pubkey::{Pubkey, MAINNET_GOVERNANCE_PROGRAM};
use mandate_core::core::rpc::{HttpResponse, RpcRequest, RpcTransport};
use mandate_core::core::vote::{VoteBuildError, VoteChoice};
use mandate_core::core::vote_service::VoteBuildRequest;
use realms_vote_build::execute_with_transport;
use serde_json::{json, Value};

const REALM: &str = "49STYcijF8oCwrUqM48sqWAoRL57p9KpXfHGvGiaRfDY";
const PROPOSAL: &str = "A35WTABGwuqJZkSEsSwrACCzXK2jPeT7jZRmbq4JR7dY";
const OWNER: &str = "GovER5Lthms3bLBqWub97yVrMmEogzX7xNjdXpPPCVZw";
const EXECUTION: [u8; 32] = [
    0x4f, 0xb6, 0x63, 0x82, 0x3e, 0x32, 0xd7, 0xab, 0xc5, 0x16, 0x2d, 0xdf, 0x0c, 0x29, 0xcf, 0x23,
    0x4e, 0x60, 0x43, 0x11, 0xe0, 0xa3, 0x16, 0xbd, 0xf0, 0x9a, 0x89, 0x2c, 0xea, 0x51, 0x86, 0x91,
];

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

fn key(value: u8) -> Pubkey {
    Pubkey::new([value; 32])
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .trim()
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn account(data: &[u8]) -> Value {
    json!({
        "data": [STANDARD.encode(data), "base64"],
        "executable": false,
        "lamports": 1,
        "owner": OWNER,
        "rentEpoch": 0,
        "space": data.len()
    })
}

fn context_envelope(id: u64, slot: u64, value: Value) -> HttpResponse {
    HttpResponse {
        status: 200,
        body: serde_json::to_vec(&json!({
            "jsonrpc":"2.0",
            "id":id,
            "result":{"context":{"slot":slot},"value":value}
        }))
        .unwrap(),
    }
}

fn scalar_envelope(id: u64, value: Value) -> HttpResponse {
    HttpResponse {
        status: 200,
        body: serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"result":value})).unwrap(),
    }
}

struct Fixture {
    proposal: Vec<u8>,
    governance: Vec<u8>,
    realm: Vec<u8>,
    transaction_0: Vec<u8>,
    transaction_1: Vec<u8>,
    voter_record: Pubkey,
    vote_record: Pubkey,
    realm_config: Pubkey,
    voter_data: Vec<u8>,
}

fn fixture(voting: bool) -> Fixture {
    let realm = pubkey(REALM);
    let mut proposal = decode_hex(PROPOSAL_HEX);
    let mut governance = decode_hex(GOVERNANCE_HEX);
    let governing_mint = Pubkey::new(proposal[33..65].try_into().unwrap());
    let voter = key(42);
    let (voter_record, _) =
        derive_token_owner_record(MAINNET_GOVERNANCE_PROGRAM, realm, governing_mint, voter)
            .unwrap();
    let (vote_record, _) =
        derive_vote_record(MAINNET_GOVERNANCE_PROGRAM, pubkey(PROPOSAL), voter_record).unwrap();
    let (realm_config, _) = derive_realm_config(MAINNET_GOVERNANCE_PROGRAM, realm).unwrap();
    if voting {
        proposal[65] = 2;
        proposal[66..98].copy_from_slice(voter_record.as_bytes());
        proposal[160] = 1;
        proposal[161..169].copy_from_slice(&1_000i64.to_le_bytes());
        governance[83..87].copy_from_slice(&1_000u32.to_le_bytes());
        governance[103..107].copy_from_slice(&0u32.to_le_bytes());
    }
    let mut voter_data = vec![17];
    voter_data.extend_from_slice(realm.as_bytes());
    voter_data.extend_from_slice(governing_mint.as_bytes());
    voter_data.extend_from_slice(voter.as_bytes());
    voter_data.extend_from_slice(&100u64.to_le_bytes());
    voter_data.extend_from_slice(&0u64.to_le_bytes());
    voter_data.push(0);
    voter_data.push(1);
    voter_data.extend_from_slice(&[0; 6]);
    voter_data.push(0);
    voter_data.extend_from_slice(&[0; 128]);
    voter_data.extend_from_slice(&[0; 32]);
    Fixture {
        proposal,
        governance,
        realm: decode_hex(REALM_HEX),
        transaction_0: decode_hex(TRANSACTION_0_HEX),
        transaction_1: decode_hex(TRANSACTION_1_HEX),
        voter_record,
        vote_record,
        realm_config,
        voter_data,
    }
}

fn responses(voting: bool, existing_vote: bool) -> Vec<HttpResponse> {
    let fixture = fixture(voting);
    let vote_value = if existing_vote {
        account(&[12; 82])
    } else {
        Value::Null
    };
    vec![
        context_envelope(1, 100, account(&fixture.proposal)),
        context_envelope(2, 101, account(&fixture.governance)),
        context_envelope(3, 102, account(&fixture.realm)),
        context_envelope(
            4,
            103,
            json!([
                account(&fixture.proposal),
                account(&fixture.governance),
                account(&fixture.realm),
                account(&fixture.transaction_0),
                account(&fixture.transaction_1)
            ]),
        ),
        context_envelope(
            5,
            104,
            json!([
                account(&fixture.proposal),
                account(&fixture.governance),
                account(&fixture.realm),
                account(&fixture.transaction_0),
                account(&fixture.transaction_1),
                account(&fixture.voter_data),
                vote_value,
                null
            ]),
        ),
        scalar_envelope(6, json!(1_500)),
        scalar_envelope(
            7,
            json!({
                "context":{"slot":105},
                "value":{
                    "blockhash":key(10).to_base58(),
                    "lastValidBlockHeight":999
                }
            }),
        ),
    ]
}

fn request(fingerprint: [u8; 32]) -> VoteBuildRequest {
    VoteBuildRequest {
        proposal: pubkey(PROPOSAL),
        governing_token_owner: key(42),
        governance_authority: key(42),
        payer: key(43),
        vote: VoteChoice::Deny,
        expected_execution_fingerprint: fingerprint,
    }
}

#[test]
fn mocked_end_to_end_build_uses_seven_bounded_read_calls() {
    let mut transport = MockTransport::new(responses(true, false));
    let built = execute_with_transport(request(EXECUTION), &mut transport).unwrap();
    assert_eq!(transport.requests.len(), 7);
    let methods = transport
        .requests
        .iter()
        .map(|request| {
            serde_json::from_slice::<Value>(&request.body).unwrap()["method"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        methods,
        [
            "getAccountInfo",
            "getAccountInfo",
            "getAccountInfo",
            "getMultipleAccounts",
            "getMultipleAccounts",
            "getBlockTime",
            "getLatestBlockhash"
        ]
    );
    assert!(!transport.requests.iter().any(|request| {
        let body = std::str::from_utf8(&request.body).unwrap();
        body.contains("getProgramAccounts")
            || body.contains("sendTransaction")
            || body.contains("simulateTransaction")
    }));
    assert_eq!(built.last_valid_block_height, 999);
    assert!(built.output.len() <= 4_096);
    let output: Value = serde_json::from_str(&built.output).unwrap();
    assert_eq!(output["status"], "ready_for_external_signing");
    assert_eq!(output["custody_tier"], "t1_unsigned");
    assert_eq!(output["vote"], "deny");
    assert_eq!(output["unsigned"], true);
    assert_eq!(output["submitted"], false);
    assert_eq!(output["proposal"], PROPOSAL);
    assert!(
        output["unsigned_transaction_base64"]
            .as_str()
            .unwrap()
            .len()
            > 100
    );
}

#[test]
fn fingerprint_mismatch_and_nonvoting_stop_before_blockhash() {
    let mut mismatch = MockTransport::new(responses(true, false));
    assert_eq!(
        execute_with_transport(request([0; 32]), &mut mismatch).unwrap_err(),
        VoteBuildError::FingerprintMismatch
    );
    assert_eq!(mismatch.requests.len(), 4);

    let mut nonvoting = MockTransport::new(responses(false, false));
    assert_eq!(
        execute_with_transport(request(EXECUTION), &mut nonvoting).unwrap_err(),
        VoteBuildError::ProposalNotVoting
    );
    assert_eq!(nonvoting.requests.len(), 4);
    for transport in [&mismatch, &nonvoting] {
        assert!(!transport.requests.iter().any(|request| {
            std::str::from_utf8(&request.body)
                .unwrap()
                .contains("getLatestBlockhash")
        }));
    }
}

#[test]
fn existing_vote_record_stops_before_time_and_blockhash() {
    let mut transport = MockTransport::new(responses(true, true));
    assert_eq!(
        execute_with_transport(request(EXECUTION), &mut transport).unwrap_err(),
        VoteBuildError::ExistingVoteRecord
    );
    assert_eq!(transport.requests.len(), 5);
}

#[test]
fn fixture_pdas_are_in_authoritative_validation_batch() {
    let fixture = fixture(true);
    let mut transport = MockTransport::new(responses(true, false));
    let _ = execute_with_transport(request(EXECUTION), &mut transport).unwrap();
    let batch: Value = serde_json::from_slice(&transport.requests[4].body).unwrap();
    let addresses = batch["params"][0].as_array().unwrap();
    for expected in [
        fixture.voter_record,
        fixture.vote_record,
        fixture.realm_config,
    ] {
        assert!(addresses
            .iter()
            .any(|value| value.as_str() == Some(&expected.to_base58())));
    }
}

#[test]
fn voter_owner_type_relationship_and_presence_fail_closed_before_blockhash() {
    for mutation in 0..4 {
        let mut set = responses(true, false);
        let mut envelope: Value = serde_json::from_slice(&set[4].body).unwrap();
        match mutation {
            0 => envelope["result"]["value"][5]["owner"] = json!(key(99).to_base58()),
            1 => {
                let encoded = envelope["result"]["value"][5]["data"][0].as_str().unwrap();
                let mut bytes = STANDARD.decode(encoded).unwrap();
                bytes[0] = 12;
                envelope["result"]["value"][5]["data"][0] = json!(STANDARD.encode(bytes));
            }
            2 => {
                let encoded = envelope["result"]["value"][5]["data"][0].as_str().unwrap();
                let mut bytes = STANDARD.decode(encoded).unwrap();
                bytes[1] ^= 1;
                envelope["result"]["value"][5]["data"][0] = json!(STANDARD.encode(bytes));
            }
            _ => envelope["result"]["value"][5] = Value::Null,
        }
        set[4].body = serde_json::to_vec(&envelope).unwrap();
        let mut transport = MockTransport::new(set);
        assert!(execute_with_transport(request(EXECUTION), &mut transport).is_err());
        assert_eq!(transport.requests.len(), 5);
    }
}

#[test]
fn expired_time_slot_regression_and_rpc_bounds_stop_before_blockhash() {
    let mut expired = responses(true, false);
    expired[5] = scalar_envelope(6, json!(300_000));
    let mut transport = MockTransport::new(expired);
    assert_eq!(
        execute_with_transport(request(EXECUTION), &mut transport).unwrap_err(),
        VoteBuildError::VotingExpired
    );
    assert_eq!(transport.requests.len(), 6);

    let mut regressed = responses(true, false);
    let mut body: Value = serde_json::from_slice(&regressed[4].body).unwrap();
    body["result"]["context"]["slot"] = json!(102);
    regressed[4].body = serde_json::to_vec(&body).unwrap();
    let mut transport = MockTransport::new(regressed);
    assert_eq!(
        execute_with_transport(request(EXECUTION), &mut transport).unwrap_err(),
        VoteBuildError::RpcFailed
    );
    assert_eq!(transport.requests.len(), 5);

    let mut oversized = responses(true, false);
    oversized[5].body = vec![b'x'; 513];
    let mut transport = MockTransport::new(oversized);
    assert_eq!(
        execute_with_transport(request(EXECUTION), &mut transport).unwrap_err(),
        VoteBuildError::RpcFailed
    );
    assert_eq!(transport.requests.len(), 6);
}
