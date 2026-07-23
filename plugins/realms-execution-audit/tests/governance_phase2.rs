use realms_execution_audit::core::account::{identify_account, AccountKind, AccountSnapshot};
use realms_execution_audit::core::execution::{
    fingerprint_v1, reconstruct_execution, ExecutionModel, FINGERPRINT_V1_DOMAIN,
};
use realms_execution_audit::core::governance::{
    parse_governance, parse_proposal, parse_proposal_transaction, parse_realm, GovernanceError,
};
use realms_execution_audit::core::limits::MAX_ACCOUNT_DATA_BYTES;
use realms_execution_audit::core::pubkey::{Pubkey, MAINNET_GOVERNANCE_PROGRAM};
use sha2::{Digest, Sha256};

const REALM_ADDRESS: &str = "49STYcijF8oCwrUqM48sqWAoRL57p9KpXfHGvGiaRfDY";
const GOVERNANCE_ADDRESS: &str = "5huMP3kiScHL2Lr4mFLo4BWDBzLCTvgnwaQ3YepjASLv";
const PROPOSAL_ADDRESS: &str = "A35WTABGwuqJZkSEsSwrACCzXK2jPeT7jZRmbq4JR7dY";
const TRANSACTION_0_ADDRESS: &str = "41MAfVcmwtGGzTP12xUaDo2w4grednxyXaDcvZcpnVMp";
const TRANSACTION_1_ADDRESS: &str = "76xgDiVSqaGC6pHH8ucQ8xuUYhQPibYUdWYum7emhEFd";

const REALM_HEX: &str = include_str!("fixtures/realm_v2.hex");
const GOVERNANCE_HEX: &str = include_str!("fixtures/mint_governance_v2.hex");
const PROPOSAL_HEX: &str = include_str!("fixtures/proposal_v2.hex");
const TRANSACTION_0_HEX: &str = include_str!("fixtures/proposal_transaction_0_v2.hex");
const TRANSACTION_1_HEX: &str = include_str!("fixtures/proposal_transaction_1_v2.hex");

fn decode_hex(value: &str) -> Vec<u8> {
    let value: String = value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

fn pubkey(value: &str) -> Pubkey {
    let bytes = bs58::decode(value).into_vec().unwrap();
    Pubkey::new(bytes.try_into().unwrap())
}

fn snapshot<'a>(address: &str, data: &'a [u8]) -> AccountSnapshot<'a> {
    AccountSnapshot {
        address: pubkey(address),
        owner: MAINNET_GOVERNANCE_PROGRAM,
        data,
    }
}

fn parsed_chain() -> (
    realms_execution_audit::core::governance::RealmAccount,
    realms_execution_audit::core::governance::GovernanceAccount,
    realms_execution_audit::core::governance::ProposalAccount,
    Vec<realms_execution_audit::core::governance::ProposalTransactionAccount>,
) {
    let realm_bytes = decode_hex(REALM_HEX);
    let governance_bytes = decode_hex(GOVERNANCE_HEX);
    let proposal_bytes = decode_hex(PROPOSAL_HEX);
    let transaction_0_bytes = decode_hex(TRANSACTION_0_HEX);
    let transaction_1_bytes = decode_hex(TRANSACTION_1_HEX);
    (
        parse_realm(&snapshot(REALM_ADDRESS, &realm_bytes)).unwrap(),
        parse_governance(&snapshot(GOVERNANCE_ADDRESS, &governance_bytes)).unwrap(),
        parse_proposal(&snapshot(PROPOSAL_ADDRESS, &proposal_bytes)).unwrap(),
        vec![
            parse_proposal_transaction(&snapshot(TRANSACTION_0_ADDRESS, &transaction_0_bytes))
                .unwrap(),
            parse_proposal_transaction(&snapshot(TRANSACTION_1_ADDRESS, &transaction_1_bytes))
                .unwrap(),
        ],
    )
}

fn model() -> ExecutionModel {
    let (realm, governance, proposal, transactions) = parsed_chain();
    reconstruct_execution(&realm, &governance, &proposal, transactions).unwrap()
}

fn mutate_pubkey(value: Pubkey) -> Pubkey {
    let mut bytes = *value.as_bytes();
    bytes[0] ^= 1;
    Pubkey::new(bytes)
}

#[test]
fn fixture_hashes_are_frozen_before_parsing() {
    for (fixture, expected_len, expected_hash) in [
        (
            REALM_HEX,
            294,
            "04e8cc52d5fbfc49d5ac2846824da5202e3afb4f5b3df32e9dd84c0b69af9636",
        ),
        (
            GOVERNANCE_HEX,
            236,
            "b0cdd8866c3eb1e0b72cc70658120080508af2bc1cb00ffa058fc11fda070dd4",
        ),
        (
            PROPOSAL_HEX,
            366,
            "7ee4626687f32d5f844641d3832e0828ee274e7614a8b99bbe4f0148859b3a0a",
        ),
        (
            TRANSACTION_0_HEX,
            611,
            "8e42780017b7e7f61be68b8a2ff2dac36c46d77abe3fbea6288a4590af90418a",
        ),
        (
            TRANSACTION_1_HEX,
            611,
            "5f230aa5479652da92d4d24c3e508d097f6c702002c695c6de5a67562b07447e",
        ),
    ] {
        let bytes = decode_hex(fixture);
        assert_eq!(bytes.len(), expected_len);
        assert_eq!(format!("{:x}", Sha256::digest(bytes)), expected_hash);
    }
}

#[test]
fn valid_realm_v2_fixture_parses() {
    let bytes = decode_hex(REALM_HEX);
    assert_eq!(
        identify_account(&snapshot(REALM_ADDRESS, &bytes)).unwrap(),
        AccountKind::RealmV2
    );
    assert_eq!(
        parse_realm(&snapshot(REALM_ADDRESS, &bytes))
            .unwrap()
            .address,
        pubkey(REALM_ADDRESS)
    );
}

#[test]
fn valid_mint_governance_v2_fixture_parses() {
    let bytes = decode_hex(GOVERNANCE_HEX);
    let governance = parse_governance(&snapshot(GOVERNANCE_ADDRESS, &bytes)).unwrap();
    assert_eq!(governance.realm, pubkey(REALM_ADDRESS));
}

#[test]
fn valid_proposal_v2_fixture_parses() {
    let bytes = decode_hex(PROPOSAL_HEX);
    let proposal = parse_proposal(&snapshot(PROPOSAL_ADDRESS, &bytes)).unwrap();
    assert_eq!(proposal.governance, pubkey(GOVERNANCE_ADDRESS));
    assert_eq!(proposal.options[0].transactions_count, 2);
}

#[test]
fn both_valid_proposal_transaction_v2_fixtures_parse() {
    let first = decode_hex(TRANSACTION_0_HEX);
    let second = decode_hex(TRANSACTION_1_HEX);
    let first = parse_proposal_transaction(&snapshot(TRANSACTION_0_ADDRESS, &first)).unwrap();
    let second = parse_proposal_transaction(&snapshot(TRANSACTION_1_ADDRESS, &second)).unwrap();
    assert_eq!((first.option_index, first.transaction_index), (0, 0));
    assert_eq!((second.option_index, second.transaction_index), (0, 1));
    assert_eq!(first.instructions.len(), 1);
    assert_eq!(first.instructions[0].accounts.len(), 14);
}

#[test]
fn wrong_program_owner_fails_closed() {
    let bytes = decode_hex(REALM_HEX);
    let input = AccountSnapshot {
        address: pubkey(REALM_ADDRESS),
        owner: Pubkey::new([7; 32]),
        data: &bytes,
    };
    assert_eq!(
        parse_realm(&input).unwrap_err(),
        GovernanceError::WrongProgramOwner
    );
}

#[test]
fn wrong_discriminator_and_legacy_or_future_versions_fail_closed() {
    let original = decode_hex(REALM_HEX);
    for (discriminator, expected) in [
        (20, GovernanceError::UnsupportedAccountType),
        (1, GovernanceError::UnsupportedAccountVersion),
        (255, GovernanceError::UnsupportedAccountType),
    ] {
        let mut bytes = original.clone();
        bytes[0] = discriminator;
        assert_eq!(
            parse_realm(&snapshot(REALM_ADDRESS, &bytes)).unwrap_err(),
            expected
        );
    }
}

#[test]
fn every_fixture_truncation_boundary_fails_without_panic() {
    type RejectsFixture = fn(&AccountSnapshot<'_>) -> bool;
    let cases: [(&str, &str, RejectsFixture); 5] = [
        (REALM_ADDRESS, REALM_HEX, |input| {
            parse_realm(input).is_err()
        }),
        (GOVERNANCE_ADDRESS, GOVERNANCE_HEX, |input| {
            parse_governance(input).is_err()
        }),
        (PROPOSAL_ADDRESS, PROPOSAL_HEX, |input| {
            parse_proposal(input).is_err()
        }),
        (TRANSACTION_0_ADDRESS, TRANSACTION_0_HEX, |input| {
            parse_proposal_transaction(input).is_err()
        }),
        (TRANSACTION_1_ADDRESS, TRANSACTION_1_HEX, |input| {
            parse_proposal_transaction(input).is_err()
        }),
    ];
    for (address, fixture, parser_rejected) in cases {
        let bytes = decode_hex(fixture);
        for end in 0..bytes.len() {
            assert!(parser_rejected(&snapshot(address, &bytes[..end])));
        }
    }
}

#[test]
fn malicious_string_vector_and_count_prefixes_fail_before_allocation() {
    let mut proposal = decode_hex(PROPOSAL_HEX);
    proposal[101..105].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        parse_proposal(&snapshot(PROPOSAL_ADDRESS, &proposal)).unwrap_err(),
        GovernanceError::CountTooLarge
    );

    let mut label = decode_hex(PROPOSAL_HEX);
    label[105..109].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        parse_proposal(&snapshot(PROPOSAL_ADDRESS, &label)).unwrap_err(),
        GovernanceError::CountTooLarge
    );

    let mut transaction = decode_hex(TRANSACTION_0_HEX);
    transaction[40..44].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        parse_proposal_transaction(&snapshot(TRANSACTION_0_ADDRESS, &transaction)).unwrap_err(),
        GovernanceError::CountTooLarge
    );

    let mut accounts = decode_hex(TRANSACTION_0_HEX);
    accounts[76..80].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        parse_proposal_transaction(&snapshot(TRANSACTION_0_ADDRESS, &accounts)).unwrap_err(),
        GovernanceError::CountTooLarge
    );

    let mut instruction_data = decode_hex(TRANSACTION_0_HEX);
    instruction_data[556..560].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        parse_proposal_transaction(&snapshot(TRANSACTION_0_ADDRESS, &instruction_data))
            .unwrap_err(),
        GovernanceError::CountTooLarge
    );
}

#[test]
fn parsed_instruction_preserves_program_metas_flags_and_exact_data() {
    let (_, _, _, transactions) = parsed_chain();
    let instruction = &transactions[0].instructions[0];
    assert_eq!(instruction.accounts.len(), 14);
    assert!(instruction.accounts.iter().any(|meta| meta.is_writable));
    assert!(instruction.accounts.iter().any(|meta| meta.is_signer));
    assert_eq!(
        instruction.data,
        decode_hex("91bd4499a1e74c6bfdff0101805d32650000000001000000010500000000000000")
    );
}

#[test]
fn unexpected_padding_or_trailing_data_fails_closed() {
    let mut proposal = decode_hex(PROPOSAL_HEX);
    *proposal.last_mut().unwrap() = 1;
    assert_eq!(
        parse_proposal(&snapshot(PROPOSAL_ADDRESS, &proposal)).unwrap_err(),
        GovernanceError::UnsupportedAccountVersion
    );
    proposal.push(0);
    assert!(parse_proposal(&snapshot(PROPOSAL_ADDRESS, &proposal)).is_err());
}

#[test]
fn account_data_over_cap_fails_closed() {
    let bytes = vec![16; MAX_ACCOUNT_DATA_BYTES + 1];
    assert_eq!(
        parse_realm(&snapshot(REALM_ADDRESS, &bytes)).unwrap_err(),
        GovernanceError::AccountDataTooLarge
    );
}

#[test]
fn total_executable_bytes_across_transactions_are_bounded() {
    let (realm, governance, proposal, mut transactions) = parsed_chain();
    transactions[0].instructions[0].data = vec![1; 5_000];
    transactions[1].instructions[0].data = vec![2; 5_000];
    assert_eq!(
        reconstruct_execution(&realm, &governance, &proposal, transactions).unwrap_err(),
        GovernanceError::TotalExecutableBytesTooLarge
    );
}

#[test]
fn executed_count_and_status_mismatch_fails() {
    let (realm, governance, proposal, mut transactions) = parsed_chain();
    transactions[0].execution_status = 0;
    assert_eq!(
        reconstruct_execution(&realm, &governance, &proposal, transactions).unwrap_err(),
        GovernanceError::DeclaredTransactionCountMismatch
    );
}

#[test]
fn wrong_realm_governance_relationship_fails() {
    let (realm, mut governance, proposal, transactions) = parsed_chain();
    governance.realm = mutate_pubkey(governance.realm);
    assert_eq!(
        reconstruct_execution(&realm, &governance, &proposal, transactions).unwrap_err(),
        GovernanceError::WrongRealmRelationship
    );
}

#[test]
fn wrong_governance_proposal_relationship_fails() {
    let (realm, governance, mut proposal, transactions) = parsed_chain();
    proposal.governance = mutate_pubkey(proposal.governance);
    assert_eq!(
        reconstruct_execution(&realm, &governance, &proposal, transactions).unwrap_err(),
        GovernanceError::WrongGovernanceRelationship
    );
}

#[test]
fn unrelated_proposal_transaction_relationship_fails() {
    let (realm, governance, proposal, mut transactions) = parsed_chain();
    transactions[0].proposal = mutate_pubkey(transactions[0].proposal);
    assert_eq!(
        reconstruct_execution(&realm, &governance, &proposal, transactions).unwrap_err(),
        GovernanceError::WrongProposalRelationship
    );
}

#[test]
fn duplicate_transaction_index_fails() {
    let (realm, governance, proposal, mut transactions) = parsed_chain();
    transactions[1].transaction_index = 0;
    assert_eq!(
        reconstruct_execution(&realm, &governance, &proposal, transactions).unwrap_err(),
        GovernanceError::DuplicateTransactionIndex
    );
}

#[test]
fn surviving_account_count_mismatch_fails() {
    let (realm, governance, proposal, mut transactions) = parsed_chain();
    transactions.pop();
    assert!(reconstruct_execution(&realm, &governance, &proposal, transactions).is_err());
}

#[test]
fn canonical_removed_transaction_gap_is_valid_and_ordered() {
    let (realm, governance, mut proposal, mut transactions) = parsed_chain();
    proposal.options[0].transactions_next_index = 3;
    transactions[1].transaction_index = 2;
    let execution = reconstruct_execution(&realm, &governance, &proposal, transactions).unwrap();
    let indices = execution.options[0]
        .transactions
        .iter()
        .map(|transaction| transaction.transaction_index)
        .collect::<Vec<_>>();
    assert_eq!(indices, vec![0, 2]);
}

#[test]
fn transaction_index_at_or_above_next_index_fails() {
    let (realm, governance, proposal, mut transactions) = parsed_chain();
    transactions[1].transaction_index = 2;
    assert_eq!(
        reconstruct_execution(&realm, &governance, &proposal, transactions).unwrap_err(),
        GovernanceError::TransactionIndexOutOfRange
    );
}

#[test]
fn out_of_range_option_index_fails() {
    let (realm, governance, proposal, mut transactions) = parsed_chain();
    transactions[0].option_index = 1;
    assert_eq!(
        reconstruct_execution(&realm, &governance, &proposal, transactions).unwrap_err(),
        GovernanceError::OutOfRangeOptionIndex
    );
}

#[test]
fn declared_transaction_count_mismatch_fails() {
    let (realm, governance, mut proposal, transactions) = parsed_chain();
    proposal.options[0].transactions_count = 1;
    proposal.options[0].transactions_next_index = 1;
    assert_eq!(
        reconstruct_execution(&realm, &governance, &proposal, transactions).unwrap_err(),
        GovernanceError::DeclaredTransactionCountMismatch
    );
}

#[test]
fn shuffled_input_collection_reconstructs_identically() {
    let (realm, governance, proposal, transactions) = parsed_chain();
    let expected =
        reconstruct_execution(&realm, &governance, &proposal, transactions.clone()).unwrap();
    let shuffled = reconstruct_execution(
        &realm,
        &governance,
        &proposal,
        transactions.into_iter().rev().collect(),
    )
    .unwrap();
    assert_eq!(expected, shuffled);
}

#[test]
fn reordered_execution_changes_fingerprint() {
    let baseline = model();
    let mut changed = baseline.clone();
    let transactions = &mut changed.options[0].transactions;
    let (left, right) = transactions.split_at_mut(1);
    std::mem::swap(&mut left[0].instructions, &mut right[0].instructions);
    assert_ne!(
        fingerprint_v1(&baseline).unwrap(),
        fingerprint_v1(&changed).unwrap()
    );
}

#[test]
fn program_id_mutation_changes_fingerprint() {
    let baseline = model();
    let mut changed = baseline.clone();
    changed.options[0].transactions[0].instructions[0].program_id =
        mutate_pubkey(changed.options[0].transactions[0].instructions[0].program_id);
    assert_ne!(
        fingerprint_v1(&baseline).unwrap(),
        fingerprint_v1(&changed).unwrap()
    );
}

#[test]
fn account_pubkey_mutation_changes_fingerprint() {
    let baseline = model();
    let mut changed = baseline.clone();
    let meta = &mut changed.options[0].transactions[0].instructions[0].accounts[0];
    meta.pubkey = mutate_pubkey(meta.pubkey);
    assert_ne!(
        fingerprint_v1(&baseline).unwrap(),
        fingerprint_v1(&changed).unwrap()
    );
}

#[test]
fn signer_and_writable_mutations_change_fingerprint() {
    let baseline = model();
    let mut signer = baseline.clone();
    signer.options[0].transactions[0].instructions[0].accounts[0].is_signer ^= true;
    let mut writable = baseline.clone();
    writable.options[0].transactions[0].instructions[0].accounts[0].is_writable ^= true;
    assert_ne!(
        fingerprint_v1(&baseline).unwrap(),
        fingerprint_v1(&signer).unwrap()
    );
    assert_ne!(
        fingerprint_v1(&baseline).unwrap(),
        fingerprint_v1(&writable).unwrap()
    );
}

#[test]
fn instruction_data_mutation_changes_fingerprint() {
    let baseline = model();
    let mut changed = baseline.clone();
    changed.options[0].transactions[0].instructions[0].data[0] ^= 1;
    assert_ne!(
        fingerprint_v1(&baseline).unwrap(),
        fingerprint_v1(&changed).unwrap()
    );
}

#[test]
fn realm_governance_and_proposal_identity_mutations_change_fingerprint() {
    let baseline = model();
    for changed in [
        ExecutionModel {
            realm: mutate_pubkey(baseline.realm),
            ..baseline.clone()
        },
        ExecutionModel {
            governance: mutate_pubkey(baseline.governance),
            ..baseline.clone()
        },
        ExecutionModel {
            proposal: mutate_pubkey(baseline.proposal),
            ..baseline.clone()
        },
    ] {
        assert_ne!(
            fingerprint_v1(&baseline).unwrap(),
            fingerprint_v1(&changed).unwrap()
        );
    }
}

#[test]
fn governing_mint_transaction_address_and_hold_up_mutations_change_fingerprint() {
    let baseline = model();
    let mut mint = baseline.clone();
    mint.governing_token_mint = mutate_pubkey(mint.governing_token_mint);
    let mut address = baseline.clone();
    address.options[0].transactions[0].address =
        mutate_pubkey(address.options[0].transactions[0].address);
    let mut hold_up = baseline.clone();
    hold_up.options[0].transactions[0].hold_up_time ^= 1;
    for changed in [mint, address, hold_up] {
        assert_ne!(
            fingerprint_v1(&baseline).unwrap(),
            fingerprint_v1(&changed).unwrap()
        );
    }
}

#[test]
fn execution_flags_mutation_changes_fingerprint() {
    let baseline = model();
    let mut changed = baseline.clone();
    changed.execution_flags ^= 1;
    assert_ne!(
        fingerprint_v1(&baseline).unwrap(),
        fingerprint_v1(&changed).unwrap()
    );
}

#[test]
fn proposal_state_does_not_change_execution_fingerprint() {
    let baseline = model();
    let mut changed = baseline.clone();
    changed.proposal_state = changed.proposal_state.wrapping_add(1);
    assert_eq!(
        fingerprint_v1(&baseline).unwrap(),
        fingerprint_v1(&changed).unwrap()
    );
}

#[test]
fn executed_count_does_not_change_execution_fingerprint() {
    let baseline = model();
    let mut changed = baseline.clone();
    changed.options[0].transactions_executed_count ^= 1;
    assert_eq!(
        fingerprint_v1(&baseline).unwrap(),
        fingerprint_v1(&changed).unwrap()
    );
}

#[test]
fn executed_at_and_execution_status_do_not_change_execution_fingerprint() {
    let baseline = model();
    let mut executed_at = baseline.clone();
    executed_at.options[0].transactions[0].executed_at = None;
    let mut status = baseline.clone();
    status.options[0].transactions[0].execution_status ^= 1;
    assert_eq!(
        fingerprint_v1(&baseline).unwrap(),
        fingerprint_v1(&executed_at).unwrap()
    );
    assert_eq!(
        fingerprint_v1(&baseline).unwrap(),
        fingerprint_v1(&status).unwrap()
    );
}

#[test]
fn identical_executable_content_is_stable_across_runs() {
    let model = model();
    let expected = fingerprint_v1(&model).unwrap();
    for _ in 0..32 {
        assert_eq!(fingerprint_v1(&model).unwrap(), expected);
    }
}

#[test]
fn proposal_display_text_mutation_does_not_change_fingerprint() {
    let baseline = model();
    let (realm, governance, _proposal, transactions) = parsed_chain();
    let mut bytes = decode_hex(PROPOSAL_HEX);
    let needle = b"Grant testing #8";
    let offset = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .unwrap();
    bytes[offset..offset + needle.len()].copy_from_slice(b"Untrusted text!!");
    let proposal = parse_proposal(&snapshot(PROPOSAL_ADDRESS, &bytes)).unwrap();
    let changed = reconstruct_execution(&realm, &governance, &proposal, transactions).unwrap();
    assert_eq!(
        fingerprint_v1(&baseline).unwrap(),
        fingerprint_v1(&changed).unwrap()
    );
}

#[test]
fn fingerprint_matches_frozen_literal_golden_vector() {
    let execution = model();
    let expected = [
        0x4f, 0xb6, 0x63, 0x82, 0x3e, 0x32, 0xd7, 0xab, 0xc5, 0x16, 0x2d, 0xdf, 0x0c, 0x29, 0xcf,
        0x23, 0x4e, 0x60, 0x43, 0x11, 0xe0, 0xa3, 0x16, 0xbd, 0xf0, 0x9a, 0x89, 0x2c, 0xea, 0x51,
        0x86, 0x91,
    ];
    assert_eq!(reference_fingerprint_v1(&execution), expected);
    assert_eq!(fingerprint_v1(&execution).unwrap().0, expected);
}

/// Independent test-only construction of the documented v1 preimage. Unlike
/// the production encoder, this materializes the complete byte vector before
/// hashing, so the literal golden is checked by two separate implementations.
fn reference_fingerprint_v1(model: &ExecutionModel) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(FINGERPRINT_V1_DOMAIN);
    bytes.extend_from_slice(model.realm.as_bytes());
    bytes.extend_from_slice(model.governance.as_bytes());
    bytes.extend_from_slice(model.proposal.as_bytes());
    bytes.extend_from_slice(model.governing_token_mint.as_bytes());
    bytes.push(model.execution_flags);
    bytes.extend_from_slice(&u16::try_from(model.options.len()).unwrap().to_le_bytes());
    for option in &model.options {
        bytes.push(option.option_index);
        bytes.extend_from_slice(
            &u16::try_from(option.transactions.len())
                .unwrap()
                .to_le_bytes(),
        );
        for transaction in &option.transactions {
            bytes.extend_from_slice(transaction.address.as_bytes());
            bytes.extend_from_slice(&transaction.transaction_index.to_le_bytes());
            bytes.extend_from_slice(&transaction.hold_up_time.to_le_bytes());
            bytes.extend_from_slice(
                &u16::try_from(transaction.instructions.len())
                    .unwrap()
                    .to_le_bytes(),
            );
            for instruction in &transaction.instructions {
                bytes.extend_from_slice(instruction.program_id.as_bytes());
                bytes.extend_from_slice(
                    &u16::try_from(instruction.accounts.len())
                        .unwrap()
                        .to_le_bytes(),
                );
                for account in &instruction.accounts {
                    bytes.extend_from_slice(account.pubkey.as_bytes());
                    bytes.push(u8::from(account.is_signer));
                    bytes.push(u8::from(account.is_writable));
                }
                bytes.extend_from_slice(
                    &u32::try_from(instruction.data.len()).unwrap().to_le_bytes(),
                );
                bytes.extend_from_slice(&instruction.data);
            }
        }
    }
    Sha256::digest(bytes).into()
}

#[test]
fn errors_and_debug_do_not_leak_raw_account_or_discarded_text() {
    let bytes = decode_hex(PROPOSAL_HEX);
    let input = snapshot(PROPOSAL_ADDRESS, &bytes);
    let input_debug = format!("{input:?}");
    assert!(input_debug.contains("<redacted>"));
    assert!(!input_debug.contains("Grant testing #8"));
    assert!(!input_debug.contains(&hex_prefix(&bytes)));

    let mut malformed = bytes;
    malformed[0] = 255;
    let error = parse_proposal(&snapshot(PROPOSAL_ADDRESS, &malformed)).unwrap_err();
    let error_debug = format!("{error:?}");
    assert!(!error_debug.contains("Grant testing #8"));
    assert!(!error_debug.contains(&hex_prefix(&malformed)));

    let transaction = parse_proposal_transaction(&snapshot(
        TRANSACTION_0_ADDRESS,
        &decode_hex(TRANSACTION_0_HEX),
    ))
    .unwrap();
    let instruction_bytes = format!("{:?}", transaction.instructions[0].data);
    let transaction_debug = format!("{transaction:?}");
    assert!(transaction_debug.contains("<redacted>"));
    assert!(!transaction_debug.contains(&instruction_bytes));
}

fn hex_prefix(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
