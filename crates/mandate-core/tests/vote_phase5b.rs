use mandate_core::core::account::AccountSnapshot;
use mandate_core::core::governance::pda::{
    derive_realm_config, derive_token_owner_record, derive_vote_record,
};
use mandate_core::core::policy::{AnalysisStatus, RiskLevel};
use mandate_core::core::pubkey::{Pubkey, MAINNET_GOVERNANCE_PROGRAM};
use mandate_core::core::vote::{
    build_unsigned_transaction, enforce_vote_policy, parse_expected_fingerprint,
    parse_token_owner_record, parse_vote_record, validate_authority, validate_voting_state,
    CastVotePlan, TokenOwnerRecord, VoteBuildError, VoteChoice,
};
use sha2::{Digest, Sha256};

fn key(value: u8) -> Pubkey {
    Pubkey::new([value; 32])
}

fn token_owner_bytes(delegate: Option<Pubkey>) -> Vec<u8> {
    let mut data = vec![17];
    data.extend_from_slice(key(2).as_bytes());
    data.extend_from_slice(key(3).as_bytes());
    data.extend_from_slice(key(4).as_bytes());
    data.extend_from_slice(&100u64.to_le_bytes());
    data.extend_from_slice(&2u64.to_le_bytes());
    data.push(1);
    data.push(1);
    data.extend_from_slice(&[0; 6]);
    match delegate {
        None => data.push(0),
        Some(value) => {
            data.push(1);
            data.extend_from_slice(value.as_bytes());
        }
    }
    data.extend_from_slice(&[0; 128]);
    if delegate.is_none() {
        data.extend_from_slice(&[0; 32]);
    }
    data
}

fn vote_record_bytes() -> Vec<u8> {
    let mut data = vec![12];
    data.extend_from_slice(key(5).as_bytes());
    data.extend_from_slice(key(4).as_bytes());
    data.push(0);
    data.extend_from_slice(&100u64.to_le_bytes());
    data.push(1);
    data.extend_from_slice(&[0; 8]);
    data
}

fn snapshot<'a>(address: Pubkey, data: &'a [u8]) -> AccountSnapshot<'a> {
    AccountSnapshot {
        address,
        owner: MAINNET_GOVERNANCE_PROGRAM,
        data,
    }
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .trim()
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn canonical_token_owner_record_and_vote_record_parse() {
    let token_bytes = token_owner_bytes(Some(key(9)));
    let token = parse_token_owner_record(&snapshot(key(8), &token_bytes)).unwrap();
    assert_eq!(token.realm, key(2));
    assert_eq!(token.governing_token_mint, key(3));
    assert_eq!(token.governing_token_owner, key(4));
    assert_eq!(token.governance_delegate, Some(key(9)));
    assert_eq!(validate_authority(&token, key(4)), Ok(()));
    assert_eq!(validate_authority(&token, key(9)), Ok(()));
    assert_eq!(
        validate_authority(&token, key(10)),
        Err(VoteBuildError::InvalidAuthority)
    );

    let vote_bytes = vote_record_bytes();
    let vote = parse_vote_record(&snapshot(key(7), &vote_bytes)).unwrap();
    assert_eq!(vote.proposal, key(5));
    assert_eq!(vote.governing_token_owner, key(4));
    assert!(!vote.is_relinquished);
}

#[test]
fn public_vote_fixtures_match_provenance_hashes_and_relationships() {
    let token_bytes = decode_hex(include_str!("fixtures/token_owner_record_v2.hex"));
    let vote_bytes = decode_hex(include_str!("fixtures/vote_record_v2.hex"));
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(&token_bytes)),
        [
            0xbf, 0x28, 0x3f, 0x6c, 0x6e, 0xab, 0x65, 0x10, 0x74, 0x59, 0xc9, 0x91, 0x43, 0xdd,
            0xb2, 0x1c, 0xca, 0x50, 0xad, 0x84, 0x17, 0x68, 0x8a, 0xe0, 0x0b, 0xc2, 0x03, 0xb1,
            0x84, 0x0b, 0x25, 0x49,
        ]
    );
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(&vote_bytes)),
        [
            0xe6, 0xdb, 0xc7, 0x85, 0xdd, 0xaa, 0x93, 0xe9, 0xeb, 0x97, 0xba, 0x0e, 0xc4, 0xca,
            0x90, 0x89, 0x00, 0xb0, 0x4a, 0x80, 0x77, 0x6c, 0x1f, 0x66, 0x24, 0x3d, 0x58, 0x62,
            0xd5, 0xe8, 0x00, 0xc1,
        ]
    );
    let token_address =
        Pubkey::from_base58("BYx2rMfnHHbPZ1SJTBTv1HKgWUPUtm7HXWNbqqn6b61o").unwrap();
    let vote_address = Pubkey::from_base58("jhFhkxrLapCqi4CUUr6DEa9QDTdeNG2RXDCt9fyeJAe").unwrap();
    let token = parse_token_owner_record(&snapshot(token_address, &token_bytes)).unwrap();
    let vote = parse_vote_record(&snapshot(vote_address, &vote_bytes)).unwrap();
    assert_eq!(
        token.realm.to_base58(),
        "49STYcijF8oCwrUqM48sqWAoRL57p9KpXfHGvGiaRfDY"
    );
    assert_eq!(
        vote.proposal.to_base58(),
        "A35WTABGwuqJZkSEsSwrACCzXK2jPeT7jZRmbq4JR7dY"
    );
    assert_eq!(vote.governing_token_owner, token.governing_token_owner);
}

#[test]
fn account_truncation_wrong_owner_type_and_version_fail_closed() {
    let original = token_owner_bytes(None);
    for length in 0..original.len() {
        assert!(parse_token_owner_record(&snapshot(key(8), &original[..length])).is_err());
    }
    let mut wrong_type = original.clone();
    wrong_type[0] = 2;
    assert!(parse_token_owner_record(&snapshot(key(8), &wrong_type)).is_err());
    let mut wrong_version = original.clone();
    wrong_version[123] = 2;
    assert!(parse_token_owner_record(&snapshot(key(8), &wrong_version)).is_err());
    let wrong_owner = AccountSnapshot {
        address: key(8),
        owner: key(99),
        data: &original,
    };
    assert!(parse_token_owner_record(&wrong_owner).is_err());

    let vote = vote_record_bytes();
    for length in 0..vote.len() {
        assert!(parse_vote_record(&snapshot(key(7), &vote[..length])).is_err());
    }
}

#[test]
fn pda_derivations_are_stable_and_domain_separated() {
    let (token_owner, token_bump) =
        derive_token_owner_record(MAINNET_GOVERNANCE_PROGRAM, key(2), key(3), key(4)).unwrap();
    let (vote_record, vote_bump) =
        derive_vote_record(MAINNET_GOVERNANCE_PROGRAM, key(5), token_owner).unwrap();
    let (realm_config, realm_bump) =
        derive_realm_config(MAINNET_GOVERNANCE_PROGRAM, key(2)).unwrap();
    assert_eq!(token_bump, 255);
    assert_eq!(vote_bump, 252);
    assert_eq!(realm_bump, 253);
    assert_ne!(token_owner, vote_record);
    assert_ne!(vote_record, realm_config);
    assert_eq!(
        derive_token_owner_record(MAINNET_GOVERNANCE_PROGRAM, key(2), key(3), key(4))
            .unwrap()
            .0,
        token_owner
    );
}

#[test]
fn policy_is_independent_and_approve_fails_closed() {
    assert_eq!(
        enforce_vote_policy(VoteChoice::Deny, true, AnalysisStatus::Unresolved, None),
        Ok(())
    );
    for (complete, status, risk) in [
        (false, AnalysisStatus::Complete, Some(RiskLevel::Low)),
        (true, AnalysisStatus::Unresolved, Some(RiskLevel::Low)),
        (true, AnalysisStatus::Complete, Some(RiskLevel::Critical)),
    ] {
        assert_eq!(
            enforce_vote_policy(VoteChoice::Approve, complete, status, risk),
            Err(VoteBuildError::PolicyBlocked)
        );
    }
    assert_eq!(
        enforce_vote_policy(
            VoteChoice::Approve,
            true,
            AnalysisStatus::Complete,
            Some(RiskLevel::Low)
        ),
        Err(VoteBuildError::UnsupportedVote)
    );
}

#[test]
fn strict_fingerprint_and_voting_deadline_validation() {
    let parsed = parse_expected_fingerprint(&format!("sha256:{}", "ab".repeat(32))).unwrap();
    assert_eq!(parsed, [0xab; 32]);
    for value in [
        "",
        "ab",
        "sha256:AB",
        "sha256:00",
        &format!("sha256:{}", "g0".repeat(32)),
    ] {
        assert_eq!(
            parse_expected_fingerprint(value),
            Err(VoteBuildError::MalformedFingerprint)
        );
    }

    let proposal = mandate_core::core::governance::ProposalAccount {
        address: key(1),
        governance: key(2),
        governing_token_mint: key(3),
        token_owner_record: key(4),
        state: 2,
        voting_at: Some(100),
        options: Vec::new(),
        execution_flags: 0,
    };
    assert_eq!(validate_voting_state(&proposal, 10, 5, 115), Ok(115));
    assert_eq!(
        validate_voting_state(&proposal, 10, 5, 116),
        Err(VoteBuildError::VotingExpired)
    );
}

fn plan(authority: Pubkey, payer: Pubkey) -> CastVotePlan {
    let (realm_config, _) = derive_realm_config(key(1), key(2)).unwrap();
    CastVotePlan {
        governance_program: key(1),
        realm: key(2),
        governance: key(3),
        proposal: key(4),
        proposal_owner_record: key(5),
        voter_token_owner_record: key(6),
        governance_authority: authority,
        vote_record: derive_vote_record(key(1), key(4), key(6)).unwrap().0,
        governing_token_mint: key(8),
        payer,
        realm_config,
        vote: VoteChoice::Deny,
    }
}

#[test]
fn canonical_deny_transaction_is_unsigned_deterministic_and_single_instruction() {
    let transaction = build_unsigned_transaction(plan(key(7), key(9)), [10; 32]).unwrap();
    let repeated = build_unsigned_transaction(plan(key(7), key(9)), [10; 32]).unwrap();
    assert_eq!(transaction, repeated);
    assert_eq!(transaction.required_signers, vec![key(9), key(7)]);
    assert_eq!(transaction.bytes[0], 2);
    assert!(transaction.bytes[1..129].iter().all(|byte| *byte == 0));
    assert_eq!(
        transaction.transaction_base64,
        "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgEFDAkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgtR7/nRVw2u3MRcqTSPetL2QXa0sna/os75FRcF9+XaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAh66s6M0l3iENjXIhy5Pz13G3/BhpuYx4+mm6fErVOlFAoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKAQgLCQIDBAUBBgoABwsCDQE="
    );
    assert_eq!(
        transaction.transaction_sha256,
        [
            0x92, 0x84, 0xe0, 0x0b, 0x52, 0x6c, 0xc1, 0xc7, 0xd1, 0x93, 0x9d, 0x75, 0x2f, 0x8b,
            0xd2, 0x10, 0x4b, 0xee, 0x59, 0xce, 0x21, 0x0c, 0x07, 0xa7, 0x24, 0x4a, 0x67, 0x3c,
            0x97, 0x16, 0x8e, 0x93,
        ]
    );
    assert_eq!(
        transaction.message_sha256,
        [
            0x3a, 0xb0, 0x8b, 0x67, 0x6a, 0x88, 0x3e, 0x86, 0x74, 0x4e, 0x30, 0x77, 0xb7, 0x55,
            0x2c, 0xb3, 0x22, 0xdc, 0x9f, 0x07, 0xb5, 0x21, 0x77, 0x8d, 0x90, 0xf7, 0xa1, 0x79,
            0x6f, 0xcd, 0x82, 0x61,
        ]
    );
}

#[test]
fn same_payer_and_authority_are_deduplicated() {
    let transaction = build_unsigned_transaction(plan(key(9), key(9)), [10; 32]).unwrap();
    assert_eq!(transaction.required_signers, vec![key(9)]);
    assert_eq!(transaction.bytes[0], 1);
    assert!(transaction.bytes[1..65].iter().all(|byte| *byte == 0));
}

#[test]
fn no_signing_state_or_private_material_exists_in_models() {
    let record = TokenOwnerRecord {
        address: key(1),
        realm: key(2),
        governing_token_mint: key(3),
        governing_token_owner: key(4),
        governance_delegate: None,
    };
    let debug = format!("{record:?}");
    for forbidden in ["private", "seed", "keypair", "signature"] {
        assert!(!debug.to_ascii_lowercase().contains(forbidden));
    }
}
