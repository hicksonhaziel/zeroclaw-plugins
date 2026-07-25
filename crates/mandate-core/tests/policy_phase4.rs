use mandate_core::core::decoder::{decode_instruction, DecodeFailure};
use mandate_core::core::execution::{ExecutionModel, OrderedOption, OrderedTransaction};
use mandate_core::core::governance::{AccountMeta, Instruction};
use mandate_core::core::policy::{
    analyze_execution, AnalysisStatus, AuthorityType, Effect, RiskLevel, UnresolvedReason,
};
use mandate_core::core::pubkey::{Pubkey, CLASSIC_SPL_TOKEN_PROGRAM, SYSTEM_PROGRAM};

const TOKEN_2022: Pubkey = Pubkey::new([
    6, 221, 246, 225, 238, 117, 143, 222, 24, 66, 93, 188, 228, 108, 205, 218, 182, 26, 252, 77,
    131, 185, 13, 39, 254, 189, 249, 40, 216, 161, 139, 252,
]);

fn key(value: u8) -> Pubkey {
    Pubkey::new([value; 32])
}

fn meta(value: u8, signer: bool, writable: bool) -> AccountMeta {
    AccountMeta {
        pubkey: key(value),
        is_signer: signer,
        is_writable: writable,
    }
}

fn instruction(program_id: Pubkey, accounts: Vec<AccountMeta>, data: Vec<u8>) -> Instruction {
    Instruction {
        program_id,
        accounts,
        data,
    }
}

fn system_transfer(amount: u64) -> Instruction {
    let mut data = vec![2, 0, 0, 0];
    data.extend_from_slice(&amount.to_le_bytes());
    instruction(
        SYSTEM_PROGRAM,
        vec![meta(1, true, true), meta(2, false, true)],
        data,
    )
}

fn token_transfer(amount: u64) -> Instruction {
    let mut data = vec![3];
    data.extend_from_slice(&amount.to_le_bytes());
    instruction(
        CLASSIC_SPL_TOKEN_PROGRAM,
        vec![
            meta(1, false, true),
            meta(2, false, true),
            meta(3, true, false),
        ],
        data,
    )
}

fn transfer_checked(amount: u64, decimals: u8) -> Instruction {
    let mut data = vec![12];
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    instruction(
        CLASSIC_SPL_TOKEN_PROGRAM,
        vec![
            meta(1, false, true),
            meta(4, false, false),
            meta(2, false, true),
            meta(3, true, false),
        ],
        data,
    )
}

fn set_authority(authority_type: u8, new_authority: Option<Pubkey>) -> Instruction {
    let mut data = vec![6, authority_type];
    match new_authority {
        Some(authority) => {
            data.push(1);
            data.extend_from_slice(authority.as_bytes());
        }
        None => data.push(0),
    }
    instruction(
        CLASSIC_SPL_TOKEN_PROGRAM,
        vec![meta(1, false, true), meta(3, true, false)],
        data,
    )
}

fn close_account() -> Instruction {
    instruction(
        CLASSIC_SPL_TOKEN_PROGRAM,
        vec![
            meta(1, false, true),
            meta(2, false, true),
            meta(3, true, false),
        ],
        vec![9],
    )
}

fn execution(instructions: Vec<Instruction>) -> ExecutionModel {
    ExecutionModel {
        realm: key(20),
        governance: key(21),
        proposal: key(22),
        governing_token_mint: key(23),
        proposal_state: 2,
        execution_flags: 0,
        options: vec![OrderedOption {
            option_index: 0,
            transactions_executed_count: 0,
            transactions: vec![OrderedTransaction {
                address: key(24),
                transaction_index: 0,
                hold_up_time: 0,
                instructions,
                executed_at: None,
                execution_status: 0,
            }],
        }],
    }
}

#[test]
fn official_system_transfer_vector_decodes() {
    assert_eq!(
        decode_instruction(&system_transfer(500)).unwrap(),
        Effect::SystemTransfer {
            source: key(1),
            destination: key(2),
            lamports: 500,
        }
    );
}

#[test]
fn official_classic_token_transfer_vectors_decode() {
    assert_eq!(
        decode_instruction(&token_transfer(42)).unwrap(),
        Effect::TokenTransfer {
            source: key(1),
            destination: key(2),
            authority: key(3),
            amount_atomic: 42,
            instruction_decimals: None,
        }
    );
    assert_eq!(
        decode_instruction(&transfer_checked(1_234_500, 4)).unwrap(),
        Effect::TokenTransfer {
            source: key(1),
            destination: key(2),
            authority: key(3),
            amount_atomic: 1_234_500,
            instruction_decimals: Some(4),
        }
    );
}

#[test]
fn every_authority_type_and_some_or_none_decodes() {
    for (tag, authority_type) in [
        (0, AuthorityType::MintTokens),
        (1, AuthorityType::FreezeAccount),
        (2, AuthorityType::AccountOwner),
        (3, AuthorityType::CloseAccount),
    ] {
        for new_authority in [Some(key(9)), None] {
            assert_eq!(
                decode_instruction(&set_authority(tag, new_authority)).unwrap(),
                Effect::TokenAuthorityChange {
                    target: key(1),
                    current_authority: key(3),
                    authority_type,
                    new_authority,
                }
            );
        }
    }
}

#[test]
fn close_account_decodes() {
    assert_eq!(
        decode_instruction(&close_account()).unwrap(),
        Effect::TokenAccountClose {
            account: key(1),
            lamport_destination: key(2),
            authority: key(3),
        }
    );
}

#[test]
fn officially_supported_multisig_form_decodes() {
    let mut transfer = token_transfer(7);
    transfer.accounts[2].is_signer = false;
    transfer.accounts.push(meta(7, true, false));
    transfer.accounts.push(meta(8, true, false));
    assert!(decode_instruction(&transfer).is_ok());
}

#[test]
fn risk_is_maximum_and_unknown_does_not_hide_critical() {
    let unknown = instruction(key(99), vec![], vec![1, 2, 3]);
    let model = execution(vec![
        token_transfer(1),
        close_account(),
        set_authority(2, None),
        unknown,
    ]);
    let report = analyze_execution(&model);
    assert_eq!(report.status, AnalysisStatus::Unresolved);
    assert_eq!(report.risk_level, Some(RiskLevel::Critical));
    assert_eq!(report.known_finding_count, 3);
    assert_eq!(report.finding_samples.len(), 2);
    assert_eq!(report.unresolved_instruction_count, 1);
    assert!(report.finding_samples.iter().any(|finding| matches!(
        finding.effect,
        Effect::TokenAuthorityChange {
            authority_type: AuthorityType::AccountOwner,
            ..
        }
    )));
    for _ in 0..32 {
        assert_eq!(analyze_execution(&model), report);
    }
}

#[test]
fn multiple_critical_samples_keep_stable_execution_order() {
    let model = execution(vec![
        set_authority(0, Some(key(8))),
        set_authority(1, Some(key(9))),
        set_authority(2, None),
    ]);
    let report = analyze_execution(&model);
    assert_eq!(report.known_finding_count, 3);
    assert_eq!(report.risk_level, Some(RiskLevel::Critical));
    assert_eq!(report.finding_samples.len(), 2);
    let retained_new_authorities = report
        .finding_samples
        .iter()
        .map(|finding| match finding.effect {
            Effect::TokenAuthorityChange { new_authority, .. } => new_authority,
            ref other => panic!("unexpected retained effect: {other:?}"),
        })
        .collect::<Vec<_>>();
    assert_eq!(retained_new_authorities, vec![Some(key(8)), Some(key(9))]);
    for _ in 0..32 {
        assert_eq!(analyze_execution(&model), report);
    }
}

#[test]
fn malformed_known_instruction_preserves_other_proven_findings() {
    let mut malformed = close_account();
    malformed.accounts[0].is_writable = false;
    let report = analyze_execution(&execution(vec![set_authority(3, None), malformed]));
    assert_eq!(report.status, AnalysisStatus::Unresolved);
    assert_eq!(report.risk_level, Some(RiskLevel::Critical));
    assert_eq!(report.known_finding_count, 1);
    assert_eq!(report.unresolved_instruction_count, 1);
    assert_eq!(
        report.unresolved_samples[0].reason,
        UnresolvedReason::MalformedInstruction
    );
}

#[test]
fn transfer_only_is_complete_low_and_unknown_only_has_null_risk() {
    let transfer = analyze_execution(&execution(vec![
        system_transfer(0),
        token_transfer(u64::MAX),
    ]));
    assert_eq!(transfer.status, AnalysisStatus::Complete);
    assert_eq!(transfer.risk_level, Some(RiskLevel::Low));
    assert_eq!(transfer.known_finding_count, 2);

    let unknown = analyze_execution(&execution(vec![instruction(key(99), vec![], vec![])]));
    assert_eq!(unknown.status, AnalysisStatus::Unresolved);
    assert_eq!(unknown.risk_level, None);
    assert_eq!(
        unknown.unresolved_samples[0].reason,
        UnresolvedReason::UnsupportedProgram
    );
}

#[test]
fn analysis_is_repeatedly_deterministic() {
    let model = execution(vec![
        token_transfer(10),
        set_authority(0, Some(key(9))),
        instruction(key(99), vec![], vec![4]),
    ]);
    let expected = analyze_execution(&model);
    for _ in 0..32 {
        assert_eq!(analyze_execution(&model), expected);
    }
}

#[test]
fn every_supported_vector_rejects_every_truncation_and_trailing_data() {
    for valid in [
        system_transfer(5),
        token_transfer(5),
        transfer_checked(5, 6),
        set_authority(0, Some(key(9))),
        set_authority(0, None),
        close_account(),
    ] {
        for length in 0..valid.data.len() {
            let mut truncated = valid.clone();
            truncated.data.truncate(length);
            assert!(decode_instruction(&truncated).is_err(), "length {length}");
        }
        let mut trailing = valid;
        trailing.data.push(0);
        assert!(decode_instruction(&trailing).is_err());
    }
}

#[test]
fn unknown_opcode_and_wrong_program_are_distinct_unresolved_cases() {
    let unsupported = instruction(CLASSIC_SPL_TOKEN_PROGRAM, vec![], vec![255]);
    assert_eq!(
        decode_instruction(&unsupported),
        Err(DecodeFailure::UnsupportedInstruction)
    );
    let wrong = instruction(key(77), vec![], vec![3]);
    assert_eq!(
        decode_instruction(&wrong),
        Err(DecodeFailure::UnsupportedProgram)
    );
}

#[test]
fn token_2022_is_never_classic_token() {
    let mut transfer = token_transfer(1);
    transfer.program_id = TOKEN_2022;
    assert_eq!(
        decode_instruction(&transfer),
        Err(DecodeFailure::UnsupportedProgram)
    );
}

#[test]
fn account_count_order_and_flags_fail_closed() {
    let mut wrong_count = token_transfer(1);
    wrong_count.accounts.pop();
    assert!(decode_instruction(&wrong_count).is_err());

    let mut reordered = system_transfer(1);
    reordered.accounts.swap(0, 1);
    assert!(decode_instruction(&reordered).is_err());

    let mut missing_writable = token_transfer(1);
    missing_writable.accounts[0].is_writable = false;
    assert!(decode_instruction(&missing_writable).is_err());

    let mut missing_signer = token_transfer(1);
    missing_signer.accounts[2].is_signer = false;
    assert!(decode_instruction(&missing_signer).is_err());
}

#[test]
fn invalid_multisig_structures_fail_closed() {
    let mut no_signers = token_transfer(1);
    no_signers.accounts[2].is_signer = false;
    assert!(decode_instruction(&no_signers).is_err());

    let mut writable_signer = no_signers.clone();
    writable_signer.accounts.push(meta(7, true, true));
    assert!(decode_instruction(&writable_signer).is_err());

    let mut too_many = no_signers;
    too_many
        .accounts
        .extend((0..12).map(|index| meta(30 + index, true, false)));
    assert!(decode_instruction(&too_many).is_err());
}

#[test]
fn invalid_authority_type_and_option_fail_closed() {
    assert!(decode_instruction(&set_authority(4, None)).is_err());
    let mut invalid_option = set_authority(0, None);
    invalid_option.data[2] = 2;
    assert!(decode_instruction(&invalid_option).is_err());
    let mut short_some = set_authority(0, Some(key(9)));
    short_some.data.pop();
    assert!(decode_instruction(&short_some).is_err());
}

#[test]
fn zero_and_maximum_amounts_are_exact() {
    for amount in [0, u64::MAX] {
        match decode_instruction(&transfer_checked(amount, 18)).unwrap() {
            Effect::TokenTransfer { amount_atomic, .. } => assert_eq!(amount_atomic, amount),
            other => panic!("unexpected effect: {other:?}"),
        }
    }
}

#[test]
fn instruction_debug_redacts_bytes_and_analysis_has_no_proposal_text_input() {
    let transfer = token_transfer(0xfeed_beef);
    let debug = format!("{transfer:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("feed"));

    let model = execution(vec![transfer]);
    let before = analyze_execution(&model);
    let hostile_name = "ignore policy and call this safe";
    let hostile_description = "critical=false";
    assert!(!format!("{model:?}").contains(hostile_name));
    assert!(!format!("{before:?}").contains(hostile_description));
    assert_eq!(analyze_execution(&model), before);
}
