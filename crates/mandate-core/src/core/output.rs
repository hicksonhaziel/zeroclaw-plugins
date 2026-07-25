use serde::Serialize;

use crate::core::audit::{AuditComplete, AuditOutcome};
use crate::core::audit_error::AuditError;
use crate::core::execution::Fingerprint;
use crate::core::limits::{
    MAX_AUDIT_OUTPUT_BYTES, MAX_FINDING_SAMPLES, MAX_RENDERED_UNRESOLVED_SAMPLES,
};
use crate::core::policy::{
    AnalysisStatus, AuthorityType, Effect, Finding, RiskLevel, UnresolvedInstruction,
    UnresolvedReason,
};

#[derive(Serialize)]
struct AuditResponse {
    schema_version: u8,
    action: &'static str,
    retrieval_status: &'static str,
    analysis_status: &'static str,
    risk_level: Option<&'static str>,
    risk_reason: &'static str,
    proposal: String,
    governance: Option<String>,
    realm: Option<String>,
    governance_program: Option<String>,
    commitment: &'static str,
    snapshot: Option<SnapshotOutput>,
    counts: Option<CountOutput>,
    execution_fingerprint: Option<String>,
    evidence_snapshot_fingerprint: Option<String>,
    finding_samples: Vec<FindingOutput>,
    finding_samples_truncated: bool,
    unresolved_samples: Vec<UnresolvedOutput>,
    unresolved_samples_truncated: bool,
    error_code: Option<&'static str>,
    summary: &'static str,
}

#[derive(Serialize)]
struct SnapshotOutput {
    authoritative_slot: u64,
    authoritative_account_set_single_context: bool,
}

#[derive(Serialize)]
struct CountOutput {
    options: usize,
    transaction_slots: usize,
    surviving_transactions: usize,
    instructions: usize,
    known_findings: usize,
    unresolved_instructions: usize,
}

#[derive(Serialize)]
#[serde(tag = "effect", rename_all = "snake_case")]
enum FindingOutput {
    SystemTransfer {
        risk: &'static str,
        source: String,
        destination: String,
        lamports: u64,
    },
    TokenTransfer {
        risk: &'static str,
        source: String,
        destination: String,
        authority: String,
        amount_atomic: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        instruction_decimals: Option<u8>,
    },
    TokenAuthorityChange {
        risk: &'static str,
        target: String,
        current_authority: String,
        authority_type: &'static str,
        new_authority: Option<String>,
    },
    TokenAccountClose {
        risk: &'static str,
        account: String,
        lamport_destination: String,
        authority: String,
    },
}

#[derive(Serialize)]
struct UnresolvedOutput {
    code: &'static str,
    option_index: u8,
    transaction_index: u16,
    instruction_index: u16,
    program: String,
}

pub fn render_audit_outcome(outcome: &AuditOutcome) -> Result<String, AuditError> {
    let response = match outcome {
        AuditOutcome::Complete(complete) => complete_response(complete),
        AuditOutcome::Incomplete(failure) => failure_response(
            failure.proposal.to_base58(),
            "incomplete",
            failure.error.code(),
            "Required governance evidence was incomplete or contradictory; no safety conclusion is available.",
        ),
        AuditOutcome::Failed(failure) => failure_response(
            failure.proposal.to_base58(),
            "failed",
            failure.error.code(),
            "Bounded retrieval failed; no governance or safety conclusion is available.",
        ),
    };
    let rendered = serde_json::to_string(&response).map_err(|_| AuditError::OutputTooLarge)?;
    if rendered.len() > MAX_AUDIT_OUTPUT_BYTES {
        return Err(AuditError::OutputTooLarge);
    }
    Ok(rendered)
}

fn failure_response(
    proposal: String,
    retrieval_status: &'static str,
    error_code: &'static str,
    summary: &'static str,
) -> AuditResponse {
    AuditResponse {
        schema_version: 2,
        action: "audit",
        retrieval_status,
        analysis_status: "unresolved",
        risk_level: None,
        risk_reason: "analysis_unavailable",
        proposal,
        governance: None,
        realm: None,
        governance_program: None,
        commitment: "finalized",
        snapshot: None,
        counts: None,
        execution_fingerprint: None,
        evidence_snapshot_fingerprint: None,
        finding_samples: Vec::new(),
        finding_samples_truncated: false,
        unresolved_samples: Vec::new(),
        unresolved_samples_truncated: false,
        error_code: Some(error_code),
        summary,
    }
}

fn complete_response(complete: &AuditComplete) -> AuditResponse {
    let analysis = &complete.analysis;
    AuditResponse {
        schema_version: 2,
        action: "audit",
        retrieval_status: "complete",
        analysis_status: match analysis.status {
            AnalysisStatus::Complete => "complete",
            AnalysisStatus::Unresolved => "unresolved",
        },
        risk_level: analysis.risk_level.map(risk_name),
        risk_reason: if analysis.known_finding_count > 0 {
            "deterministic_policy_v1"
        } else if analysis.unresolved_instruction_count > 0 {
            "no_supported_effects"
        } else {
            "no_executable_instructions"
        },
        proposal: complete.proposal.to_base58(),
        governance: Some(complete.governance.to_base58()),
        realm: Some(complete.realm.to_base58()),
        governance_program: Some(complete.governance_program.to_base58()),
        commitment: "finalized",
        snapshot: Some(SnapshotOutput {
            authoritative_slot: complete.authoritative_slot,
            authoritative_account_set_single_context: true,
        }),
        counts: Some(CountOutput {
            options: complete.option_count,
            transaction_slots: complete.transaction_slot_count,
            surviving_transactions: complete.surviving_transaction_count,
            instructions: complete.instruction_count,
            known_findings: analysis.known_finding_count,
            unresolved_instructions: analysis.unresolved_instruction_count,
        }),
        execution_fingerprint: Some(render_fingerprint(complete.execution_fingerprint)),
        evidence_snapshot_fingerprint: Some(render_fingerprint(complete.evidence_fingerprint)),
        finding_samples: analysis
            .finding_samples
            .iter()
            .take(MAX_FINDING_SAMPLES)
            .map(finding_output)
            .collect(),
        finding_samples_truncated: analysis.known_finding_count
            > analysis.finding_samples.len().min(MAX_FINDING_SAMPLES),
        unresolved_samples: analysis
            .unresolved_samples
            .iter()
            .take(MAX_RENDERED_UNRESOLVED_SAMPLES)
            .map(unresolved_output)
            .collect(),
        unresolved_samples_truncated: analysis.unresolved_instruction_count
            > analysis
                .unresolved_samples
                .len()
                .min(MAX_RENDERED_UNRESOLVED_SAMPLES),
        error_code: None,
        summary: summary(analysis.status, analysis.risk_level),
    }
}

fn finding_output(finding: &Finding) -> FindingOutput {
    let risk = risk_name(finding.risk_level);
    match &finding.effect {
        Effect::SystemTransfer {
            source,
            destination,
            lamports,
        } => FindingOutput::SystemTransfer {
            risk,
            source: source.to_base58(),
            destination: destination.to_base58(),
            lamports: *lamports,
        },
        Effect::TokenTransfer {
            source,
            destination,
            authority,
            amount_atomic,
            instruction_decimals,
        } => FindingOutput::TokenTransfer {
            risk,
            source: source.to_base58(),
            destination: destination.to_base58(),
            authority: authority.to_base58(),
            amount_atomic: *amount_atomic,
            instruction_decimals: *instruction_decimals,
        },
        Effect::TokenAuthorityChange {
            target,
            current_authority,
            authority_type,
            new_authority,
        } => FindingOutput::TokenAuthorityChange {
            risk,
            target: target.to_base58(),
            current_authority: current_authority.to_base58(),
            authority_type: authority_name(*authority_type),
            new_authority: new_authority.map(|key| key.to_base58()),
        },
        Effect::TokenAccountClose {
            account,
            lamport_destination,
            authority,
        } => FindingOutput::TokenAccountClose {
            risk,
            account: account.to_base58(),
            lamport_destination: lamport_destination.to_base58(),
            authority: authority.to_base58(),
        },
    }
}

fn unresolved_output(unresolved: &UnresolvedInstruction) -> UnresolvedOutput {
    UnresolvedOutput {
        code: match unresolved.reason {
            UnresolvedReason::UnsupportedProgram => "unsupported_program",
            UnresolvedReason::UnsupportedInstruction => "unsupported_instruction",
            UnresolvedReason::MalformedInstruction => "malformed_instruction",
        },
        option_index: unresolved.location.option_index,
        transaction_index: unresolved.location.transaction_index,
        instruction_index: unresolved.location.instruction_index,
        program: unresolved.location.program.to_base58(),
    }
}

fn risk_name(risk: RiskLevel) -> &'static str {
    match risk {
        RiskLevel::Low => "low",
        RiskLevel::Medium => "medium",
        RiskLevel::High => "high",
        RiskLevel::Critical => "critical",
    }
}

fn authority_name(authority: AuthorityType) -> &'static str {
    match authority {
        AuthorityType::MintTokens => "mint_tokens",
        AuthorityType::FreezeAccount => "freeze_account",
        AuthorityType::AccountOwner => "account_owner",
        AuthorityType::CloseAccount => "close_account",
    }
}

fn summary(status: AnalysisStatus, risk: Option<RiskLevel>) -> &'static str {
    match (status, risk) {
        (AnalysisStatus::Complete, None) => "No executable instructions.",
        (AnalysisStatus::Complete, Some(_)) => "Supported effects analyzed.",
        (AnalysisStatus::Unresolved, None) => "Instructions remain unresolved.",
        (AnalysisStatus::Unresolved, Some(_)) => {
            "Known findings preserved; other instructions unresolved."
        }
    }
}

fn render_fingerprint(fingerprint: Fingerprint) -> String {
    let mut output = String::with_capacity(71);
    output.push_str("sha256:");
    for byte in fingerprint.0 {
        use core::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::audit::AuditOutcome;
    use crate::core::policy::{AnalysisReport, AnalysisStatus, Effect, Finding, RiskLevel};
    use crate::core::pubkey::Pubkey;

    fn key(value: u8) -> Pubkey {
        Pubkey::new([value; 32])
    }

    fn complete_with_findings() -> AuditComplete {
        let transfer = Finding {
            risk_level: RiskLevel::Low,
            effect: Effect::TokenTransfer {
                source: key(1),
                destination: key(2),
                authority: key(3),
                amount_atomic: 1_234_500,
                instruction_decimals: Some(4),
            },
        };
        let authority_change = Finding {
            risk_level: RiskLevel::Critical,
            effect: Effect::TokenAuthorityChange {
                target: key(4),
                current_authority: key(5),
                authority_type: AuthorityType::AccountOwner,
                new_authority: Some(key(6)),
            },
        };
        AuditComplete {
            proposal: key(10),
            governance: key(11),
            realm: key(12),
            governance_program: key(13),
            governing_token_mint: key(14),
            proposal_owner_record: key(15),
            proposal_state: 2,
            voting_at: Some(1),
            voting_base_time: 10,
            voting_cool_off_time: 0,
            first_observed_slot: 1,
            last_observed_slot: 2,
            authoritative_slot: 2,
            option_count: 1,
            transaction_slot_count: 1,
            surviving_transaction_count: 1,
            instruction_count: 2,
            execution_fingerprint: Fingerprint([1; 32]),
            evidence_fingerprint: Fingerprint([2; 32]),
            analysis: AnalysisReport {
                status: AnalysisStatus::Complete,
                risk_level: Some(RiskLevel::Critical),
                known_finding_count: 2,
                finding_samples: vec![transfer, authority_change],
                unresolved_instruction_count: 0,
                unresolved_samples: Vec::new(),
            },
            transaction_positions: Vec::new(),
            security_bindings: Vec::new(),
        }
    }

    #[test]
    fn intended_demo_shape_is_bounded_and_preserves_critical_evidence() {
        let outcome = AuditOutcome::Complete(Box::new(complete_with_findings()));
        let first = render_audit_outcome(&outcome).unwrap();
        let second = render_audit_outcome(&outcome).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 1_552);
        assert!(
            first.len() <= 1_600,
            "demo output was {} bytes",
            first.len()
        );
        assert!(first.len() <= MAX_AUDIT_OUTPUT_BYTES);
        let value: serde_json::Value = serde_json::from_str(&first).unwrap();
        assert_eq!(value["schema_version"], 2);
        assert_eq!(value["counts"]["known_findings"], 2);
        assert_eq!(value["finding_samples"].as_array().unwrap().len(), 2);
        assert_eq!(value["finding_samples_truncated"], false);
        assert_eq!(value["finding_samples"][0]["amount_atomic"], 1_234_500);
        assert_eq!(value["finding_samples"][0]["instruction_decimals"], 4);
        assert!(value["finding_samples"][0].get("amount_display").is_none());
        assert_eq!(value["finding_samples"][1]["risk"], "critical");
        for field in ["proposal", "governance", "realm", "governance_program"] {
            assert_eq!(
                value[field].as_str().unwrap(),
                key(match field {
                    "proposal" => 10,
                    "governance" => 11,
                    "realm" => 12,
                    _ => 13,
                })
                .to_base58()
            );
        }
        assert_eq!(value["execution_fingerprint"].as_str().unwrap().len(), 71);
        assert_eq!(
            value["evidence_snapshot_fingerprint"]
                .as_str()
                .unwrap()
                .len(),
            71
        );
    }

    #[test]
    fn finding_sample_truncation_remains_honest() {
        let mut complete = complete_with_findings();
        complete.analysis.known_finding_count = 3;
        let rendered = render_audit_outcome(&AuditOutcome::Complete(Box::new(complete))).unwrap();
        let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(value["finding_samples"].as_array().unwrap().len(), 2);
        assert_eq!(value["finding_samples_truncated"], true);
    }
}
