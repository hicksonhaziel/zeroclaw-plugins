use serde::Serialize;

use crate::core::audit::{AuditComplete, AuditOutcome};
use crate::core::audit_error::AuditError;
use crate::core::execution::Fingerprint;
use crate::core::limits::{MAX_AUDIT_OUTPUT_BYTES, MAX_RENDERED_UNRESOLVED_SAMPLES};

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
    unresolved_instructions: usize,
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
        AuditOutcome::Incomplete(failure) => AuditResponse {
            schema_version: 1,
            action: "audit",
            retrieval_status: "incomplete",
            analysis_status: "unresolved",
            risk_level: None,
            risk_reason: "policy_not_implemented",
            proposal: failure.proposal.to_base58(),
            governance: None,
            realm: None,
            governance_program: None,
            commitment: "finalized",
            snapshot: None,
            counts: None,
            execution_fingerprint: None,
            evidence_snapshot_fingerprint: None,
            unresolved_samples: Vec::new(),
            unresolved_samples_truncated: false,
            error_code: Some(failure.error.code()),
            summary: "Required governance evidence was incomplete or contradictory; no safety conclusion is available.",
        },
        AuditOutcome::Failed(failure) => AuditResponse {
            schema_version: 1,
            action: "audit",
            retrieval_status: "failed",
            analysis_status: "unresolved",
            risk_level: None,
            risk_reason: "policy_not_implemented",
            proposal: failure.proposal.to_base58(),
            governance: None,
            realm: None,
            governance_program: None,
            commitment: "finalized",
            snapshot: None,
            counts: None,
            execution_fingerprint: None,
            evidence_snapshot_fingerprint: None,
            unresolved_samples: Vec::new(),
            unresolved_samples_truncated: false,
            error_code: Some(failure.error.code()),
            summary: "Bounded retrieval failed; no governance or safety conclusion is available.",
        },
    };
    let rendered = serde_json::to_string(&response).map_err(|_| AuditError::OutputTooLarge)?;
    if rendered.len() > MAX_AUDIT_OUTPUT_BYTES {
        return Err(AuditError::OutputTooLarge);
    }
    Ok(rendered)
}

fn complete_response(complete: &AuditComplete) -> AuditResponse {
    let unresolved_count = complete.instruction_count;
    AuditResponse {
        schema_version: 1,
        action: "audit",
        retrieval_status: "complete",
        analysis_status: if unresolved_count == 0 {
            "complete"
        } else {
            "unresolved"
        },
        risk_level: None,
        risk_reason: "policy_not_implemented",
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
            unresolved_instructions: unresolved_count,
        }),
        execution_fingerprint: Some(render_fingerprint(complete.execution_fingerprint)),
        evidence_snapshot_fingerprint: Some(render_fingerprint(complete.evidence_fingerprint)),
        unresolved_samples: complete
            .unresolved_samples
            .iter()
            .take(MAX_RENDERED_UNRESOLVED_SAMPLES)
            .map(|sample| UnresolvedOutput {
                code: "unsupported_instruction",
                option_index: sample.option_index,
                transaction_index: sample.transaction_index,
                instruction_index: sample.instruction_index,
                program: sample.program.to_base58(),
            })
            .collect(),
        unresolved_samples_truncated: unresolved_count
            > complete
                .unresolved_samples
                .len()
                .min(MAX_RENDERED_UNRESOLVED_SAMPLES),
        error_code: None,
        summary: if unresolved_count == 0 {
            "Governance execution was reconstructed; no executable instructions were present and risk policy is not implemented."
        } else {
            "Governance execution was reconstructed; instruction effects and risk remain unresolved."
        },
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
