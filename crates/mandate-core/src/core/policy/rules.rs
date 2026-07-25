use crate::core::decoder::{decode_instruction, DecodeFailure};
use crate::core::execution::ExecutionModel;
use crate::core::limits::{MAX_FINDING_SAMPLES, MAX_UNRESOLVED_SAMPLES};

use super::model::{
    AnalysisReport, AnalysisStatus, Effect, Finding, InstructionLocation, RiskLevel,
    UnresolvedInstruction, UnresolvedReason,
};

pub fn analyze_execution(execution: &ExecutionModel) -> AnalysisReport {
    let mut report = AnalysisReport {
        status: AnalysisStatus::Complete,
        risk_level: None,
        known_finding_count: 0,
        finding_samples: Vec::new(),
        unresolved_instruction_count: 0,
        unresolved_samples: Vec::new(),
    };

    for option in &execution.options {
        for transaction in &option.transactions {
            for (index, instruction) in transaction.instructions.iter().enumerate() {
                let location = InstructionLocation {
                    option_index: option.option_index,
                    transaction_index: transaction.transaction_index,
                    instruction_index: u16::try_from(index).unwrap_or(u16::MAX),
                    program: instruction.program_id,
                };
                match decode_instruction(instruction) {
                    Ok(effect) => add_finding(&mut report, effect),
                    Err(failure) => add_unresolved(&mut report, location, failure),
                }
            }
        }
    }
    report
}

fn add_finding(report: &mut AnalysisReport, effect: Effect) {
    let risk_level = match effect {
        Effect::SystemTransfer { .. } | Effect::TokenTransfer { .. } => RiskLevel::Low,
        Effect::TokenAccountClose { .. } => RiskLevel::High,
        Effect::TokenAuthorityChange { .. } => RiskLevel::Critical,
    };
    report.known_finding_count += 1;
    report.risk_level = Some(
        report
            .risk_level
            .map_or(risk_level, |risk| risk.max(risk_level)),
    );
    let finding = Finding { risk_level, effect };
    if report.finding_samples.len() < MAX_FINDING_SAMPLES {
        report.finding_samples.push(finding);
    } else if let Some(lowest_risk) = report
        .finding_samples
        .iter()
        .map(|sample| sample.risk_level)
        .min()
    {
        if risk_level > lowest_risk {
            // Removing the earliest lowest-risk sample and appending this
            // higher-risk finding preserves execution order among retained
            // samples. Equal-risk ties keep their earliest samples.
            if let Some(index) = report
                .finding_samples
                .iter()
                .position(|sample| sample.risk_level == lowest_risk)
            {
                report.finding_samples.remove(index);
                report.finding_samples.push(finding);
            }
        }
    }
}

fn add_unresolved(
    report: &mut AnalysisReport,
    location: InstructionLocation,
    failure: DecodeFailure,
) {
    report.status = AnalysisStatus::Unresolved;
    report.unresolved_instruction_count += 1;
    if report.unresolved_samples.len() < MAX_UNRESOLVED_SAMPLES {
        let reason = match failure {
            DecodeFailure::UnsupportedProgram => UnresolvedReason::UnsupportedProgram,
            DecodeFailure::UnsupportedInstruction => UnresolvedReason::UnsupportedInstruction,
            DecodeFailure::MalformedInstruction => UnresolvedReason::MalformedInstruction,
        };
        report
            .unresolved_samples
            .push(UnresolvedInstruction { location, reason });
    }
}
