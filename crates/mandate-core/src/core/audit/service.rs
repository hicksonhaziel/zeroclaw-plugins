use std::collections::BTreeSet;

use crate::core::account::AccountSnapshot;
use crate::core::audit_error::AuditError;
use crate::core::evidence::{
    fingerprint_evidence_v1, EvidenceSnapshot, FinalObservation, ObservationRole,
};
use crate::core::execution::{fingerprint_v1, reconstruct_execution, Fingerprint};
use crate::core::governance::pda::derive_proposal_transaction;
use crate::core::governance::{
    parse_governance, parse_proposal, parse_proposal_transaction, parse_realm,
};
use crate::core::limits::{
    MAX_AGGREGATE_DISCOVERY_POSITIONS, MAX_FINAL_BATCH_ADDRESSES, MAX_FINAL_BATCH_RESPONSE_BYTES,
    MAX_RPC_CALLS, MAX_SINGLE_ACCOUNT_RESPONSE_BYTES, MAX_TOTAL_RPC_RESPONSE_BYTES,
};
use crate::core::policy::{analyze_execution, AnalysisReport};
use crate::core::pubkey::{is_supported_governance_program, Pubkey};
use crate::core::rpc::{
    account_info_request, multiple_accounts_request, parse_multiple_accounts, parse_single_account,
    AccountObservation, HttpResponse, RpcRequest, RpcTransport,
};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountSecurityBinding {
    pub address: Pubkey,
    pub owner: Option<Pubkey>,
    pub executable: Option<bool>,
    pub data_sha256: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditComplete {
    pub proposal: Pubkey,
    pub governance: Pubkey,
    pub realm: Pubkey,
    pub governance_program: Pubkey,
    pub governing_token_mint: Pubkey,
    pub proposal_owner_record: Pubkey,
    pub proposal_state: u8,
    pub voting_at: Option<i64>,
    pub voting_base_time: u32,
    pub voting_cool_off_time: u32,
    pub first_observed_slot: u64,
    pub last_observed_slot: u64,
    pub authoritative_slot: u64,
    pub option_count: usize,
    pub transaction_slot_count: usize,
    pub surviving_transaction_count: usize,
    pub instruction_count: usize,
    pub execution_fingerprint: Fingerprint,
    pub evidence_fingerprint: Fingerprint,
    pub analysis: AnalysisReport,
    pub transaction_positions: Vec<(u8, u16, Pubkey)>,
    pub security_bindings: Vec<AccountSecurityBinding>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditFailure {
    pub proposal: Pubkey,
    pub error: AuditError,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditOutcome {
    Complete(Box<AuditComplete>),
    Incomplete(AuditFailure),
    Failed(AuditFailure),
}

pub fn run_audit<T: RpcTransport>(transport: &mut T, proposal: Pubkey) -> AuditOutcome {
    match run_audit_inner(transport, proposal) {
        Ok(complete) => AuditOutcome::Complete(Box::new(complete)),
        Err(error) if error.is_incomplete() => {
            AuditOutcome::Incomplete(AuditFailure { proposal, error })
        }
        Err(error) => AuditOutcome::Failed(AuditFailure { proposal, error }),
    }
}

fn run_audit_inner<T: RpcTransport>(
    transport: &mut T,
    proposal_address: Pubkey,
) -> Result<AuditComplete, AuditError> {
    let mut budget = RpcBudget::default();

    let proposal_request =
        account_info_request(1, proposal_address, None, MAX_SINGLE_ACCOUNT_RESPONSE_BYTES)?;
    let proposal_response = budget.send(transport, &proposal_request)?;
    let (proposal_context, preliminary_proposal) =
        parse_single_account(proposal_response, 1, proposal_address)?;
    let preliminary_proposal = preliminary_proposal.ok_or(AuditError::MissingParent)?;
    validate_governance_observation(&preliminary_proposal, None)?;
    let proposal_model =
        parse_proposal(&snapshot(&preliminary_proposal)).map_err(|_| AuditError::Governance)?;
    let governance_program = preliminary_proposal.owner;

    let governance_request = account_info_request(
        2,
        proposal_model.governance,
        Some(proposal_context.slot),
        MAX_SINGLE_ACCOUNT_RESPONSE_BYTES,
    )?;
    let governance_response = budget.send(transport, &governance_request)?;
    let (governance_context, preliminary_governance) =
        parse_single_account(governance_response, 2, proposal_model.governance)?;
    require_nondecreasing(proposal_context.slot, governance_context.slot)?;
    let preliminary_governance = preliminary_governance.ok_or(AuditError::MissingParent)?;
    validate_governance_observation(&preliminary_governance, Some(governance_program))?;
    let governance_model =
        parse_governance(&snapshot(&preliminary_governance)).map_err(|_| AuditError::Governance)?;
    if proposal_model.governance != governance_model.address {
        return Err(AuditError::Governance);
    }

    let realm_request = account_info_request(
        3,
        governance_model.realm,
        Some(governance_context.slot),
        MAX_SINGLE_ACCOUNT_RESPONSE_BYTES,
    )?;
    let realm_response = budget.send(transport, &realm_request)?;
    let (realm_context, preliminary_realm) =
        parse_single_account(realm_response, 3, governance_model.realm)?;
    require_nondecreasing(governance_context.slot, realm_context.slot)?;
    let preliminary_realm = preliminary_realm.ok_or(AuditError::MissingParent)?;
    validate_governance_observation(&preliminary_realm, Some(governance_program))?;
    let realm_model =
        parse_realm(&snapshot(&preliminary_realm)).map_err(|_| AuditError::Governance)?;
    if governance_model.realm != realm_model.address
        || (proposal_model.governing_token_mint != realm_model.community_mint
            && Some(proposal_model.governing_token_mint) != realm_model.council_mint)
    {
        return Err(AuditError::Governance);
    }

    let mut final_addresses = vec![
        proposal_address,
        governance_model.address,
        realm_model.address,
    ];
    let mut transaction_roles = Vec::new();
    let mut discovery_count = 0usize;
    for (option_index, option) in proposal_model.options.iter().enumerate() {
        discovery_count = discovery_count
            .checked_add(usize::from(option.transactions_next_index))
            .ok_or(AuditError::DiscoveryLimit)?;
        if discovery_count > MAX_AGGREGATE_DISCOVERY_POSITIONS {
            return Err(AuditError::DiscoveryLimit);
        }
        let option_index = u8::try_from(option_index).map_err(|_| AuditError::DiscoveryLimit)?;
        for transaction_index in 0..option.transactions_next_index {
            let (address, _bump) = derive_proposal_transaction(
                governance_program,
                proposal_address,
                option_index,
                transaction_index,
            )
            .map_err(|_| AuditError::PdaDerivation)?;
            final_addresses.push(address);
            transaction_roles.push((option_index, transaction_index, address));
        }
    }
    if final_addresses.len() > MAX_FINAL_BATCH_ADDRESSES
        || final_addresses
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len()
            != final_addresses.len()
    {
        return Err(if final_addresses.len() > MAX_FINAL_BATCH_ADDRESSES {
            AuditError::DiscoveryLimit
        } else {
            AuditError::DuplicateAddress
        });
    }

    let final_request = multiple_accounts_request(
        4,
        &final_addresses,
        realm_context.slot,
        MAX_FINAL_BATCH_RESPONSE_BYTES,
    )?;
    let final_response = budget.send(transport, &final_request)?;
    let (final_context, mut final_values) =
        parse_multiple_accounts(final_response, 4, &final_addresses)?;
    require_nondecreasing(realm_context.slot, final_context.slot)?;
    if budget.calls != MAX_RPC_CALLS {
        return Err(AuditError::Transport);
    }

    let final_proposal = take_present(&mut final_values, 0)?;
    let final_governance = take_present(&mut final_values, 1)?;
    let final_realm = take_present(&mut final_values, 2)?;
    for (preliminary, authoritative) in [
        (&preliminary_proposal, &final_proposal),
        (&preliminary_governance, &final_governance),
        (&preliminary_realm, &final_realm),
    ] {
        if preliminary.owner != authoritative.owner
            || preliminary.executable != authoritative.executable
            || preliminary.data != authoritative.data
        {
            return Err(AuditError::SnapshotChanged);
        }
    }

    for observation in [&final_proposal, &final_governance, &final_realm] {
        validate_governance_observation(observation, Some(governance_program))?;
    }
    let final_proposal_model =
        parse_proposal(&snapshot(&final_proposal)).map_err(|_| AuditError::Governance)?;
    let final_governance_model =
        parse_governance(&snapshot(&final_governance)).map_err(|_| AuditError::Governance)?;
    let final_realm_model =
        parse_realm(&snapshot(&final_realm)).map_err(|_| AuditError::Governance)?;

    let mut parsed_transactions = Vec::new();
    let mut observations = vec![
        final_observation(ObservationRole::Proposal, final_proposal),
        final_observation(ObservationRole::Governance, final_governance),
        final_observation(ObservationRole::Realm, final_realm),
    ];
    for (offset, (option_index, transaction_index, address)) in
        transaction_roles.iter().copied().enumerate()
    {
        let account = final_values
            .get_mut(offset + 3)
            .ok_or(AuditError::InvalidResponseLength)?
            .take();
        if let Some(account) = &account {
            validate_governance_observation(account, Some(governance_program))?;
            let parsed = parse_proposal_transaction(&snapshot(account))
                .map_err(|_| AuditError::Governance)?;
            if parsed.address != address
                || parsed.proposal != proposal_address
                || parsed.option_index != option_index
                || parsed.transaction_index != transaction_index
            {
                return Err(AuditError::TransactionPdaMismatch);
            }
            parsed_transactions.push(parsed);
        }
        observations.push(FinalObservation {
            role: ObservationRole::ProposalTransaction {
                option_index,
                transaction_index,
            },
            address,
            account,
        });
    }

    let execution = reconstruct_execution(
        &final_realm_model,
        &final_governance_model,
        &final_proposal_model,
        parsed_transactions,
    )
    .map_err(|_| AuditError::Governance)?;
    let execution_fingerprint = fingerprint_v1(&execution).map_err(|_| AuditError::Governance)?;
    let security_bindings = observations
        .iter()
        .map(|observation| match &observation.account {
            Some(account) => AccountSecurityBinding {
                address: observation.address,
                owner: Some(account.owner),
                executable: Some(account.executable),
                data_sha256: Some(Sha256::digest(&account.data).into()),
            },
            None => AccountSecurityBinding {
                address: observation.address,
                owner: None,
                executable: None,
                data_sha256: None,
            },
        })
        .collect();
    let evidence_fingerprint = fingerprint_evidence_v1(&EvidenceSnapshot {
        execution_fingerprint,
        governance_program,
        authoritative_slot: final_context.slot,
        observations,
    })?;

    let instruction_count = execution
        .options
        .iter()
        .flat_map(|option| &option.transactions)
        .map(|transaction| transaction.instructions.len())
        .try_fold(0usize, |total, count| total.checked_add(count))
        .ok_or(AuditError::DiscoveryLimit)?;
    let analysis = analyze_execution(&execution);

    Ok(AuditComplete {
        proposal: execution.proposal,
        governance: execution.governance,
        realm: execution.realm,
        governance_program,
        governing_token_mint: final_proposal_model.governing_token_mint,
        proposal_owner_record: final_proposal_model.token_owner_record,
        proposal_state: final_proposal_model.state,
        voting_at: final_proposal_model.voting_at,
        voting_base_time: final_governance_model.voting_base_time,
        voting_cool_off_time: final_governance_model.voting_cool_off_time,
        first_observed_slot: proposal_context.slot,
        last_observed_slot: final_context.slot,
        authoritative_slot: final_context.slot,
        option_count: execution.options.len(),
        transaction_slot_count: discovery_count,
        surviving_transaction_count: execution
            .options
            .iter()
            .map(|option| option.transactions.len())
            .sum(),
        instruction_count,
        execution_fingerprint,
        evidence_fingerprint,
        analysis,
        transaction_positions: transaction_roles,
        security_bindings,
    })
}

#[derive(Default)]
struct RpcBudget {
    calls: usize,
    response_bytes: usize,
}

impl RpcBudget {
    fn send<T: RpcTransport>(
        &mut self,
        transport: &mut T,
        request: &RpcRequest,
    ) -> Result<HttpResponse, AuditError> {
        if self.calls >= MAX_RPC_CALLS {
            return Err(AuditError::Transport);
        }
        let response = transport.send(request)?;
        self.calls += 1;
        if response.body.len() > request.response_limit {
            return Err(AuditError::ResponseTooLarge);
        }
        self.response_bytes = self
            .response_bytes
            .checked_add(response.body.len())
            .ok_or(AuditError::ResponseTooLarge)?;
        if self.response_bytes > MAX_TOTAL_RPC_RESPONSE_BYTES {
            return Err(AuditError::ResponseTooLarge);
        }
        Ok(response)
    }
}

fn validate_governance_observation(
    account: &AccountObservation,
    expected_program: Option<Pubkey>,
) -> Result<(), AuditError> {
    if account.executable
        || !is_supported_governance_program(account.owner)
        || expected_program.is_some_and(|program| account.owner != program)
    {
        return Err(AuditError::WrongOwner);
    }
    Ok(())
}

fn snapshot(account: &AccountObservation) -> AccountSnapshot<'_> {
    AccountSnapshot {
        address: account.address,
        owner: account.owner,
        data: &account.data,
    }
}

fn require_nondecreasing(previous: u64, current: u64) -> Result<(), AuditError> {
    if current < previous {
        Err(AuditError::SlotRegression)
    } else {
        Ok(())
    }
}

fn take_present(
    values: &mut [Option<AccountObservation>],
    index: usize,
) -> Result<AccountObservation, AuditError> {
    values
        .get_mut(index)
        .ok_or(AuditError::InvalidResponseLength)?
        .take()
        .ok_or(AuditError::MissingParent)
}

fn final_observation(role: ObservationRole, account: AccountObservation) -> FinalObservation {
    FinalObservation {
        role,
        address: account.address,
        account: Some(account),
    }
}
