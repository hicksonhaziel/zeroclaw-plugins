use core::fmt;
use std::collections::BTreeSet;

use serde::Serialize;

use crate::core::audit_error::AuditError;
use crate::core::limits::MAX_RPC_REQUEST_BYTES;
use crate::core::pubkey::Pubkey;

#[derive(Clone, Eq, PartialEq)]
pub struct RpcRequest {
    pub id: u64,
    pub body: Vec<u8>,
    pub response_limit: usize,
}

impl fmt::Debug for RpcRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RpcRequest")
            .field("id", &self.id)
            .field("body", &"<redacted>")
            .field("response_limit", &self.response_limit)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RpcContext {
    pub slot: u64,
}

#[derive(Clone, Eq, PartialEq)]
pub struct AccountObservation {
    pub address: Pubkey,
    pub owner: Pubkey,
    pub executable: bool,
    pub lamports: u64,
    pub rent_epoch: u64,
    pub data: Vec<u8>,
}

impl fmt::Debug for AccountObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountObservation")
            .field("address", &self.address)
            .field("owner", &self.owner)
            .field("executable", &self.executable)
            .field("lamports", &self.lamports)
            .field("rent_epoch", &self.rent_epoch)
            .field("data", &"<redacted>")
            .finish()
    }
}

#[derive(Serialize)]
struct AccountConfig {
    encoding: &'static str,
    commitment: &'static str,
    #[serde(rename = "minContextSlot", skip_serializing_if = "Option::is_none")]
    min_context_slot: Option<u64>,
}

#[derive(Serialize)]
struct RequestEnvelope<P> {
    jsonrpc: &'static str,
    id: u64,
    method: &'static str,
    params: P,
}

pub fn account_info_request(
    id: u64,
    address: Pubkey,
    min_context_slot: Option<u64>,
    response_limit: usize,
) -> Result<RpcRequest, AuditError> {
    build(
        id,
        "getAccountInfo",
        (
            address.to_base58(),
            AccountConfig {
                encoding: "base64",
                commitment: "finalized",
                min_context_slot,
            },
        ),
        response_limit,
    )
}

pub fn multiple_accounts_request(
    id: u64,
    addresses: &[Pubkey],
    min_context_slot: u64,
    response_limit: usize,
) -> Result<RpcRequest, AuditError> {
    if addresses.iter().copied().collect::<BTreeSet<_>>().len() != addresses.len() {
        return Err(AuditError::DuplicateAddress);
    }
    let addresses = addresses
        .iter()
        .copied()
        .map(Pubkey::to_base58)
        .collect::<Vec<_>>();
    build(
        id,
        "getMultipleAccounts",
        (
            addresses,
            AccountConfig {
                encoding: "base64",
                commitment: "finalized",
                min_context_slot: Some(min_context_slot),
            },
        ),
        response_limit,
    )
}

fn build<P: Serialize>(
    id: u64,
    method: &'static str,
    params: P,
    response_limit: usize,
) -> Result<RpcRequest, AuditError> {
    let body = serde_json::to_vec(&RequestEnvelope {
        jsonrpc: "2.0",
        id,
        method,
        params,
    })
    .map_err(|_| AuditError::InvalidRpcEnvelope)?;
    if body.len() > MAX_RPC_REQUEST_BYTES {
        return Err(AuditError::DiscoveryLimit);
    }
    Ok(RpcRequest {
        id,
        body,
        response_limit,
    })
}
