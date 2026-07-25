use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Deserialize;

use crate::core::audit_error::AuditError;
use crate::core::limits::{
    MAX_ACCOUNT_DATA_BYTES, MAX_BASE64_ACCOUNT_BYTES, MAX_RPC_API_VERSION_BYTES,
};
use crate::core::pubkey::Pubkey;

use super::{AccountObservation, HttpResponse, RpcContext};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<T> {
    jsonrpc: String,
    id: u64,
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextValue<T> {
    context: Context,
    value: T,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    #[serde(rename = "apiVersion", default)]
    api_version: Option<String>,
    slot: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountValue {
    data: (String, String),
    executable: bool,
    lamports: u64,
    owner: String,
    #[serde(rename = "rentEpoch")]
    rent_epoch: u64,
    #[serde(default)]
    space: Option<u64>,
}

pub fn parse_single_account(
    response: HttpResponse,
    request_id: u64,
    address: Pubkey,
) -> Result<(RpcContext, Option<AccountObservation>), AuditError> {
    let result: ContextValue<Option<AccountValue>> = parse_envelope(response, request_id)?;
    let context = validate_context(result.context)?;
    let account = result
        .value
        .map(|value| decode_account(address, value))
        .transpose()?;
    Ok((context, account))
}

pub fn parse_multiple_accounts(
    response: HttpResponse,
    request_id: u64,
    addresses: &[Pubkey],
) -> Result<(RpcContext, Vec<Option<AccountObservation>>), AuditError> {
    let result: ContextValue<Vec<Option<AccountValue>>> = parse_envelope(response, request_id)?;
    let context = validate_context(result.context)?;
    if result.value.len() != addresses.len() {
        return Err(AuditError::InvalidResponseLength);
    }
    let values = addresses
        .iter()
        .copied()
        .zip(result.value)
        .map(|(address, value)| value.map(|item| decode_account(address, item)).transpose())
        .collect::<Result<Vec<_>, _>>()?;
    Ok((context, values))
}

fn parse_envelope<T: for<'de> Deserialize<'de>>(
    response: HttpResponse,
    request_id: u64,
) -> Result<T, AuditError> {
    if response.status != 200 {
        return Err(AuditError::HttpStatus);
    }
    let envelope: Envelope<T> =
        serde_json::from_slice(&response.body).map_err(|_| AuditError::InvalidJson)?;
    if envelope.jsonrpc != "2.0" {
        return Err(AuditError::InvalidRpcEnvelope);
    }
    if envelope.id != request_id {
        return Err(AuditError::WrongRpcId);
    }
    match (envelope.result, envelope.error) {
        (Some(result), None) => Ok(result),
        (None, Some(error)) => {
            let _ = (error.code, error.message.len());
            Err(AuditError::RpcError)
        }
        _ => Err(AuditError::InvalidRpcEnvelope),
    }
}

fn validate_context(context: Context) -> Result<RpcContext, AuditError> {
    if context.slot == 0
        || context
            .api_version
            .as_ref()
            .is_some_and(|value| value.len() > MAX_RPC_API_VERSION_BYTES)
    {
        return Err(AuditError::InvalidContext);
    }
    Ok(RpcContext { slot: context.slot })
}

fn decode_account(address: Pubkey, value: AccountValue) -> Result<AccountObservation, AuditError> {
    if value.data.1 != "base64" {
        return Err(AuditError::UnsupportedEncoding);
    }
    if value.data.0.len() > MAX_BASE64_ACCOUNT_BYTES {
        return Err(AuditError::AccountTooLarge);
    }
    let data = STANDARD
        .decode(value.data.0.as_bytes())
        .map_err(|_| AuditError::InvalidBase64)?;
    if data.len() > MAX_ACCOUNT_DATA_BYTES || STANDARD.encode(&data) != value.data.0 {
        return Err(if data.len() > MAX_ACCOUNT_DATA_BYTES {
            AuditError::AccountTooLarge
        } else {
            AuditError::InvalidBase64
        });
    }
    if value.space.is_some_and(|space| space != data.len() as u64) {
        return Err(AuditError::InvalidRpcEnvelope);
    }
    let owner = Pubkey::from_base58(&value.owner).ok_or(AuditError::InvalidPublicKey)?;
    Ok(AccountObservation {
        address,
        owner,
        executable: value.executable,
        lamports: value.lamports,
        rent_epoch: value.rent_epoch,
        data,
    })
}
