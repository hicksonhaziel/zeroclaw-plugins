//! Bounded WASI HTTP adapter. Pure validation remains in `core::health`.

#[cfg(target_family = "wasm")]
use std::time::Duration;

#[cfg(target_family = "wasm")]
use crate::core::health::{validate_get_health_response, HealthResult, RpcEndpoint};
#[cfg(target_family = "wasm")]
use crate::core::limits::HTTP_TIMEOUT_SECS;
#[cfg(any(target_family = "wasm", test))]
use crate::core::limits::MAX_RESPONSE_BYTES;
#[cfg(any(target_family = "wasm", test))]
use crate::core::CapabilityError;

#[cfg(target_family = "wasm")]
use crate::core::audit_error::AuditError;
#[cfg(target_family = "wasm")]
use crate::core::rpc::{HttpResponse, RpcRequest, RpcTransport};

#[cfg(target_family = "wasm")]
const GET_HEALTH_BODY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"getHealth"}"#;

#[cfg(target_family = "wasm")]
pub fn perform_healthcheck(endpoint: &RpcEndpoint) -> Result<HealthResult, CapabilityError> {
    let response = waki::Client::new()
        .post(endpoint.expose_to_http_adapter())
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .connect_timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .body(GET_HEALTH_BODY)
        .send()
        .map_err(|_| CapabilityError::RequestFailed)?;
    let status = response.status_code();

    let mut body = Vec::new();
    loop {
        let remaining = MAX_RESPONSE_BYTES + 1 - body.len();
        let chunk = response
            .chunk(remaining as u64)
            .map_err(|_| CapabilityError::ResponseReadFailed)?;
        match chunk {
            Some(bytes) => append_response_chunk(&mut body, &bytes)?,
            None => break,
        }
    }

    validate_get_health_response(status, &body)
}

#[cfg(any(target_family = "wasm", test))]
fn append_response_chunk(body: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CapabilityError> {
    if bytes.is_empty() {
        return Err(CapabilityError::ResponseReadFailed);
    }
    body.extend_from_slice(bytes);
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(CapabilityError::ResponseTooLarge);
    }
    Ok(())
}

#[cfg(target_family = "wasm")]
pub struct WasiRpcTransport<'a> {
    endpoint: &'a str,
}

#[cfg(target_family = "wasm")]
impl<'a> WasiRpcTransport<'a> {
    pub fn new(endpoint: &'a RpcEndpoint) -> Self {
        Self {
            endpoint: endpoint.expose_to_http_adapter(),
        }
    }
}

#[cfg(target_family = "wasm")]
impl RpcTransport for WasiRpcTransport<'_> {
    fn send(&mut self, request: &RpcRequest) -> Result<HttpResponse, AuditError> {
        let response = waki::Client::new()
            .post(self.endpoint)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .connect_timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
            .body(request.body.clone())
            .send()
            .map_err(|_| AuditError::Transport)?;
        let status = response.status_code();
        let mut body = Vec::new();
        loop {
            let remaining = request
                .response_limit
                .checked_add(1)
                .and_then(|limit| limit.checked_sub(body.len()))
                .ok_or(AuditError::ResponseTooLarge)?;
            let chunk = response
                .chunk(remaining as u64)
                .map_err(|_| AuditError::Transport)?;
            match chunk {
                Some(bytes) => {
                    append_audit_response_chunk(&mut body, &bytes, request.response_limit)?
                }
                None => break,
            }
        }
        Ok(HttpResponse { status, body })
    }
}

#[cfg(any(target_family = "wasm", test))]
fn append_audit_response_chunk(
    body: &mut Vec<u8>,
    bytes: &[u8],
    limit: usize,
) -> Result<(), crate::core::audit_error::AuditError> {
    if bytes.is_empty() {
        return Err(crate::core::audit_error::AuditError::Transport);
    }
    body.extend_from_slice(bytes);
    if body.len() > limit {
        return Err(crate::core::audit_error::AuditError::ResponseTooLarge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_response_chunk_fails_instead_of_spinning() {
        let mut body = Vec::new();
        assert_eq!(
            append_response_chunk(&mut body, &[]).unwrap_err(),
            CapabilityError::ResponseReadFailed
        );
        assert!(body.is_empty());

        assert_eq!(
            append_audit_response_chunk(&mut body, &[], 8).unwrap_err(),
            crate::core::audit_error::AuditError::Transport
        );
        assert!(body.is_empty());
    }

    #[test]
    fn audit_response_chunk_over_limit_is_rejected() {
        let mut body = vec![1, 2];
        assert_eq!(
            append_audit_response_chunk(&mut body, &[3, 4], 3).unwrap_err(),
            crate::core::audit_error::AuditError::ResponseTooLarge
        );
    }
}
