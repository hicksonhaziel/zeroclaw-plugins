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
    }
}
