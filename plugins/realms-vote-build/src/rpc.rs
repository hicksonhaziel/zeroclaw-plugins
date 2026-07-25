//! Production-only bounded `wasi:http` transport.

#[cfg(target_family = "wasm")]
use std::time::Duration;

#[cfg(target_family = "wasm")]
use mandate_core::core::audit_error::AuditError;
#[cfg(target_family = "wasm")]
use mandate_core::core::health::RpcEndpoint;
#[cfg(target_family = "wasm")]
use mandate_core::core::limits::HTTP_TIMEOUT_SECS;
#[cfg(target_family = "wasm")]
use mandate_core::core::rpc::{HttpResponse, RpcRequest, RpcTransport};

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
            match response
                .chunk(remaining as u64)
                .map_err(|_| AuditError::Transport)?
            {
                Some(bytes) if bytes.is_empty() => return Err(AuditError::Transport),
                Some(bytes) => {
                    body.extend_from_slice(&bytes);
                    if body.len() > request.response_limit {
                        return Err(AuditError::ResponseTooLarge);
                    }
                }
                None => break,
            }
        }
        Ok(HttpResponse { status, body })
    }
}
