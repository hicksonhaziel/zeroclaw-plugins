use crate::core::audit_error::AuditError;

use super::RpcRequest;

pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

pub trait RpcTransport {
    fn send(&mut self, request: &RpcRequest) -> Result<HttpResponse, AuditError>;
}
