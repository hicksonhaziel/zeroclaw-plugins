use std::collections::HashMap;

use realms_execution_audit::config::parse_host_execution;
use realms_execution_audit::core::limits::{
    MAX_ACTION_BYTES, MAX_ENDPOINT_BYTES, MAX_ERROR_OUTPUT_BYTES, MAX_EXECUTE_ARGS_BYTES,
    MAX_RESPONSE_BYTES, MAX_SUCCESS_OUTPUT_BYTES,
};
use realms_execution_audit::core::{
    validate_get_health_response, CapabilityError, HealthResult, RpcEndpoint, ToolAction,
};

const PUBLIC_RPC: &str = "https://api.devnet.solana.com";

fn envelope(action: &str, config: HashMap<&str, &str>) -> String {
    let config: HashMap<String, String> = config
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect();
    serde_json::json!({"action": action, "__config": config}).to_string()
}

#[test]
fn valid_configuration_is_converted_to_validated_types() {
    let parsed = parse_host_execution(&envelope(
        "healthcheck",
        HashMap::from([("rpc_url", PUBLIC_RPC)]),
    ))
    .unwrap();
    assert_eq!(parsed.action, ToolAction::Healthcheck);
}

#[test]
fn missing_rpc_url_is_rejected() {
    assert_eq!(
        parse_host_execution(&envelope("healthcheck", HashMap::new())).unwrap_err(),
        CapabilityError::MissingRpcUrl
    );
}

#[test]
fn empty_rpc_url_is_rejected() {
    assert_eq!(
        RpcEndpoint::parse("").unwrap_err(),
        CapabilityError::EmptyRpcUrl
    );
}

#[test]
fn non_https_rpc_url_is_rejected() {
    assert_eq!(
        RpcEndpoint::parse("http://api.devnet.solana.com").unwrap_err(),
        CapabilityError::RpcUrlNotHttps
    );
}

#[test]
fn oversized_rpc_url_is_rejected() {
    let value = format!("https://{}", "a".repeat(MAX_ENDPOINT_BYTES));
    assert!(value.len() > MAX_ENDPOINT_BYTES);
    assert_eq!(
        parse_host_execution(&envelope(
            "healthcheck",
            HashMap::from([("rpc_url", value.as_str())]),
        ))
        .unwrap_err(),
        CapabilityError::RpcUrlTooLarge
    );
}

#[test]
fn malformed_rpc_urls_are_rejected_without_echoing_them() {
    for value in [
        "https://",
        "https://user@example.com",
        "https://example.com/#fragment",
    ] {
        let error = RpcEndpoint::parse(value).unwrap_err();
        assert_eq!(error, CapabilityError::MalformedRpcUrl);
        assert!(!error.render().contains(value));
    }
}

#[test]
fn valid_get_health_response_is_accepted() {
    let body = br#"{"jsonrpc":"2.0","result":"ok","id":1}"#;
    assert_eq!(
        validate_get_health_response(200, body).unwrap(),
        HealthResult
    );
}

#[test]
fn invalid_json_is_rejected() {
    assert_eq!(
        validate_get_health_response(200, b"not-json").unwrap_err(),
        CapabilityError::InvalidJson
    );
}

#[test]
fn json_rpc_error_is_rejected() {
    let body = br#"{"jsonrpc":"2.0","error":{"code":-32000,"message":"no"},"id":1}"#;
    assert_eq!(
        validate_get_health_response(200, body).unwrap_err(),
        CapabilityError::RpcError
    );
}

#[test]
fn unexpected_result_is_rejected() {
    let body = br#"{"jsonrpc":"2.0","result":"behind","id":1}"#;
    assert_eq!(
        validate_get_health_response(200, body).unwrap_err(),
        CapabilityError::UnexpectedHealth
    );
}

#[test]
fn incomplete_or_unexpected_envelope_is_rejected() {
    for body in [
        br#"{"jsonrpc":"2.0","result":"ok"}"#.as_slice(),
        br#"{"jsonrpc":"2.0","result":"ok","id":2}"#.as_slice(),
        br#"{"jsonrpc":"2.0","result":"ok","id":1,"extra":true}"#.as_slice(),
    ] {
        assert_eq!(
            validate_get_health_response(200, body).unwrap_err(),
            CapabilityError::InvalidRpcEnvelope
        );
    }
}

#[test]
fn non_success_http_status_is_rejected_before_body_parsing() {
    assert_eq!(
        validate_get_health_response(503, b"service unavailable").unwrap_err(),
        CapabilityError::HttpStatus
    );
}

#[test]
fn oversized_response_is_rejected() {
    let body = vec![b' '; MAX_RESPONSE_BYTES + 1];
    assert_eq!(
        validate_get_health_response(200, &body).unwrap_err(),
        CapabilityError::ResponseTooLarge
    );
}

#[test]
fn success_rendering_is_deterministic_and_bounded() {
    let rendered = HealthResult.render();
    assert_eq!(
        rendered,
        "status=ok\nconfig=validated\nhttps=ok\nrpc_health=ok"
    );
    assert!(rendered.len() <= MAX_SUCCESS_OUTPUT_BYTES);
}

#[test]
fn every_error_rendering_is_bounded() {
    let errors = [
        CapabilityError::InputTooLarge,
        CapabilityError::ActionTooLarge,
        CapabilityError::MalformedInput,
        CapabilityError::UnsupportedAction,
        CapabilityError::MissingRpcUrl,
        CapabilityError::EmptyRpcUrl,
        CapabilityError::RpcUrlTooLarge,
        CapabilityError::RpcUrlNotHttps,
        CapabilityError::MalformedRpcUrl,
        CapabilityError::RequestFailed,
        CapabilityError::ResponseReadFailed,
        CapabilityError::HttpStatus,
        CapabilityError::ResponseTooLarge,
        CapabilityError::InvalidJson,
        CapabilityError::RpcError,
        CapabilityError::InvalidRpcEnvelope,
        CapabilityError::UnexpectedHealth,
    ];
    for error in errors {
        assert!(error.render().len() <= MAX_ERROR_OUTPUT_BYTES);
    }
}

#[test]
fn unknown_action_is_rejected() {
    assert_eq!(
        parse_host_execution(&envelope("audit", HashMap::from([("rpc_url", PUBLIC_RPC)]),))
            .unwrap_err(),
        CapabilityError::UnsupportedAction
    );
}

#[test]
fn malformed_and_missing_action_inputs_reach_the_production_parser() {
    for input in [
        "{",
        "{}",
        r#"{"action":1,"__config":{"rpc_url":"https://api.devnet.solana.com"}}"#,
    ] {
        assert_eq!(
            parse_host_execution(input).unwrap_err(),
            CapabilityError::MalformedInput
        );
    }
}

#[test]
fn oversized_execute_envelope_is_rejected_before_json_parsing() {
    let input = "x".repeat(MAX_EXECUTE_ARGS_BYTES + 1);
    assert_eq!(
        parse_host_execution(&input).unwrap_err(),
        CapabilityError::InputTooLarge
    );
}

#[test]
fn oversized_action_is_rejected_through_the_production_parser() {
    let input = envelope(
        &"x".repeat(MAX_ACTION_BYTES + 1),
        HashMap::from([("rpc_url", PUBLIC_RPC)]),
    );
    assert_eq!(
        parse_host_execution(&input).unwrap_err(),
        CapabilityError::ActionTooLarge
    );
}

#[test]
fn production_parser_rejects_top_level_tool_call_configuration() {
    let input = serde_json::json!({
        "action": "healthcheck",
        "rpc_url": "https://attacker.invalid",
        "__config": {"rpc_url": PUBLIC_RPC}
    })
    .to_string();
    assert_eq!(
        parse_host_execution(&input).unwrap_err(),
        CapabilityError::MalformedInput
    );
}

#[test]
fn outputs_never_contain_the_configured_rpc_url() {
    let endpoint = "https://rpc.example.invalid/path?api-key=FAKE-API-KEY-12345";
    let parsed = RpcEndpoint::parse(endpoint).unwrap();
    let debug = format!("{parsed:?}");
    assert_eq!(debug, "RpcEndpoint(<redacted>)");
    assert!(!debug.contains(endpoint));
    assert!(!debug.contains("api-key"));
    assert!(!debug.contains("FAKE-API-KEY-12345"));

    let execution = parse_host_execution(&envelope(
        "healthcheck",
        HashMap::from([("rpc_url", endpoint)]),
    ))
    .unwrap();
    let execution_debug = format!("{execution:?}");
    assert!(!execution_debug.contains(endpoint));
    assert!(!execution_debug.contains("api-key"));
    assert!(!execution_debug.contains("FAKE-API-KEY-12345"));

    assert!(!HealthResult.render().contains(endpoint));
    for error in [CapabilityError::RequestFailed, CapabilityError::RpcError] {
        assert!(!error.render().contains(endpoint));
    }
}

#[test]
fn execute_envelope_rejects_unexpected_caller_fields() {
    let input = serde_json::json!({
        "action": "healthcheck",
        "rpc_url": "https://attacker.invalid",
        "__config": {"rpc_url": PUBLIC_RPC}
    })
    .to_string();
    assert_eq!(
        parse_host_execution(&input).unwrap_err(),
        CapabilityError::MalformedInput
    );
}
