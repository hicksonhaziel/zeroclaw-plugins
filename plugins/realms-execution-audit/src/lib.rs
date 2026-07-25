//! Bounded read-only Realms execution reconstruction for Mandate.
//!
//! The component exposes the established healthcheck and dispatches a versioned
//! audit request into a shared transport-independent orchestration service.
//! Supported System and classic SPL Token instructions receive deterministic
//! findings; unsupported or malformed instructions remain unresolved. Pure
//! logic lives in [`core`]; this file remains the thin WIT adapter.

pub mod config;
pub mod rpc;
pub use mandate_core::core;

use crate::core::audit::{run_audit, AuditOutcome};
use crate::core::audit_error::AuditError;
use crate::core::output::render_audit_outcome;
use crate::core::pubkey::Pubkey;
use crate::core::rpc::RpcTransport;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditDispatch {
    pub outcome: AuditOutcome,
    pub output: String,
}

/// Shared audit dispatch used by both the WIT entry point and deterministic
/// mocked component tests.
pub fn execute_audit_with_transport<T: RpcTransport>(
    proposal: Pubkey,
    transport: &mut T,
) -> Result<AuditDispatch, AuditError> {
    let outcome = run_audit(transport, proposal);
    let output = render_audit_outcome(&outcome)?;
    Ok(AuditDispatch { outcome, output })
}

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::config::parse_host_execution;
    use crate::core::audit::AuditOutcome;
    use crate::core::limits::{MAX_ACTION_BYTES, MAX_PROPOSAL_ADDRESS_BYTES};
    use crate::core::{CapabilityError, ToolAction};
    use crate::rpc::{perform_healthcheck, WasiRpcTransport};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "realms-execution-audit";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "realms_execution_audit";

    struct RealmsExecutionAudit;

    impl PluginInfo for RealmsExecutionAudit {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_owned()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_owned()
        }
    }

    impl Tool for RealmsExecutionAudit {
        fn name() -> String {
            TOOL_NAME.to_owned()
        }

        fn description() -> String {
            "Runs a healthcheck or bounded read-only Realms execution audit. Returns fingerprints and deterministic findings for supported System and classic SPL Token instructions; unsupported effects remain unresolved."
                .to_owned()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "oneOf": [
                    {
                        "type": "object",
                        "properties": {
                            "action": {
                                "type": "string",
                                "const": "healthcheck",
                                "maxLength": MAX_ACTION_BYTES
                            }
                        },
                        "required": ["action"],
                        "additionalProperties": false
                    },
                    {
                        "type": "object",
                        "properties": {
                            "action": {
                                "type": "string",
                                "const": "audit",
                                "maxLength": MAX_ACTION_BYTES
                            },
                            "schema_version": {"type": "integer", "const": 1},
                            "proposal": {
                                "type": "string",
                                "maxLength": MAX_PROPOSAL_ADDRESS_BYTES,
                                "description": "Full canonical base58 proposal public key."
                            }
                        },
                        "required": ["action", "schema_version", "proposal"],
                        "additionalProperties": false
                    }
                ]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let execution = match parse_host_execution(&args) {
                Ok(execution) => execution,
                Err(error) => return Ok(failure(error)),
            };

            let result = match execution.action {
                ToolAction::Healthcheck => perform_healthcheck(&execution.endpoint),
                ToolAction::Audit { proposal, .. } => {
                    let mut transport = WasiRpcTransport::new(&execution.endpoint);
                    let dispatch =
                        match crate::execute_audit_with_transport(proposal, &mut transport) {
                            Ok(dispatch) => dispatch,
                            Err(_) => {
                                emit(
                                    LogLevel::Warn,
                                    PluginAction::Fail,
                                    PluginOutcome::Failure,
                                    "Bounded Realms audit output failed",
                                    "{\"operation\":\"audit\",\"retrieval_status\":\"failed\"}",
                                );
                                return Ok(ToolResult {
                                    success: false,
                                    output: String::new(),
                                    error: Some("error=audit_output_failed".to_owned()),
                                });
                            }
                        };
                    let success = !matches!(dispatch.outcome, AuditOutcome::Failed(_));
                    let status = match &dispatch.outcome {
                        AuditOutcome::Complete(_) => "complete",
                        AuditOutcome::Incomplete(_) => "incomplete",
                        AuditOutcome::Failed(_) => "failed",
                    };
                    let attrs =
                        format!("{{\"operation\":\"audit\",\"retrieval_status\":\"{status}\"}}");
                    emit(
                        if success {
                            LogLevel::Info
                        } else {
                            LogLevel::Warn
                        },
                        if success {
                            PluginAction::Complete
                        } else {
                            PluginAction::Fail
                        },
                        if success {
                            PluginOutcome::Success
                        } else {
                            PluginOutcome::Failure
                        },
                        "Bounded Realms execution audit completed",
                        &attrs,
                    );
                    return Ok(ToolResult {
                        success,
                        output: dispatch.output,
                        error: if success {
                            None
                        } else {
                            Some("error=audit_retrieval_failed".to_owned())
                        },
                    });
                }
            };
            match result {
                Ok(health) => {
                    emit(
                        LogLevel::Info,
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "Capability healthcheck completed",
                        "{\"operation\":\"healthcheck\"}",
                    );
                    Ok(ToolResult {
                        success: true,
                        output: health.render().to_owned(),
                        error: None,
                    })
                }
                Err(error) => Ok(failure(error)),
            }
        }
    }

    fn failure(error: CapabilityError) -> ToolResult {
        let attrs = format!("{{\"error_code\":\"{}\"}}", error.code());
        emit(
            LogLevel::Warn,
            PluginAction::Fail,
            PluginOutcome::Failure,
            "Capability healthcheck failed",
            &attrs,
        );
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(error.render()),
        }
    }

    fn emit(
        level: LogLevel,
        action: PluginAction,
        outcome: PluginOutcome,
        message: &str,
        attrs: &str,
    ) {
        log_record(
            level,
            &PluginEvent {
                function_name: "realms_execution_audit::tool::execute".to_owned(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: Some(attrs.to_owned()),
                message: message.to_owned(),
            },
        );
    }

    export!(RealmsExecutionAudit);
}
