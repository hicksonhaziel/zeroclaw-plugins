//! Phase 1 capability scaffold for Mandate's future Realms execution auditor.
//!
//! This component intentionally performs no governance work. Its only operation
//! proves the production boundary: strict tool input, host-only configuration,
//! bounded HTTPS, strict response validation, structured logging, and bounded
//! output. Pure logic lives in [`core`]; this file is the thin WIT adapter.

pub mod config;
pub mod core;
pub mod rpc;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::config::parse_host_execution;
    use crate::core::limits::MAX_ACTION_BYTES;
    use crate::core::{CapabilityError, ToolAction};
    use crate::rpc::perform_healthcheck;
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
            "Phase 1 capability scaffold only. Runs a bounded, read-only Solana RPC healthcheck; it does not audit governance proposals."
                .to_owned()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["healthcheck"],
                        "maxLength": MAX_ACTION_BYTES,
                        "description": "Run the Phase 1 bounded capability healthcheck."
                    }
                },
                "required": ["action"],
                "additionalProperties": false
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
            };
            match result {
                Ok(health) => {
                    emit(
                        LogLevel::Info,
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "Phase 1 capability healthcheck completed",
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
            "Phase 1 capability healthcheck failed",
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
