//! T1 build-only policy-controlled unsigned Realms vote component.
//!
//! This component never accepts private material, signs, submits, or exposes
//! arbitrary instructions. It reuses the single shared Mandate audit service.

pub mod config;
pub mod rpc;

pub use mandate_core::core;

use core::rpc::RpcTransport;
use core::vote::VoteBuildError;
use core::vote_service::{run_vote_build, VoteBuildComplete, VoteBuildRequest};

pub fn execute_with_transport<T: RpcTransport>(
    request: VoteBuildRequest,
    transport: &mut T,
) -> Result<VoteBuildComplete, VoteBuildError> {
    run_vote_build(transport, request)
}

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::config::parse_host_execution;
    use crate::rpc::WasiRpcTransport;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct RealmsVoteBuild;

    impl PluginInfo for RealmsVoteBuild {
        fn plugin_name() -> String {
            "realms-vote-build".to_owned()
        }

        fn plugin_version() -> String {
            env!("CARGO_PKG_VERSION").to_owned()
        }
    }

    impl Tool for RealmsVoteBuild {
        fn name() -> String {
            "realms_vote_build".to_owned()
        }

        fn description() -> String {
            "T1 build-only: re-audits a Realms proposal and, after policy and fingerprint checks, builds one unsigned, unsubmitted SPL Governance Deny vote for external signing. Always require human approval before calling."
                .to_owned()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type":"object",
                "properties":{
                    "action":{"type":"string","const":"build_vote"},
                    "schema_version":{"type":"integer","const":1},
                    "proposal":{"type":"string","maxLength":44},
                    "governing_token_owner":{"type":"string","maxLength":44},
                    "governance_authority":{"type":"string","maxLength":44},
                    "payer":{"type":"string","maxLength":44},
                    "vote":{"type":"string","enum":["deny","approve"]},
                    "expected_execution_fingerprint":{
                        "type":"string",
                        "pattern":"^sha256:[0-9a-f]{64}$"
                    }
                },
                "required":[
                    "action","schema_version","proposal","governing_token_owner",
                    "governance_authority","payer","vote",
                    "expected_execution_fingerprint"
                ],
                "additionalProperties":false
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let execution = match parse_host_execution(&args) {
                Ok(value) => value,
                Err(error) => return Ok(failure(error)),
            };
            let mut transport = WasiRpcTransport::new(&execution.endpoint);
            match crate::execute_with_transport(execution.request, &mut transport) {
                Ok(complete) => {
                    emit(
                        LogLevel::Info,
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "Unsigned Deny vote built for external signing",
                        "{\"operation\":\"build_vote\",\"custody\":\"t1_unsigned\",\"submitted\":false}",
                    );
                    Ok(ToolResult {
                        success: true,
                        output: complete.output,
                        error: None,
                    })
                }
                Err(error) => Ok(failure(error)),
            }
        }
    }

    fn failure(error: crate::core::vote::VoteBuildError) -> ToolResult {
        emit(
            LogLevel::Warn,
            PluginAction::Fail,
            PluginOutcome::Failure,
            "Unsigned vote build refused",
            "{\"operation\":\"build_vote\",\"submitted\":false}",
        );
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(format!("error={}", error.code())),
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
                function_name: "realms_vote_build::tool::execute".to_owned(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: Some(attrs.to_owned()),
                message: message.to_owned(),
            },
        );
    }

    export!(RealmsVoteBuild);
}
