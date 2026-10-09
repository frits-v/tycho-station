//! The unit's control session: spawned through the vendor port and handed the task packet
//! reference through `Session::instruct`, never the packet's content.

use std::sync::Arc;

use restate_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use tycho_types::envelope::{ContentRef, ShortText};
use tycho_types::launcher::AwaitableId;
use tycho_types::service::WorkUnitId;
use tycho_types::session::SessionName;
use tycho_types::task_packet::{AbsolutePath, Effort};

use crate::services::session::{
    InstructRequest, InstructionRecord, SessionClient, SpawnOutcome, SpawnRequest,
};
use crate::services::spawner::SpawnTerminal;
use crate::services::{secret, CODE_BAD_REQUEST, CODE_CONFLICT, CODE_INTERNAL};
use crate::spawn::CLAUDE_SANDBOX_SETTINGS;
use crate::vendors::control::{ControlLaunch, PermissionMode, SessionVendor, VendorSessionId};

/// How the unit's control session runs; it is instructed with the packet before dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlStart {
    pub task_packet: ContentRef,
    pub model: ShortText,
    pub effort: Effort,
    pub permission: PermissionMode,
    pub working_dir: AbsolutePath,
}

/// The argv and resume handle the vendor port gives for the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ControlPlan {
    argv: Vec<ShortText>,
    resume_handle: ShortText,
}

fn failure(code: u16, message: impl Into<String>) -> TerminalError {
    TerminalError::new_with_code(code, message)
}

/// The instruction text: a reference to the packet in the store, within one `ShortText`.
pub fn packet_instruction(packet: &ContentRef) -> Result<ShortText, TerminalError> {
    ShortText::parse(&format!(
        "Task packet {packet}: read it from the factory store and answer through your handler."
    ))
    .map_err(|error| failure(CODE_BAD_REQUEST, error.to_string()))
}

fn plan(vendor: &dyn SessionVendor, launch: &ControlLaunch) -> Result<ControlPlan, TerminalError> {
    let command = vendor
        .control_command(launch)
        .map_err(|error| failure(CODE_BAD_REQUEST, error.to_string()))?;
    let argv = command
        .argv
        .iter()
        .map(|word| ShortText::parse(word))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| failure(CODE_BAD_REQUEST, format!("control argv: {error}")))?;
    let resume_handle = vendor
        .resume_handle(&launch.vendor_session)
        .map_err(|error| failure(CODE_BAD_REQUEST, error.to_string()))?;
    Ok(ControlPlan {
        argv,
        resume_handle,
    })
}

async fn spawn_request(
    workflow_context: &WorkflowContext<'_>,
    vendor: &Arc<dyn SessionVendor>,
    session: &SessionName,
    start: &ControlStart,
) -> Result<SpawnRequest, TerminalError> {
    let generated = workflow_context
        .run(|| async {
            let id = secret::generate().map_err(HandlerError::from)?;
            let session_secret = secret::generate().map_err(HandlerError::from)?;
            Ok(Json((
                id.expose().to_string(),
                session_secret.expose().to_string(),
            )))
        })
        .name("control session id and secret")
        .await?;
    let (id_hex, session_secret) = generated.into_inner();
    let vendor_session = VendorSessionId::from_hex(&id_hex)
        .map_err(|error| failure(CODE_INTERNAL, error.to_string()))?;
    let launch = ControlLaunch {
        session: session.clone(),
        vendor_session,
        model: start.model.to_string(),
        effort: start.effort,
        permission: start.permission,
        sandbox_settings: CLAUDE_SANDBOX_SETTINGS.to_string(),
        working_dir: start.working_dir.clone(),
        resume: false,
    };
    let control_plan = plan(vendor.as_ref(), &launch)?;
    let (awaitable_id, exit) = workflow_context.awakeable::<Json<serde_json::Value>>();
    // The unit does not wait for its control session to exit: the Session object and the
    // reconciler track it, and the launcher resolves this awaitable only at exit.
    drop(exit);
    Ok(SpawnRequest {
        argv: control_plan.argv,
        awaitable_id: AwaitableId::parse(&awaitable_id)
            .map_err(|error| failure(CODE_INTERNAL, error.to_string()))?,
        secret: session_secret,
        inbox_socket: None,
        resume_handle: Some(control_plan.resume_handle),
        terminal: SpawnTerminal::Inherit,
        working_dir: Some(start.working_dir.clone()),
    })
}

/// Spawns the control session under its own secret and instructs it with the packet reference.
pub async fn start_control(
    workflow_context: &WorkflowContext<'_>,
    vendor: &Arc<dyn SessionVendor>,
    unit_id: &WorkUnitId,
    session: &SessionName,
    start: &ControlStart,
) -> Result<InstructionRecord, TerminalError> {
    let request = spawn_request(workflow_context, vendor, session, start).await?;
    let session_secret = request.secret.clone();
    let spawned = workflow_context
        .object_client::<SessionClient>(session.to_string())
        .spawn(Json(request))
        .call()
        .await?
        .into_inner();
    if let SpawnOutcome::Requeue { reason } = spawned {
        return Err(failure(
            CODE_CONFLICT,
            format!("control session {session} is held: {reason:?}"),
        ));
    }
    let key = ShortText::parse(&format!("{unit_id}:task_packet:1"))
        .map_err(|error| failure(CODE_INTERNAL, error.to_string()))?;
    let instruction = InstructRequest {
        secret: session_secret,
        key,
        text: packet_instruction(&start.task_packet)?,
    };
    let record = workflow_context
        .object_client::<SessionClient>(session.to_string())
        .instruct(Json(instruction))
        .call()
        .await?
        .into_inner();
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vendors::claude_control::ClaudeControl;
    use std::path::PathBuf;

    fn launch() -> ControlLaunch {
        ControlLaunch {
            session: SessionName::parse("cf7a.wu03.ctl.claude").unwrap(),
            vendor_session: VendorSessionId::parse("56736586-cf23-4aaa-955f-7ea9c1fb1e15").unwrap(),
            model: "haiku".to_string(),
            effort: Effort::Low,
            permission: PermissionMode::DontAsk,
            sandbox_settings: CLAUDE_SANDBOX_SETTINGS.to_string(),
            working_dir: AbsolutePath::parse("/Users/agent/control/cf7a-wu03").unwrap(),
            resume: false,
        }
    }

    #[test]
    fn the_control_plan_is_the_vendor_argv_and_its_resume_handle() {
        let vendor = ClaudeControl::new(PathBuf::from("/opt/claude"), PathBuf::from("/c"));
        let control_plan = plan(&vendor, &launch()).unwrap();
        assert_eq!(control_plan.argv.len(), 13);
        assert_eq!(
            control_plan.resume_handle.as_str(),
            "56736586-cf23-4aaa-955f-7ea9c1fb1e15"
        );
        let mut minimal = launch();
        minimal.effort = Effort::Minimal;
        assert!(plan(&vendor, &minimal).is_err());
    }

    #[test]
    fn the_instruction_names_the_packet_and_fits_one_short_text() {
        let packet = ContentRef::parse(&format!("sha256:{}", "a".repeat(64))).unwrap();
        let text = packet_instruction(&packet).unwrap();
        assert!(text.as_str().contains(packet.as_str()));
    }

    #[test]
    fn a_control_start_refuses_unknown_fields() {
        let json = r#"{"task_packet":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","model":"haiku","effort":"low","permission":"dont_ask","working_dir":"/w","extra":1}"#;
        assert!(serde_json::from_str::<ControlStart>(json).is_err());
        let known = json.replace(r#","extra":1"#, "");
        assert!(serde_json::from_str::<ControlStart>(&known).is_ok());
    }
}
