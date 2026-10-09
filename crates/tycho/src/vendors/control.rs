//! The `SessionVendor` port for interactive control sessions: the command that starts or
//! resumes one, an instruction posted into a running one, what it is doing, and how much
//! context it holds.

use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tycho_types::envelope::ShortText;
use tycho_types::session::{SessionName, Vendor};
use tycho_types::task_packet::{AbsolutePath, Effort};

use crate::launch_spec::VendorTerminal;

pub const MODEL_NAME_MAX_BYTES: usize = 64;
/// Vendor text kept in a decoded state, such as an unknown status word or a refusal.
pub const VENDOR_TEXT_MAX_BYTES: usize = 160;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VendorError {
    Argument(String),
    Unsupported(&'static str),
}

impl fmt::Display for VendorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Argument(reason) => write!(formatter, "control session argument: {reason}"),
            Self::Unsupported(reason) => write!(formatter, "not supported: {reason}"),
        }
    }
}

impl std::error::Error for VendorError {}

/// Cuts vendor text to `VENDOR_TEXT_MAX_BYTES` on a character boundary.
#[must_use]
pub fn bounded(text: &str) -> String {
    let mut end = text.len().min(VENDOR_TEXT_MAX_BYTES);
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    text.get(..end).unwrap_or_default().to_string()
}

pub use crate::vendors::worker::VendorSessionId;

/// The permission modes a control session may run in; bypassing prompts is never offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionMode {
    /// Every unapproved tool use waits for a person at the prompt.
    Manual,
    AcceptEdits,
    /// Anything not allowed by a rule is denied without a prompt.
    DontAsk,
    Plan,
}

/// What starts or resumes one control session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlLaunch {
    pub session: SessionName,
    pub vendor_session: VendorSessionId,
    pub model: String,
    pub effort: Effort,
    pub permission: PermissionMode,
    /// The sandbox object the launch spec carries, as JSON.
    pub sandbox_settings: String,
    pub working_dir: AbsolutePath,
    /// Resume the vendor session instead of starting it.
    pub resume: bool,
}

/// The vendor command and how the launcher runs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlCommand {
    pub argv: Vec<String>,
    pub terminal: VendorTerminal,
    pub working_dir: PathBuf,
}

/// What became of one instruction; once `written`, nothing may deliver it again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Delivery {
    /// Written; the vendor closed the connection without a reply, as it always does.
    Posted {
        socket: String,
    },
    /// Written; the connection stayed open past the read timeout.
    PostedUnclosed {
        socket: String,
    },
    /// Some or all bytes were written, then the write or the half-close failed.
    WriteInterrupted {
        socket: String,
        sent: usize,
        reason: String,
    },
    /// Written; the vendor answered with bytes no observed version sends.
    Replied {
        socket: String,
        reply: String,
    },
    /// Left in the session's relay directory for its launcher to post as the vendor user.
    Relayed {
        file: String,
    },
    /// No running process of the vendor holds this session id.
    NoSession,
    /// The session's registry entry or the directory holding it could not be read.
    Unreadable {
        reason: String,
    },
    NoSocket {
        socket: String,
    },
    Refused {
        socket: String,
    },
    /// The socket belongs to another user: the vendor restricts it to its own.
    Denied {
        socket: String,
    },
    /// Nothing was written before the write failed.
    WriteFailed {
        socket: String,
        reason: String,
    },
    /// The socket refused the core and the relay could not take the instruction either.
    RelayFailed {
        reason: String,
    },
    /// The registry named a socket outside the vendor's directory, name or owner; nothing was
    /// connected.
    Untrusted {
        reason: String,
    },
    Unrecognised {
        reason: String,
    },
}

impl Delivery {
    /// True when the instruction may have reached the vendor or is held by the relay.
    #[must_use]
    pub const fn written(&self) -> bool {
        match self {
            Self::Posted { .. }
            | Self::PostedUnclosed { .. }
            | Self::WriteInterrupted { .. }
            | Self::Replied { .. }
            | Self::Relayed { .. } => true,
            Self::NoSession
            | Self::Unreadable { .. }
            | Self::NoSocket { .. }
            | Self::Refused { .. }
            | Self::Denied { .. }
            | Self::WriteFailed { .. }
            | Self::RelayFailed { .. }
            | Self::Untrusted { .. }
            | Self::Unrecognised { .. } => false,
        }
    }
}

/// The zmx session and the vendor session one instruction is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressTarget {
    pub session: SessionName,
    pub vendor_session: VendorSessionId,
}

/// Why a waiting session waits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "for", content = "text", rename_all = "snake_case")]
pub enum WaitingFor {
    PermissionPrompt,
    Unrecognised(String),
}

/// What a running control session is doing, from the vendor's session registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Observation {
    Idle { pid: u32 },
    Busy { pid: u32 },
    Waiting { pid: u32, waiting_for: WaitingFor },
    Absent,
    Unreadable { reason: String },
    Unrecognised { reason: String },
}

/// The context a session holds after its last turn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ContextReport {
    Tokens { tokens: u64 },
    NoTurnYet,
    Absent,
    Unreadable { reason: String },
    Unrecognised { reason: String },
}

/// Blocking calls; services run them off the async runtime inside journaled steps.
pub trait SessionVendor: Send + Sync + 'static {
    fn describe(&self) -> String;
    /// Whether this port runs control sessions of the vendor.
    fn serves(&self, vendor: Vendor) -> bool;
    /// The command for a fresh or resumed control session; the sandbox is passed every time.
    fn control_command(&self, launch: &ControlLaunch) -> Result<ControlCommand, VendorError>;
    /// Posts to the session's inbox, or relays it under the key when the socket refuses the core.
    fn address(&self, target: &AddressTarget, key: &ShortText, instruction: &ShortText)
        -> Delivery;
    fn observe(&self, session: &VendorSessionId) -> Observation;
    /// The handle a later `control_command` with `resume` takes.
    fn resume_handle(&self, session: &VendorSessionId) -> Result<ShortText, VendorError>;
    fn context_size(&self, session: &VendorSessionId) -> ContextReport;
    /// Removes what the port keeps for a session that was killed or reaped.
    fn release(&self, session: &SessionName) -> Result<(), String>;
}

/// The production stand-in until a control vendor is installed: every call is refused.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoVendor;

const NO_VENDOR: &str = "no control session vendor is installed in this endpoint";

impl SessionVendor for NoVendor {
    fn describe(&self) -> String {
        "no vendor".to_string()
    }

    fn serves(&self, _vendor: Vendor) -> bool {
        false
    }

    fn control_command(&self, _launch: &ControlLaunch) -> Result<ControlCommand, VendorError> {
        Err(VendorError::Unsupported(NO_VENDOR))
    }

    fn address(
        &self,
        _target: &AddressTarget,
        _key: &ShortText,
        _instruction: &ShortText,
    ) -> Delivery {
        Delivery::Unrecognised {
            reason: NO_VENDOR.to_string(),
        }
    }

    fn observe(&self, _session: &VendorSessionId) -> Observation {
        Observation::Unreadable {
            reason: NO_VENDOR.to_string(),
        }
    }

    fn resume_handle(&self, _session: &VendorSessionId) -> Result<ShortText, VendorError> {
        Err(VendorError::Unsupported(NO_VENDOR))
    }

    fn context_size(&self, _session: &VendorSessionId) -> ContextReport {
        ContextReport::Unreadable {
            reason: NO_VENDOR.to_string(),
        }
    }

    fn release(&self, _session: &SessionName) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_unwritten_instruction_falls_back() {
        let socket = "/tmp/cc-socks/1.sock".to_string();
        let written = [
            Delivery::Posted {
                socket: socket.clone(),
            },
            Delivery::PostedUnclosed {
                socket: socket.clone(),
            },
            Delivery::Replied {
                socket: socket.clone(),
                reply: "x".to_string(),
            },
            Delivery::WriteInterrupted {
                socket: socket.clone(),
                sent: 1,
                reason: "broken pipe".to_string(),
            },
            Delivery::Relayed {
                file: "a.json".to_string(),
            },
        ];
        let unwritten = [
            Delivery::NoSession,
            Delivery::Unreadable {
                reason: "r".to_string(),
            },
            Delivery::NoSocket {
                socket: socket.clone(),
            },
            Delivery::Refused {
                socket: socket.clone(),
            },
            Delivery::Denied {
                socket: socket.clone(),
            },
            Delivery::WriteFailed {
                socket,
                reason: "broken pipe".to_string(),
            },
            Delivery::RelayFailed {
                reason: "r".to_string(),
            },
            Delivery::Untrusted {
                reason: "r".to_string(),
            },
            Delivery::Unrecognised {
                reason: "r".to_string(),
            },
        ];
        assert!(written.iter().all(Delivery::written));
        assert!(!unwritten.iter().any(Delivery::written));
    }

    #[test]
    fn vendor_text_is_bounded_on_a_character_boundary() {
        let long = "é".repeat(VENDOR_TEXT_MAX_BYTES);
        let cut = bounded(&long);
        assert!(cut.len() <= VENDOR_TEXT_MAX_BYTES);
        assert!(cut.chars().all(|character| character == 'é'));
    }
}
