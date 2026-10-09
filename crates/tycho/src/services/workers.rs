//! What a work unit and its worker runs need for headless workers: the canonical repository,
//! the worktree clone, the graph index, the worker command and the checkpoint a result leaves.

use std::fmt;
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tycho_types::envelope::CommitSha;
use tycho_types::service::{Attempt, WorkUnitId};
use tycho_types::session::{SessionName, Vendor};
use tycho_types::task_packet::Effort;

use crate::code_graph::{BuildReport, Checkout, CodeGraph, GraphError, StepKey};
use crate::repositories::{ProjectName, Repositories, Worktree};
use crate::vendors::worker::{ModelName, VendorSessionId, WorkerArgs};

/// The headless worker side of the ports; absent, worker runs take the request's argv as is.
pub struct WorkerPorts {
    pub repositories: Repositories,
    pub graph: Arc<dyn CodeGraph>,
    pub project: ProjectName,
    /// The `tycho` binary the launcher runs as the worker's vendor command.
    pub tycho: PathBuf,
    pub claude: PathBuf,
    pub codex: PathBuf,
}

impl fmt::Debug for WorkerPorts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkerPorts")
            .field("repositories", &self.repositories)
            .field("project", &self.project)
            .field("tycho", &self.tycho)
            .finish_non_exhaustive()
    }
}

impl WorkerPorts {
    #[must_use]
    pub fn binary(&self, vendor: Vendor) -> Option<&Path> {
        match vendor {
            Vendor::Claude => Some(&self.claude),
            Vendor::Codex => Some(&self.codex),
            Vendor::Antigravity | Vendor::Amp | Vendor::OpenCode => None,
        }
    }
}

/// Where a unit attempt placed its worker: the worktree and the control session it answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerPlacement {
    pub worktree: Worktree,
    pub control: SessionName,
}

impl WorkerPlacement {
    /// The placement for the next task of the attempt, based on the head the last one left.
    #[must_use]
    pub fn after(&self, head: &CommitSha) -> Self {
        Self {
            worktree: Worktree {
                base: head.clone(),
                ..self.worktree.clone()
            },
            control: self.control.clone(),
        }
    }
}

/// Bytes a brief may hold; it is journaled with the task, so it stays small.
pub const BRIEF_MAX_BYTES: usize = 8192;

/// A worker's brief: up to 8 KiB of text, newlines allowed, no other control characters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Brief(String);

impl Brief {
    pub fn parse(text: &str) -> Result<Self, String> {
        if text.is_empty() || text.len() > BRIEF_MAX_BYTES {
            return Err(format!(
                "a brief is 1..={BRIEF_MAX_BYTES} bytes, not {}",
                text.len()
            ));
        }
        if let Some(control) = text.chars().find(|c| c.is_control() && *c != '\n') {
            return Err(format!("a brief holds the control character {control:?}"));
        }
        Ok(Self(text.to_string()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Brief {
    type Error = String;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<Brief> for String {
    fn from(value: Brief) -> Self {
        value.0
    }
}

/// A headless task in the plan; the unit adds the placement before the worker run starts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerTaskRequest {
    /// The brief the worker receives on stdin.
    pub brief: Brief,
    pub max_turns: Option<NonZeroU16>,
    #[serde(default)]
    pub placement: Option<WorkerPlacement>,
}

/// What a completed worker run reports besides its result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerEvidence {
    pub session: SessionName,
    pub resume_handle: Option<String>,
    /// `None` when the session has no view to read it from.
    pub context_tokens: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexKind {
    Build,
    Rebuild,
}

/// One graph index build of a unit's worktree, as the evaluation harness records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexRecord {
    pub kind: IndexKind,
    pub step_key: String,
    pub commit: Option<String>,
    pub wall_clock_ms: Option<u64>,
    pub cache_hit: Option<bool>,
    /// Why the build failed; the index is off the worker's path, so a failure never stops it.
    pub failure: Option<String>,
}

impl IndexRecord {
    #[must_use]
    pub fn from_build(
        kind: IndexKind,
        key: &StepKey,
        built: Result<BuildReport, GraphError>,
    ) -> Self {
        match built {
            Ok(report) => {
                let time = report.index_time();
                Self {
                    kind,
                    step_key: time.step_key,
                    commit: Some(time.commit),
                    wall_clock_ms: Some(time.wall_clock_ms),
                    cache_hit: Some(time.cache_hit),
                    failure: None,
                }
            }
            Err(error) => Self {
                kind,
                step_key: key.as_str().to_string(),
                commit: None,
                wall_clock_ms: None,
                cache_hit: None,
                failure: Some(error.to_string()),
            },
        }
    }
}

/// The checkpoint payload of design section 7, recorded when a worker's result arrives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub sequence: u32,
    pub commit: CommitSha,
    pub pin_ref: String,
    pub worktree: PathBuf,
    pub resume_handle: Option<String>,
    pub session: Option<String>,
    pub context_tokens: Option<u64>,
    pub reason: String,
}

/// `<unit>.a<attempt>.<what>`, the step key a graph build is journaled and reported under.
pub fn graph_key(unit: &WorkUnitId, attempt: Attempt, what: &str) -> Result<StepKey, String> {
    StepKey::parse(&format!("{unit}.a{}.{what}", attempt.get())).map_err(|error| error.to_string())
}

/// Builds the index of a fresh clone, or rebuilds it after a commit; never fails the step.
/// The worktree is the core's own path, checked level by level just before the graph runs.
#[must_use]
pub fn index(
    graph: &dyn CodeGraph,
    repositories: &Repositories,
    kind: IndexKind,
    key: &StepKey,
    unit: &WorkUnitId,
    worktree: &Path,
) -> IndexRecord {
    let built = repositories
        .check_worktree(worktree)
        .map_err(|error| GraphError::CannotPrepare(worktree.to_path_buf(), error.to_string()))
        .and_then(|()| Checkout::parse(worktree).map_err(GraphError::from))
        .and_then(|checkout| match kind {
            IndexKind::Build => graph.build(key, unit, &checkout),
            IndexKind::Rebuild => graph.rebuild(key, unit, &checkout),
        });
    IndexRecord::from_build(kind, key, built)
}

/// One worker attempt's command inputs, decided by the run.
#[derive(Debug, Clone)]
pub struct WorkerCommand<'a> {
    pub task: &'a WorkerTaskRequest,
    pub vendor: Vendor,
    pub session: &'a SessionName,
    pub model: &'a str,
    pub effort: Effort,
    pub session_id: &'a VendorSessionId,
}

/// Writes the brief beside the worktrees and returns the launcher's vendor command.
pub fn worker_command(
    ports: &WorkerPorts,
    command: &WorkerCommand<'_>,
) -> Result<Vec<String>, String> {
    let placement = command
        .task
        .placement
        .as_ref()
        .ok_or_else(|| "a headless task without a placement".to_string())?;
    let binary = ports
        .binary(command.vendor)
        .ok_or_else(|| format!("no headless binary for {}", command.vendor.as_str()))?;
    let brief = ports
        .repositories
        .write_brief(command.session, command.task.brief.as_str().as_bytes())
        .map_err(|error| error.to_string())?;
    let args = WorkerArgs {
        vendor: command.vendor,
        binary: binary.to_path_buf(),
        brief,
        worktree: placement.worktree.path.clone(),
        model: ModelName::parse(command.model).map_err(|error| error.to_string())?,
        effort: command.effort,
        max_turns: command.task.max_turns,
        session_id: command.session_id.clone(),
        to: placement.control.clone(),
        branch: placement.worktree.branch.clone(),
        base: placement.worktree.base.clone(),
    };
    Ok(args.to_argv(&ports.tycho))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_graph::{Completeness, GraphCounts};
    use crate::repositories::tests::{fixture, Scratch};
    use crate::repositories::unit_branch;
    use std::sync::Mutex;
    use std::time::Duration;

    /// Records each build and rebuild in order, and answers with a fixed report.
    #[derive(Default)]
    struct RecordingGraph {
        calls: Mutex<Vec<String>>,
    }

    impl RecordingGraph {
        fn report(key: &StepKey, unit: &WorkUnitId, checkout: &Checkout) -> BuildReport {
            BuildReport {
                key: key.clone(),
                work_unit: unit.clone(),
                checkout: checkout.clone(),
                index_dir: PathBuf::from("/index"),
                plugin_version: "v0.4.0".to_string(),
                commit: "abc".to_string(),
                wall_clock: Duration::from_millis(1500),
                tool_latency_ms: 1400,
                cache_hit: false,
                counts: GraphCounts {
                    files: 3,
                    parsed_files: 3,
                    symbols: 9,
                    relations: 4,
                    partial_failures: 0,
                },
                completeness: Completeness::Complete,
            }
        }

        fn record(&self, call: String) {
            self.calls.lock().unwrap().push(call);
        }
    }

    impl CodeGraph for RecordingGraph {
        fn build(
            &self,
            key: &StepKey,
            unit: &WorkUnitId,
            checkout: &Checkout,
        ) -> Result<BuildReport, GraphError> {
            self.record(format!("build {} {}", key.as_str(), checkout.as_str()));
            Ok(Self::report(key, unit, checkout))
        }

        fn rebuild(
            &self,
            key: &StepKey,
            _unit: &WorkUnitId,
            checkout: &Checkout,
        ) -> Result<BuildReport, GraphError> {
            self.record(format!("rebuild {} {}", key.as_str(), checkout.as_str()));
            Err(GraphError::EmptyIndex)
        }

        fn definitions(
            &self,
            _: &StepKey,
            _: &Checkout,
            _: &crate::code_graph::Symbol,
        ) -> Result<crate::code_graph::QueryReport<crate::code_graph::Definitions>, GraphError>
        {
            Err(GraphError::EmptyIndex)
        }

        fn callers(
            &self,
            _: &StepKey,
            _: &Checkout,
            _: &crate::code_graph::Symbol,
        ) -> Result<crate::code_graph::QueryReport<crate::code_graph::Callers>, GraphError>
        {
            Err(GraphError::EmptyIndex)
        }

        fn impact(
            &self,
            _: &StepKey,
            _: &Checkout,
            _: &crate::code_graph::Revision,
            _: &[crate::code_graph::RepoPath],
        ) -> Result<crate::code_graph::QueryReport<crate::code_graph::Impact>, GraphError> {
            Err(GraphError::EmptyIndex)
        }
    }

    fn unit() -> WorkUnitId {
        WorkUnitId::parse("wu01").unwrap()
    }

    #[test]
    fn the_index_is_built_on_the_clone_and_a_failed_rebuild_is_recorded_not_raised() {
        let scratch = Scratch::new("clone-then-build");
        let (repositories, project) = fixture(&scratch);
        let graph = RecordingGraph::default();
        let path = scratch.0.join("worktrees/cf7a/wu01/a1");
        let branch = unit_branch(&unit(), Attempt::FIRST).unwrap();
        let worktree = repositories
            .clone_worktree(&project, &path, &branch)
            .unwrap();
        let key = graph_key(&unit(), Attempt::FIRST, "build").unwrap();
        let built = index(
            &graph,
            &repositories,
            IndexKind::Build,
            &key,
            &unit(),
            &worktree.path,
        );
        assert_eq!(built.step_key, "wu01.a1.build");
        assert_eq!(built.wall_clock_ms, Some(1500));
        assert_eq!(built.failure, None);
        let rekey = graph_key(&unit(), Attempt::FIRST, "rebuild.1").unwrap();
        let rebuilt = index(
            &graph,
            &repositories,
            IndexKind::Rebuild,
            &rekey,
            &unit(),
            &worktree.path,
        );
        assert_eq!(rebuilt.kind, IndexKind::Rebuild);
        assert!(rebuilt.failure.is_some());
        let missing = index(
            &graph,
            &repositories,
            IndexKind::Build,
            &key,
            &unit(),
            &scratch.0.join("absent"),
        );
        assert!(missing.failure.is_some());
        assert_eq!(
            *graph.calls.lock().unwrap(),
            vec![
                format!("build wu01.a1.build {}", path.display()),
                format!("rebuild wu01.a1.rebuild.1 {}", path.display()),
            ]
        );
    }

    #[test]
    fn the_index_refuses_a_worktree_swapped_for_a_link() {
        let scratch = Scratch::new("index-link");
        let (repositories, project) = fixture(&scratch);
        let graph = RecordingGraph::default();
        let path = scratch.0.join("worktrees/cf7a/wu01/a1");
        let branch = unit_branch(&unit(), Attempt::FIRST).unwrap();
        let worktree = repositories
            .clone_worktree(&project, &path, &branch)
            .unwrap();
        let elsewhere = scratch.0.join("elsewhere");
        std::fs::rename(&path, &elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &path).unwrap();
        let key = graph_key(&unit(), Attempt::FIRST, "build").unwrap();
        let built = index(
            &graph,
            &repositories,
            IndexKind::Build,
            &key,
            &unit(),
            &worktree.path,
        );
        assert!(
            built
                .failure
                .as_ref()
                .is_some_and(|failure| failure.contains("is a symlink")),
            "{built:?}"
        );
        assert!(graph.calls.lock().unwrap().is_empty());
    }

    fn ports(repositories: Repositories, project: ProjectName) -> WorkerPorts {
        WorkerPorts {
            repositories,
            graph: Arc::new(RecordingGraph::default()),
            project,
            tycho: PathBuf::from("/opt/tycho"),
            claude: PathBuf::from("/opt/claude"),
            codex: PathBuf::from("/opt/codex"),
        }
    }

    #[test]
    fn the_worker_command_writes_the_brief_beside_the_worktree() {
        let scratch = Scratch::new("command");
        let (repositories, project) = fixture(&scratch);
        let path = scratch.0.join("worktrees/cf7a/wu01/a1");
        let branch = unit_branch(&unit(), Attempt::FIRST).unwrap();
        let worktree = repositories
            .clone_worktree(&project, &path, &branch)
            .unwrap();
        let ports = ports(repositories, project);
        let task = WorkerTaskRequest {
            brief: Brief::parse("Make widget::answer return 42.").unwrap(),
            max_turns: NonZeroU16::new(8),
            placement: Some(WorkerPlacement {
                worktree: worktree.clone(),
                control: SessionName::parse("cf7a.wu01.ctl.claude").unwrap(),
            }),
        };
        let session = SessionName::parse("cf7a.wu01.wrk.claude.a1f3").unwrap();
        let session_id = VendorSessionId::parse("3f0c6c1e-6b1a-4a51-9a0e-2a8c5d0c1a10").unwrap();
        let command = WorkerCommand {
            task: &task,
            vendor: Vendor::Claude,
            session: &session,
            model: "haiku",
            effort: Effort::Low,
            session_id: &session_id,
        };
        let argv = worker_command(&ports, &command).unwrap();
        let brief = scratch
            .0
            .join("worktrees/briefs/cf7a.wu01.wrk.claude.a1f3.md");
        assert_eq!(
            std::fs::read_to_string(&brief).unwrap(),
            "Make widget::answer return 42."
        );
        let parsed = WorkerArgs::parse(&argv[2..]).unwrap();
        assert_eq!(parsed.worktree, worktree.path);
        assert_eq!(parsed.base, worktree.base);
        assert_eq!(parsed.brief, brief);
        let victim = scratch.0.join("victim");
        std::fs::create_dir_all(&victim).unwrap();
        let briefs = scratch.0.join("worktrees/briefs");
        std::fs::remove_dir_all(&briefs).unwrap();
        std::os::unix::fs::symlink(&victim, &briefs).unwrap();
        let swapped = worker_command(&ports, &command);
        assert!(
            swapped
                .as_ref()
                .is_err_and(|error| error.contains("is a symlink")),
            "{swapped:?}"
        );
        assert_eq!(std::fs::read_dir(&victim).unwrap().count(), 0);
        let unplaced = WorkerTaskRequest {
            placement: None,
            ..task.clone()
        };
        assert!(worker_command(
            &ports,
            &WorkerCommand {
                task: &unplaced,
                ..command.clone()
            }
        )
        .is_err());
        assert!(worker_command(
            &ports,
            &WorkerCommand {
                vendor: Vendor::Amp,
                ..command
            }
        )
        .is_err());
    }

    #[test]
    fn briefs_are_bounded_text() {
        assert!(Brief::parse("line one\nline two").is_ok());
        assert!(Brief::parse(&"b".repeat(BRIEF_MAX_BYTES)).is_ok());
        for bad in [
            String::new(),
            "b".repeat(BRIEF_MAX_BYTES + 1),
            "tab\there".to_string(),
        ] {
            assert!(Brief::parse(&bad).is_err(), "{bad:?}");
        }
        assert!(serde_json::from_str::<Brief>("\"\"").is_err());
    }

    #[test]
    fn a_second_task_starts_from_the_head_the_first_one_left() {
        let worktree = Worktree {
            path: PathBuf::from("/agent/worktrees/cf7a/wu01/a1"),
            branch: unit_branch(&unit(), Attempt::FIRST).unwrap(),
            base: CommitSha::parse("0123456789abcdef0123456789abcdef01234567").unwrap(),
        };
        let placement = WorkerPlacement {
            worktree: worktree.clone(),
            control: SessionName::parse("cf7a.wu01.ctl.claude").unwrap(),
        };
        let head = CommitSha::parse("1123456789abcdef0123456789abcdef01234567").unwrap();
        let next = placement.after(&head);
        assert_eq!(next.worktree.base, head);
        assert_eq!(next.worktree.path, worktree.path);
        assert_eq!(next.worktree.branch, worktree.branch);
        assert_eq!(next.control, placement.control);
    }
}
