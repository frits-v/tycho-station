# Ledger

One row per rule; full rows are in [`notes/ledger/`](ledger/), one file per month. A new mistake gets a full row in the current month's file and a row here linking it.

[2026-10]: ledger/2026-10.md

| Date | Rule | Enforced by | Archive |
|---|---|---|---|
| 2026-10-08 | The git hook judges each chain segment by the directory it moved to; `.worktrees/` paths are worktrees. | `~/.claude/hooks/git_hygiene.py` | [A git command][2026-10] |
| 2026-10-08 | Logic lives in the xtask, tools in mise, hooks in lefthook; no marketplace action carries logic. | `xtask check-pr-title`; lefthook | [Repository logic lives][2026-10] |
| 2026-10-09 | A rule a lint, hook or check can enforce is not prose; a rule file is short and scoped, and one that restates a global rule is deleted. | `xtask check-rules` | [A rule that][2026-10] |
| 2026-10-09 | The git hook resolves literal shell variables as `cd` or `git -C` targets and scans a push per segment. | `~/.claude/hooks/git_hygiene.py` | [A shell variable][2026-10] |
| 2026-10-09 | No ticket or issue numbers in code comments. | `xtask check-comments` | [No ticket or][2026-10] |
| 2026-10-09 | A kill-path test fails when the kill does not run, and a probe that cannot run fails it. | `verify` tests | [A test of a][2026-10] |
| 2026-10-09 | A handler that deduplicates calls carries a sequence in its body; Restate hides the idempotency key. | `session` sequence test | [Restate 1.7.13 with][2026-10] |
| 2026-10-09 | No shared or ingress handler returns an awaitable id or a session secret. | `session`, `reconciler` status tests | [An awaitable id][2026-10] |
| 2026-10-09 | A timestamp a deadline counts from is journaled after the step it dates. | `spawn_time_is_read_after_the_spawn_step` | [A timestamp that][2026-10] |
| 2026-10-09 | A handler that changes authority, spends budget or starts sessions is `ingress_private`, behind the Operator. | spine tests; `operator` tests | [A handler that][2026-10], [Workflow `run` handlers][2026-10] |
| 2026-10-09 | A journaled step that starts a process records what it may have started on its error path. | spine cancel-during-spawn test | [Under the SDK's][2026-10] |
| 2026-10-09 | A bounded listing fails over its bound and counts only what it bounds. | `figures` tests | [A bounded listing][2026-10] |
| 2026-10-09 | A rendered figure inlined without its fonts names a fallback stack. | `figures` tests | [A rendered figure][2026-10] |
| 2026-10-09 | A path in an agent-writable directory is opened `O_NOFOLLOW` and checked on its descriptor. | `agent_files`, `spool` tests | [A path in][2026-10] |
| 2026-10-09 | A file the agent can read holds an awaitable's SHA-256, never its id; the vendor environment is allowlisted. | `lease`, `launch_spec` tests | [A file the agent][2026-10] |
| 2026-10-09 | A line typed into zmx stays under 1000 bytes with zmx's suffix and carries no secret. | `spawn` tests; launcher suite | [A command typed][2026-10] |
| 2026-10-09 | A pid in an agent-writable file is a hint; the core signals only a pid zmx lists and that matches. | `kill` tests | [A pid in][2026-10] |
| 2026-10-09 | A JSON Schema from cue is validated against real fixtures before it is trusted. | `envelope` schema tests; `xtask check-config` | [A JSON Schema generated][2026-10] |
| 2026-10-09 | A ruling resolves only while the unit is escalated in that attempt. | `work_unit::ruling_promise` | [A ruling resolves][2026-10] |
| 2026-10-09 | A vendor gets `USER` and `LOGNAME` from the password database, never the inherited environment. | `launch_spec`, `worker_process` tests | [A headless vendor][2026-10], [The vendor environment][2026-10] |
| 2026-10-09 | A vendor under zmx leads its own session with no controlling terminal. | `tests/worker_session.rs`; `mise run worker-tests` | [A vendor under][2026-10] |
| 2026-10-09 | A test double emits the real wire shape through the real component's constructor or check. | `spool::check_result_envelope` | [A test double emits][2026-10] |
| 2026-10-09 | Text typed through `zmx send` ends with a carriage return. | `spawn` test | [Text typed into][2026-10] |
| 2026-10-09 | A Claude session resumes only after its first turn wrote the transcript. | control suite resume test | [A Claude session][2026-10] |
| 2026-10-09 | A decoder of a directory other tool versions share requires only the fields it keys on. | `claude_control` registry test | [A decoder of][2026-10] |
| 2026-10-09 | A file the core leaves for another user is checked by descriptor and content; cleanup only unlinks. | `relay` tests | [A file the core][2026-10] |
| 2026-10-09 | A test that attaches a zmx client removes `ZMX_SESSION` from its environment. | `tycho::zmx::Zmx` | [A test that attaches][2026-10] |
| 2026-10-09 | A registry path is checked before connecting, and the peer uid before writing. | `crates/tycho/src/vendors/claude_control/tests.rs` | [A path read][2026-10] |
| 2026-10-09 | The core never follows a symlink or runs git under an agent-writable directory. | clippy `disallowed_methods`; `agent_tree` tests | [The core never][2026-10] |
| 2026-10-09 | An owner and mode check on a file in a directory the checked user owns cannot show the file is protected from that user. | none (needs core-owned locations) | [An owner and][2026-10] |
| 2026-10-09 | A git setting is checked over every file git reads, with `--show-scope`. | `setup` tests | [A check of a git][2026-10] |
| 2026-10-09 | A JWT `iss` claim is a string. | `app_token` JWT test | [A JWT `iss`][2026-10] |
| 2026-10-09 | A step holding a secret runs a prebuilt binary, and its children never get the secret. | `release` tests | [A step that][2026-10] |
| 2026-10-09 | A marker scan covers every tracked file and matches across line breaks. | `credentials` tests | [A marker scan][2026-10] |
| 2026-10-09 | A credential issued and then refused is revoked before the refusal returns. | `app_token` revocation test | [A credential issued][2026-10] |
| 2026-10-09 | gh run with a cleared environment gets a private working directory and telemetry off. | none (no command does this) | [gh 2.102.0 run][2026-10] |
| 2026-10-09 | A text scan decodes non-binary files lossily and drops invisible separators first. | `credentials` tests | [A text scan][2026-10] |
| 2026-10-09 | A test that captures a child's environment bounds it with its own cap. | `command` environment test | [A test that captures][2026-10] |
| 2026-10-09 | A test double reads its ports from the port claim its core starts with. | `start_core_with_spawner` | [A test double built][2026-10] |
| 2026-10-09 | A start step waits, bounded, for a listener's health before calling through it. | `core::wait_for_ingress` | [A start step][2026-10] |
| 2026-10-09 | A call that timed out may have landed: read its outcome before reporting or repeating it. | `core::kick_reconciler`; `http` tests | [A call that][2026-10] |
| 2026-10-09 | Test cores that run at once claim distinct port slots before they start. | `CorePorts::claim`; `port_claim` tests | [Test cores that][2026-10] |
| 2026-10-09 | A pid zmx lists for an ended session is never signalled. | `zmx::clear_action`; `watchdog` tests | [A pid that][2026-10] |
| 2026-10-10 | A probe meant to tell two mechanisms apart uses an input on which they differ. | `app_token`, `github_api` tests | [A probe meant][2026-10] |
| 2026-10-09 | Root never changes the owner or mode of a path in a directory another user can write. | `provision` tests | [Root never changes][2026-10] |
| 2026-10-09 | An access boundary is checked by the access it denies, not the attribute meant to cause it. | setup home check; `setup` tests | [An access boundary][2026-10] |
| 2026-10-09 | A test that needs a socket nothing listens on binds one and never listens. | `test_sockets::bound_without_listener` | [A test that needs][2026-10] |
| 2026-10-09 | An inbox-protocol test listener reads to the client's half-close and half-closes its reply. | none (timing); `test_sockets::listener_for` | [A test listener][2026-10] |
| 2026-10-10 | A ci log counts only when its closing line names the checkout and a clean commit. | `ci_summary`; `checkout` tests | [A ci log][2026-10] |
| 2026-10-10 | `xtask ci` runs only in the checkout it was built from. | `checkout::same_checkout` | [`xtask ci` runs][2026-10] |
| 2026-10-10 | The ci test step runs every test binary and accounts for each one. | `test_step` tests | [The ci test][2026-10] |
| 2026-10-12 | The git hook judges a command with its heredoc bodies blanked. | `~/.claude/hooks/git_hygiene.py` | [Text a command][2026-10] |
| 2026-10-12 | A user record is not a home directory; setup checks the directory the record names. | `setup`, `provision` tests | [A user record][2026-10] |
| 2026-10-12 | A probe of a macOS-only tool takes its reader as a parameter, so Linux tests its decoding. | `setup::measure_agent_home` | [A probe that][2026-10] |
| 2026-10-12 | Every git spawn removes the hook environment, and hooks call only the xtask. | `tycho_types::git_environment`; `xtask opengrep` | [A test that spawns][2026-10] |
| 2026-10-12 | The worker suite checks its scratch paths fit the typed line before a session starts. | `assert_typed_line_fits` | [The worker suite's][2026-10] |
| 2026-10-12 | A JSON Schema handed to `claude --json-schema` names no `$schema` dialect. | `review::minified` | [A JSON Schema handed][2026-10] |
| 2026-10-12 | A file the review model reads lives outside the checkout, in an `--add-dir` directory. | `review::claude_run` tests | [A file the review][2026-10] |
| 2026-10-12 | A privileged workflow fetches a pull request by the resolved commit, never by a ref. | `review::setup` tests; CodeQL | [A privileged workflow][2026-10] |
| 2026-10-13 | A lint's exemption is a decision, never an escape. | `.github/workflow-policy.cue`; `xtask codeql` | [A lint's exemption][2026-10] |
| 2026-10-13 | A secret the xtask uses never reaches a child process. | `secrets::take_from_environment`; opengrep | [A secret the][2026-10] |
| 2026-10-12 | A poll over a tool's state maps every transient state, each from a captured sample. | `decoders` launchctl test | [A poll over][2026-10] |
| 2026-10-12 | A live suite reads files in agent-writable directories the way production does. | `decoders` marker test | [A live suite reads][2026-10] |
| 2026-10-12 | A suite that prompts checks it owns the terminal and restores the terminal after. | `TerminalState`; `decoders` tests | [A suite that][2026-10] |
| 2026-10-12 | A command that may leave a daemon is captured to files, never read from pipes. | `run_to_files`; `decoders` tests | [A command whose][2026-10] |
| 2026-10-12 | A pty test keeps the master open while it uses the slave. | `pty_slave`; Linux ci runner | [A test on][2026-10] |
| 2026-10-12 | A terminal prompt is preceded by the emulator resets. | `reset_emulator`; `decoders` test | [A prompt on][2026-10] |
| 2026-10-13 | A value holding a token is never returned together with what the run prints. | `review::setup`; CodeQL | [A value that][2026-10] |
| 2026-10-13 | The ledger files merge with the union driver; branches update by local merge or rebase. | `.gitattributes` | [The ledger is][2026-10] |
| 2026-10-13 | A federation rule is written against claims of a token actually issued. | `anthropic_token::rule_claims` | [A federation rule][2026-10] |
| 2026-10-13 | A minimum guarding a budget is derived from that budget's terms, setup time included. | `passes::TOKEN_LIFETIME_MIN` | [A minimum that][2026-10] |
| 2026-10-13 | Text posted to GitHub is escaped for its markdown context. | `review::findings` tests | [Text posted to][2026-10] |
| 2026-10-13 | A pull request title passes `xtask check-pr-title` before `gh pr create` or `gh pr edit`. | pre-tool-use hook; ci | [A pull request title is][2026-10], [A pull request title passes][2026-10] |
| 2026-10-13 | Posted text breaks every mention and reference GitHub would link, checked against its API. | `review::findings` tests | [An entity does][2026-10] |
| 2026-10-13 | A commit or pull request title carries a scope only when the scope adds information. | none (a judgment) | [A commit or][2026-10] |
| 2026-10-13 | Fixes within an approved change need no new review; when the scope grows, the author dismisses the approval and asks again. | `docs/process.md`; ruleset | [An approval can][2026-10] |
| 2026-10-13 | A bound moved from code into a CUE schema moves its test with it. | `config` petition-bound test | [A bound moved][2026-10] |
| 2026-10-14 | A pull request opens as a draft and is marked ready with `gh pr ready`. | pre-tool-use hook (`pull_request_hook`) | [A pull request is][2026-10] |
| 2026-10-15 | An approved, resolved and green pull request is merged by its author without asking. | `docs/process.md` | [A pull request the][2026-10] |
| 2026-10-15 | A branch updates by local rebase and `--force-with-lease`, never `gh pr update-branch`. | pre-tool-use hook | [A branch is][2026-10] |
| 2026-10-15 | A directory the core makes for another user gets its exact mode on a descriptor after `mkdir`. | `spawn::set_created_mode` | [A directory the][2026-10] |
| 2026-10-15 | A zmx command in the shared directory runs under umask 007 after checking the directory and log. | `zmx` tests; boundary suite | [Every zmx command][2026-10] |
| 2026-10-15 | A sudoers rule is read back from the full `sudo -n -k -l` listing. | `agent_switch::decode_listing` | [A sudoers rule is][2026-10] |
| 2026-10-15 | A sudoers rule keeps variables with `env_keep =` on its own line, never `+=`. | `agent_switch` rule test | [A sudoers rule that][2026-10] |
| 2026-10-15 | A pid the core binds a credential to is the one `zmx list` reports, never a lease's. | `spawn::Found`; `spawn` tests | [A pid the][2026-10] |
| 2026-10-15 | A residual names the surviving process and the test that hides it. | `kill::deliver_through` | [A residual names][2026-10] |
| 2026-10-15 | `LOCAL_PEERPID` names the socket's last user, so the peer pid is checked twice. | `credential_handoff` test | [`LOCAL_PEERPID` on macOS][2026-10] |
| 2026-10-15 | A value CodeQL takes as a user id, a uid included, is never printed. | `SessionEvidence`; CodeQL | [A value CodeQL's][2026-10] |
| 2026-10-15 | A pid to signal comes from the started process, never a pattern match. | none (a shell habit) | [A pid to][2026-10] |
| 2026-10-15 | Root writes into `/etc/sudoers.d` only by renaming a complete, checked file. | `provision` tests | [Root never writes][2026-10] |
| 2026-10-15 | A program that must lead its own session starts as a child of the shell, never by `exec`. | `group_leader` tests | [A program typed][2026-10] |
| 2026-10-15 | The sudo listing decoder splits a line at each `Defaults` it holds. | `bound_lines`; `agent_switch` test | [sudo 1.9.17 prints][2026-10] |
| 2026-10-15 | A ledger row names only enforcement that exists, or lists the name as kept elsewhere. | `xtask check-ledger` | [A ledger row][2026-10] |
| 2026-10-24 | The review refuses a head in another repository before fetching it. | `review::setup::refuse_fork` | [The review job][2026-10] |
| 2026-10-24 | The environment changes only in the xtask's single-threaded startup steps. | `unsafe_code = "deny"` | [The process environment][2026-10] |
| 2026-10-25 | Each crate names the dependency features it relies on. | none in ci (workspace builds hide it) | [A dependency's feature][2026-10] |
| 2026-10-25 | A test expecting a refusal checks it is the refusal it names. | `group_leader` boundary test | [A test that expects][2026-10] |
| 2026-10-25 | A file a vendor saves by sibling and rename is granted with its siblings. | `sandbox::state_file_rule` | [A file a][2026-10] |
| 2026-10-25 | A sandboxed process starts in a directory the sandbox grants. | `worker_process` tests | [A process in][2026-10] |
| 2026-10-25 | Turning a vendor's sandbox off also turns off what it allowed. | `worker_process` tests | [Turning a vendor's][2026-10] |
| 2026-10-25 | A path check reads the path as text. | `sandbox::check_path` | [A path check][2026-10] |
| 2026-10-25 | A live suite's fake vendor runs inside the session sandbox like a real one. | `FIXTURE_DIR`; launcher suite | [A live suite's][2026-10] |
| 2026-10-25 | A path that resolves through the process's descriptor table is never granted. | `sandbox` tests on Linux | [A system path][2026-10] |
| 2026-10-25 | A refusal that would repeat on every attempt goes to the inbox, not the queue. | `exit_decode::decode_exit` | [A refusal that][2026-10] |
| 2026-10-25 | A path written into a pattern is refused where the escape cannot hold it. | `sandbox` tests | [A path written][2026-10] |
| 2026-10-25 | A channel is a residual only after the setting that closes it is probed. | `sandbox::capability_set` | [A channel is][2026-10] |
| 2026-10-25 | A count taken from a bounded buffer says it is bounded. | `session_proxy::AUDIT_EVENTS_MAX` | [A count taken][2026-10] |
| 2026-10-25 | A helper for platform-gated tests is gated with them or shared. | clippy on the Linux runner | [A test helper][2026-10] |
| 2026-10-25 | A test waits for its event, never a fixed time, and a race test is checked to fail without its fix at the bound it uses. | `launcher`, `session_proxy` tests | [A test of what][2026-10], [A race test][2026-10] |
| 2026-10-25 | A check of a file another tool parses mirrors that tool's parse rules. | `codeowners::rules` | [A check of a file][2026-10] |
| 2026-10-25 | A `claude` pin bump recaptures the worker streams and maps every event. | `claude_worker` capture test | [A `claude` pin][2026-10] |
| 2026-10-25 | A live suite starts the vendor with the adapter's command line, adding no flag. | control suite | [A live suite starts][2026-10] |
| 2026-10-25 | A value read right after a result is written by a call, never a send. | `launcher`, `spool` tests | [A value a reader][2026-10] |
| 2026-10-25 | Closing a vendor's settings layers is checked against every file it reads into a session. | `worker_process` tests | [Closing a vendor's][2026-10] |
| 2026-10-25 | A run records a value as measured only from a result whose source confirmed it. | `worker_run`, `work_unit` tests | [A value a run][2026-10] |
| 2026-10-25 | A handler's journaled steps change only by appending after every step an earlier build journaled. | spine `assert_status_read_follows_each_result`, `assert_session_steps` | [A handler's journaled step][2026-10], [A step added][2026-10], [A handler's journaled steps][2026-10] |
| 2026-10-25 | Which path a vendor's traffic takes is measured under the station's own configuration. | `session_proxy` tests | [Which path a][2026-10] |
| 2026-10-25 | A vendor's TLS trust is part of what its sandbox allows, checked against an unsandboxed run. | `session_sandbox::trust_environment` | [A vendor's TLS][2026-10] |
| 2026-10-25 | A record taken when a session ends is taken on the path sessions normally end by. | `assert_proxy_audit_recorded` | [A record the][2026-10] |
| 2026-10-25 | The vendor's environment is an exact set at each layer, and tests compare the whole set. | `launch_spec` tests | [The vendor's environment][2026-10] |
| 2026-10-25 | A listing that stands for a set keeps only entries of that kind. | worker suite | [A listing that][2026-10] |
| 2026-10-25 | What the core reads after a kill is written before the vendor is signalled. | `Run::supervise`; `launcher` test | [Whatever the core][2026-10] |
| 2026-10-25 | A claim about what a dependency does to a request is asserted on what the far side received. | `session_proxy` route test | [A claim about][2026-10] |
| 2026-10-25 | A byte bound on a serialised field is taken on the serialised form. | `proxy_audit::cut` | [A byte bound][2026-10] |
| 2026-10-25 | A read that finds nothing while the writer may still write is read again, bounded. | `keep_proxy_audit` | [A read that][2026-10] |
| 2026-10-25 | A vendor credential handed out as a copy is checked for whether the vendor rewrites it. | Codex sandbox test; fix: none (the Codex refresh issue) | [A vendor credential][2026-10] |
| 2026-10-26 | A record of a server's decisions is taken after it stops deciding. | `SessionProxy::close` | [A record of][2026-10] |
