# Slices

The build is three vertical slices. A later slice does not start until the earlier one
passes its exit tests. Each slice answers questions the design could not settle on paper;
those questions are listed so the answers get recorded in the design when they arrive.

The design is `docs/design.html`. Section numbers below refer to it.

## Operator prerequisites

- A dedicated macOS user for agents with its own primary group, not `staff` (design
  section 7, trust boundaries), and a deny entry for it in the developer's home ACL, since
  every local account is in `staff` through `localaccounts`. No credentials of any kind in
  that account. The core runs as the developer.
- A group shared by the developer and the agent user, for the zmx socket directory.
- The shared tool prefix `/Users/Shared/tycho`, owned by the developer and closed to group
  and other writes, holding every binary the agent runs: the pinned mise, claude, codex and
  zmx, and release builds of the station (design section 7). The agent cannot search the
  developer's home, where mise otherwise installs them.
- Vendor credentials in the core's store, set once by the developer from a terminal: a
  Claude Code subscription token from `claude setup-token` and the Codex `auth.json` of a
  ChatGPT plan login, each through `tycho credentials set` (design section 7, vendor
  credentials). The agent user logs in to no vendor; the core hands each session its
  credential. Antigravity is optional in slice zero.
- The entire CLI logged in as the developer if the entire mirror is the sync remote.

`mise run provision-agent`, run as the developer from a terminal, creates the user, both
groups, the home ACL entry and the socket directories, asking for sudo on the terminal, and
creates and fills the tool prefix with no root step
([provisioning](process.md#provisioning-the-agent-user)). The vendor credentials need a
browser login by the plans' owner and stay with the operator, who stores them with the
commands the task prints ([vendor credentials](process.md#vendor-credentials)). `mise run setup` as the developer and
`/Users/Shared/tycho/bin/xtask setup` as the agent check every precondition above and print
what is missing, so the state of the machine is never guessed.

## Slice zero: the spine

Goal: one work unit goes from spawn to merged with nothing lost across kills, with no
council, no reader and no pane host beyond a Ghostty tab.

Components:

- Restate server and the Rust service endpoint, pinned through mise, each in its own zmx
  session, started and probed by a launchd watchdog outside zmx (section 5).
- Services: Epic, WorkUnit, Session, Reconciler, WorkerRun (section 7, service map).
- The launcher: spawns a session under zmx with a name derived from the workflow key and
  attempt, writes a lease file, passes the awaitable id and the session secret, spools
  the result on exit, resolves with retry, kills its own session (section 7).
- The SessionVendor port with the Claude adapter (interactive control session, headless
  worker) and the Codex adapter (headless worker).
- The semantic graph index built per worktree after the clone (section 11).
- The local merge gate: canonical bare repository owned by the core, worktrees cloned
  from it owned by the agent user, verify on a fresh checkout with pinned criteria,
  fast-forward by the core, sync to one remote (section 7, merge gate).
- A blocker path that writes a markdown packet to a directory and reads a verdict from a
  file (section 9 shape, no lint and no inbox yet).

Steps and the question each one answers:

1. Core processes under zmx with the watchdog. Kill the server, the endpoint and the
   watchdog in turn; each returns and in-flight invocations resume.
2. Spawn an interactive Claude control session with the accept setting and post into its
   per-session socket from a handler step. Answers: the socket payload schema; whether
   `zmx send` is needed as a fallback; whether the session stalls on a permission prompt.
3. Spawn a headless worker in a worktree, hand it an awaitable, let it commit, spool and
   resolve. Answers: result decoding states per vendor; context size reporting.
4. Kill tests: Ghostty, then the Restate server between worker exit and resolve, then
   the endpoint, then the launcher before its exit trap. Nothing lost, no duplicate
   session spawned. Answers: whether lease files and the spool are sufficient.
5. Boundary tests as the agent user: read the developer's keychain and config
   directories, write the agent's own settings file, reach the Restate admin port,
   write to the canonical repository, edit its hooks directory, push to its default
   branch. All must fail. Then the positive gate path to a throwaway remote.
   `crates/tycho/tests/boundary.rs`, run with `mise run boundary-tests` from a terminal,
   since sudo asks for the developer's password to run each probe as the agent.
6. Attach tests: a Ghostty tab as the developer attaches to a zmx session owned by the
   agent user through the shared socket directory; the reader opens that tab through
   AppleScript while running under zmx and under launchd, and the Automation consent
   prompt is recorded for each. `crates/tycho/tests/attach.rs`, run with
   `mise run attach-tests` from a Ghostty terminal, since sudo asks for the developer's
   password to create the agent's sessions.
7. A planted contradiction makes the worker reject its awaitable with a certified
   question; the packet lands in a directory; a verdict typed into a file resumes the
   unit.

Exit tests: steps 4, 5 and 7 pass on the synthetic repository; a work unit merges end to
end; journal size per unit and index build time are recorded as the first baselines.

## Slice one: judgment and provenance

Goal: escalations resolve without a human where the design says they should, and every
ruling is a case.

Components: Escalation, Council (two vendors, persuasive weight), CaseLaw, DecisionPacket
with the lint, the reader's rule action with its secret (sections 8 and 9); entire
checkpoints for Claude workers with the three-part push exclusion, hidden refs on the
canonical repository, and the core's fetch of checkpoint refs (section 15, entire.io).

Steps:

1. Escalation sorts a question empirical, authority, judgment; a probe worker answers an
   empirical one.
2. Council convenes on a judgment question with sealed briefs and independent votes; a
   split produces a packet; a majority produces a case.
3. CaseLaw query by scope, keyword and embedding; a fingerprint change demotes a case.
4. DecisionPacket lint rejects a packet over the word limit, with a strawman option, with
   a dead evidence link, or with a timeout default on a one-way door.
5. The rule action resolves the verdict promise and writes the case; a stop verdict
   cancels the unit and its sessions.
6. Checkpoints: one headless capture per worker commit; a push in every git form,
   including mirror, leaves no checkpoint ref on any remote; the core fetches the refs.

Exit tests: the synthetic epic's forced split produces exactly one packet; the forced
precedent is cited and its check runs; rollover fidelity shows zero repeated dead ends.

## Slice two: surfaces

Goal: the human surface the design describes, on top of a factory that already works.

Components: the reader's TUI and web view over one store-reader module, Ghostty hand-off
and deep links, the read-only browser terminal, notifications (sections 10 and 12);
Codex and Antigravity checkpoint capture; the TaskTracker port with the beads adapter
(section 13).

Steps:

1. Inbox with the seven causes and two severities, lifecycle as a projection over events.
2. Deep link: notification carries a localhost link; the reader focuses the recorded
   Ghostty terminal or opens a tab running the attach.
3. TUI and web view render the same packet from one JSON.
4. Tracker intake from a beads issue and outbound status mirroring off the critical path.
5. Checkpoint capture for Codex and Antigravity workers.

Exit tests: the success test in section 1 holds on the synthetic epic; a cold reader
rules on the forced packet in under five minutes; a kill of Ghostty, the reader or the
core mid-run loses nothing.

## Evaluation harness

Built alongside slice zero and extended per slice (section 17): the synthetic epic
repository with five work units (trivial, moderate and ambiguous, forced escalation,
forced council split, downstream dependent), pinned fixtures, programmatic verification,
the chaos tests, and the metric table with the zero-work-units-green rule as a gate
failure.
