# Tycho Station

A local code factory. A root session takes a body of work, splits it into work units,
and hands each one to a control session that plans, delegates, verifies and escalates
but never edits code. Every process lives under zmx; Ghostty shows sessions; a Rust
reader provides the inbox, TUI and web view. Orchestration runs on Restate. Blockers
climb a ladder of arbiters with case law at each rung, and a human sees a decision
packet, not a transcript.

Status: design complete, implementation not started. The first build is slice zero,
described in the design.

## Layout

- `docs/design.html`: the design and requirements document, with mocks. Open it in a
  browser. The same page is published as a Claude artifact for comments.
- `.worktrees/`: per-task git worktrees, ignored.

## Decisions in force

Rust throughout; Restate for durable execution; zmx owns every long-lived process;
Ghostty driven by the reader as the pane host; a local-git merge gate on a core-owned
canonical repository; agents run as a separate user with no credentials; control
sessions roll over from a structured handoff note instead of compacting.
