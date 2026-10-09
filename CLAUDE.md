# Tycho Station

- Design: `docs/design.html`. Decisions in force are listed in the README.
- Tooling is installed and pinned through mise (`mise install`). Git hooks: `mise run hooks`.
- Build, check and release logic lives in `xtask` (Rust). No bash scripts, no logic in workflow YAML, no reusable or marketplace workflows beyond checkout and mise setup.
- Commits are signed and conventional; pull request titles are conventional; merges are squash or rebase.
- Task worktrees live under `.worktrees/` (ignored); the main checkout stays pristine.

@notes/ledger.md
