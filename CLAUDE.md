# Tycho Station

Design: `docs/design.html`. Mandate: `docs/mandate.md`. Plan: `docs/slices.md`. Issues and
milestones on GitHub.

Rules in `.claude/rules/` apply to every edit: `code.md`, `docs.md`, `git.md`.

- `mise install` once; `mise run ci` is the whole check; `mise run hooks` installs git hooks.
- Logic in Rust (`xtask` for build, check, hooks). No bash scripts, no logic in YAML.
- CUE before JSON before YAML; TOML only for mise. Figures are stencil documents.
- Task worktrees under `.worktrees/`; the main checkout stays pristine.

@notes/ledger.md
