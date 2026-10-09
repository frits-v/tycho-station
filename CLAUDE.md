# Tycho Station

- Design: `docs/design.html`. Decisions in force are listed in the README.
- Tooling is installed and pinned through mise (`mise install`). Git hooks: `mise run hooks`.
- Build, check and release logic lives in `xtask` (Rust). No bash scripts, no logic in workflow YAML, no reusable or marketplace workflows beyond checkout and mise setup.
- Commits are signed and conventional; pull request titles are conventional; merges are squash or rebase.
- Strictly typed over everything: CUE before JSON before YAML. Configuration, schemas and thresholds are CUE with `cue vet` as the gate; the runtime reads exported JSON; JSON Schema is generated from CUE. YAML only where a tool forces it (GitHub Actions), TOML only for mise.
- Figures are stencil documents (github.com/frits-v/stencil): authored in CUE under `figures/`, rendered by the xtask, checked in CI. Add grammars, templates or checks to stencil when a figure needs them.
- Batteries included: one binary with assets, grammars, schemas and themes embedded; nothing fetched at run time.
- Task worktrees live under `.worktrees/` (ignored); the main checkout stays pristine.

@notes/ledger.md
