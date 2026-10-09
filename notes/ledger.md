# Ledger

| Date | Rule | Enforced by |
|---|---|---|
| 2026-10-08 | A git command chain is judged per segment by the directory it has moved to, and paths under `.worktrees/` are linked worktrees even before they exist; the hook previously judged a whole chain by its first `cd` and blocked worktree commits. | `~/.claude/hooks/git_hygiene.py` (effective_cwd with offsets, is_main_checkout `.worktrees` rule), `~/.claude/hooks/tests/test_git_hygiene.py` |
| 2026-10-08 | Repository logic lives in typed code (xtask), tools come from mise, hooks run through lefthook, and no marketplace action carries logic; the first CI workflow used a marketplace action for the title check. | `xtask check-pr-title` in `.github/workflows/ci.yml`, `lefthook.yml` commit-msg |
