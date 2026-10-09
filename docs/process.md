# Failure handling

## When something goes wrong

A mistake that costs a turn, a check that was wrong, a gate that let something through:
three things happen in the same change.

1. Fix the immediate issue.
2. Add a row to `notes/ledger.md`: date, the rule as a sentence, what enforces it.
3. Add the prevention at the lowest layer that can catch it, in this order of preference:
   a compiler or clippy lint (`Cargo.toml` lints, `clippy.toml`); an `xtask check-*`
   command, which then runs in `ci` and in the post-edit hook; a lefthook hook; the
   repository ruleset; a `.claude/settings.json` hook; a test. Instruction prose is the
   last resort and only for what no mechanism can see.

A ledger row names its mechanism, or says `none` with the reason. A row without either
is a defect.

## Mechanisms and where they live

| Layer | Location | Runs |
|---|---|---|
| Lints | `Cargo.toml` `[workspace.lints]`, `clippy.toml` | every build, ci, post-edit hook |
| Repository checks | `xtask` (`check-names`, `check-comments`, `check-rules`, `check-commit-msg`, `check-pr-title`) | ci, post-edit hook, lefthook |
| Git hooks | `lefthook.json` | commit-msg, pre-commit, pre-push |
| Host rules | repository ruleset on the default branch | every push and merge |
| Agent hooks | `.claude/settings.json` | after Edit and Write |
| Tests | `cargo test` | ci, pre-push |

## Verifying before claiming done

A change is done when `mise run ci` passes on the branch and the pull request's `ci`
check is green. A claim of done without that run says so explicitly, with the reason the
run was not possible. Tests that fail are reported with their output, not summarised
away. A step that was skipped is named as skipped.

## Reporting

A report leads with the outcome. It states what was verified and how, what was not and
why, and what is left. It does not narrate the steps taken.

## Adding a check

1. Write the check in the xtask as a function returning an exit code, bounded in input
   and output, that counts what it examined and fails on zero.
2. Add it to the `COMMANDS` table and to `ci`; add it to the post-edit hook when it is
   fast.
3. Add a unit test for the defect it catches and one for the clean case.
4. Add the row in `docs/style.md` naming the check, and delete any prose the check now
   replaces.
