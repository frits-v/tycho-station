# Git

- The main checkout is read-only. Work in a worktree under `.worktrees/`, one per task,
  removed after the merge.
- Branch from a fresh `origin/main`. Conventional commit subjects, signed, under 72
  characters, lowercase after the type.
- The default branch moves only by squash or rebase merge of a pull request with a
  green `ci` check. No direct push, no force push, no amend after push.
- Never bypass a hook or a check. Fix the cause.
