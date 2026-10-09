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
| Repository checks | `xtask` (`check-names`, `check-comments`, `check-rules`, `check-credentials`, `check-figures`, `check-config`, `check-commit-msg`, `check-pr-title`) | ci, post-edit hook, lefthook |
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

## Releases

The `release` workflow runs on every push to the default branch, through the xtask.

- `xtask release-pr` runs `release-plz release-pr`. It opens or updates one release pull
  request with the next `tycho` version and its changelog, derived from conventional
  commits since the last `v*` tag. Only `tycho` is released; every other crate stays
  unreleased until `release-plz.toml` opts it in. Nothing is published to crates.io.
- Merging the release pull request makes `xtask release` tag the merge commit `vX.Y.Z`
  and create the GitHub release. The `binaries` job then runs `xtask release-binaries` on
  macOS and Linux, which builds the archives with dist and uploads them. Re-running the
  workflow on a release commit rebuilds and replaces the archives.
- `mise run release-pr -- --dry-run` shows the next release pull request locally without
  a token.

release-plz writes the release pull request's commit through the GitHub API, so GitHub
signs it. The pull request still needs `ci`, a required check. A pull request opened with
the workflow's own `GITHUB_TOKEN` waits for a writer to approve its workflow runs on every
update, and release-plz updates it on every push, so the `release-pr` job opens it with a
GitHub App installation token that the xtask mints for each run:

- The xtask signs an RS256 JWT with the App's private key (`iat` sixty seconds in the
  past, `exp` ten minutes after `iat`), looks up the App's installation on this
  repository, and requests an installation token limited to this repository and to
  Contents and Pull requests write. It refuses a token whose grant is wider. The token
  reaches release-plz as `GIT_TOKEN` in its environment and is revoked when release-plz
  exits; the key, the JWT and the token never appear in arguments, output or errors.
- The release pull request's author is the App's bot account (`<app-name>[bot]`), not a
  person. The merge gate and any ruleset that names authors or bypass actors see that
  identity.
- Setup, once: create a GitHub App owned by the operator's account with webhooks off,
  repository permissions Contents and Pull requests set to read and write and nothing
  else, installable only on this account. Install it on this repository only. Generate a
  private key, then store the App id and the key and delete the downloaded file:

  ```sh
  gh variable set TYCHO_RELEASE_APP_ID -R frits-v/tycho-station --body <app-id>
  gh secret set TYCHO_RELEASE_APP_PRIVATE_KEY -R frits-v/tycho-station < key.pem
  rm key.pem
  ```

- Rotation: generate a new private key in the App settings, store it with the same
  `gh secret set` command, delete the local file, then delete the old key in the App
  settings. The next `release-pr` run uses the new key.
- Until the variable and the secret exist, the `release-pr` job fails with a message
  naming both and this section; the `release` and `binaries` jobs use the workflow's own
  `GITHUB_TOKEN` and are unaffected. A key that does not belong to the App id, or an App
  not installed on this repository, fails the installation lookup with GitHub's message.
