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
| Repository checks | `xtask` (`check-names`, `check-comments`, `check-rules`, `check-credentials`, `check-figures`, `check-config`, `check-commit-msg`, `check-pr-title`, `opengrep`, `workflows`) | ci, post-edit hook, lefthook |
| Source rules | `opengrep/rust.yml`, each rule with fixture lines in `opengrep/rust.rs` | `xtask opengrep` in ci |
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
   and output, that counts what it examined and fails on zero. A check whose findings have
   a file and line reports them through `finish_findings`, which also writes its SARIF. A
   pattern over Rust source is an opengrep rule in `opengrep/rust.yml` with lines that must
   fire and lines that must not in `opengrep/rust.rs`.
2. Add it to the `COMMANDS` table and to `ci`; add it to the post-edit hook when it is
   fast.
3. Add a unit test for the defect it catches and one for the clean case.
4. Add the row in `docs/style.md` naming the check, and delete any prose the check now
   replaces.

## Build cache

Cargo runs through mbx, a compiler-output cache that mise wires in (`mr_boxington` on the
rust pin, `min_version` 2026.9.2). A cargo that the xtask starts finds rustup's cargo on
`PATH` rather than the mise wrapper, so the xtask starts `mbx clippy` and `mbx test` by
name, and an opengrep rule refuses `cargo` with a build subcommand in Rust source. dist,
which `release-binaries` runs, starts cargo through `$CARGO -vV` first, which mbx refuses,
so release builds use rustup's cargo.

- The ci workflow restores `~/.cache/mbx` and the cargo registry on every run, keyed by
  commit with a prefix fallback. It saves them, after `mise run cache-trim` collects the
  store down to 3 GiB, only after a passing push to the default branch, so a pull request
  never writes outputs another run reads. A newer push cancels a pull request's running ci,
  never a push to the default branch, so each merge reaches the save. A run before the
  first save builds cold.
- The release workflow restores nothing.
- Locally the store grows under the platform cache directory (`mbx doctor` names it) and
  collects itself; `mise run cache-trim` trims it to the size ci saves, and `mbx stats`
  shows what it holds.

## Code scanning

Every ci run writes SARIF to `target/sarif/<tool>.sarif`: clippy, opengrep, zizmor,
jactionlint, and one file per xtask file check (`xtask-check-names`, `xtask-check-comments`,
`xtask-check-rules`, `xtask-check-credentials`). The `ci` job uploads them as the run's
`sarif` artifact. A second job, `code-scanning`, runs after it whether it passed or failed:
it downloads the artifact into `target/sarif`, builds the xtask in a step without a token,
then runs `xtask sarif-upload`, which posts each file to the code scanning API through
`gh api`, gzipped and base64-encoded, with the commit and ref of the run and the file's name
as its category, so one tool's upload never replaces another's alerts.

- Only `code-scanning` holds `security-events: write`. The `ci` job, where build scripts and
  tests run, has `contents: read` and a token only for the online workflow audits, so no
  build step can write or dismiss code scanning alerts.
- The repository ruleset requires the `ci` check only, so the upload does not gate merge;
  each check already fails `ci` on a finding.
- A repository without code scanning answers 403 "Code scanning is not enabled". The upload
  prints `sarif-upload: code scanning is not enabled for this repository; N files not
  uploaded` with GitHub's message, adds a `code scanning off` warning to the run, and passes.
  Any other refusal fails the job.
- A pull request from a fork gets a read-only token, which code scanning refuses, so the job
  is skipped when the head repository is not this one.
- For code scanning to accept the files, the operator enables GitHub Code Security for the
  repository (Settings, Advanced Security) where the account's plan offers it, or moves the
  repository to an organisation that has it.

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
  Contents and Pull requests write. A token whose grant is wider, or whose grant the
  response does not state, it refuses and revokes. The token reaches release-plz as
  `GIT_TOKEN` in its environment and is revoked when release-plz exits. The key, the JWT
  and the token never appear in arguments, output, errors or child environments: gh runs
  in a new empty private directory that is also its `GH_CONFIG_DIR`, with `PATH`,
  `TMPDIR` and the locale from the job, telemetry off and the credential in `GH_TOKEN`;
  release-plz and the processes it starts get the job's environment without the App id
  and key.
- The workflow builds the xtask in a step without the key, then runs the built binary in
  the step that holds it, so no build script or proc-macro inherits the key. A build
  script in the build step can still write `$GITHUB_ENV` or replace `target/debug/xtask`,
  and the next step would run with that environment or binary and the key. Closing that
  takes a separate build job that passes the binary to the release job as an artifact
  checked against its digest; the workflow does not do that.
- A failed revocation fails the job. A run cancelled between minting and revoking, or a
  token request that ends timed out or over its output cap after GitHub issued the token,
  leaves the token valid until GitHub expires it, one hour after it was issued.
- The release pull request's author is the App's bot account (`<app-name>[bot]`), not a
  person. The merge gate and any ruleset that names authors or bypass actors see that
  identity.
- Setup, once: create a GitHub App owned by the operator's account with webhooks off,
  repository permissions Contents and Pull requests set to read and write and nothing
  else, installable only on this account. Install it on this repository only. Create the
  `release` environment limited to the default branch, so a workflow on any other branch
  cannot read its secret. Generate a private key, then store the App id and the key in
  the environment and delete the downloaded file:

  ```sh
  gh api -X PUT repos/frits-v/tycho-station/environments/release \
    -F 'deployment_branch_policy[protected_branches]=false' \
    -F 'deployment_branch_policy[custom_branch_policies]=true'
  gh api -X POST repos/frits-v/tycho-station/environments/release/deployment-branch-policies \
    -f name=main -f type=branch
  gh variable set TYCHO_RELEASE_APP_ID -R frits-v/tycho-station --env release --body <app-id>
  gh secret set TYCHO_RELEASE_APP_PRIVATE_KEY -R frits-v/tycho-station --env release < key.pem
  rm key.pem
  ```

  Then delete any repository secret that holds a user token for this workflow, and revoke
  that token in the account settings of the user who issued it.

- Rotation: generate a new private key in the App settings, store it with the same
  `gh secret set` command, delete the local file, then delete the old key in the App
  settings. The next `release-pr` run uses the new key.
- The first run that names the `release` environment creates it without a branch policy
  if it does not exist yet; the `PUT` above sets the policy either way. Until the variable
  and the secret exist in it, the `release-pr` job fails with a message naming both and
  this section; the `release` and `binaries` jobs use the
  workflow's own `GITHUB_TOKEN` and are unaffected. A key that does not belong to the App
  id, or an App not installed on this repository, fails the installation lookup with
  GitHub's message.
