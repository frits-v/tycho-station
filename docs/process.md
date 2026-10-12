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
| Git hooks | `lefthook.json`, each command `cargo run -q -p xtask -- <command>` | commit-msg, pre-commit, pre-push |
| Host rules | repository ruleset on the default branch | every push and merge |
| Agent hooks | `.claude/settings.json` | after Edit and Write |
| Tests | `xtask test` (`mbx test --workspace --no-fail-fast`) | ci, pre-push |

## Git hooks and the tests

git hands a hook the repository it runs for in `GIT_DIR` and its relatives: `GIT_WORK_TREE`,
`GIT_INDEX_FILE`, `GIT_COMMON_DIR`, `GIT_CONFIG_PARAMETERS` and the other names
`git rev-parse --local-env-vars` lists. Every process the hook starts inherits them, and from
a linked worktree `GIT_DIR` is `.git/worktrees/<name>`. A test that runs `git init` or
`git commit` in a scratch directory under that environment acts on the repository that ran
the hook, whatever directory it names with `-C`: it can set `core.bare` on the main
repository and commit its fixture onto the branch being pushed.

- The xtask is the only entry point a hook calls. `xtask` removes the names in
  `tycho_types::git_environment::GIT_ENVIRONMENT_REMOVED`, with the numbered
  `GIT_CONFIG_KEY_<n>` and `GIT_CONFIG_VALUE_<n>` pairs, from its own environment before it
  dispatches, so no test binary, cargo or git it starts sees them. A hook command that starts
  cargo, a test binary or git directly is a defect.
- Every git the code starts, production and test, goes through `git_command`,
  `scrub_git_environment`, or a runner given `git_environment_removed()`; the harness
  repository builder and setup's credential check clear the whole environment instead. The
  opengrep rule `rust-git-inherits-hook-environment` refuses any other `Command::new("git")`
  outside `tests/` directories, which opengrep skips by default; there it is review.
- A test that spawns git calls `refuse_hook_environment` first. With `GIT_DIR` set in the test
  process it panics, naming the hook it probably runs under, so `cargo test` started straight
  from a hook fails those tests instead of writing to the repository.

## Verifying before claiming done

A change is done when `mise run ci` passes on the branch and the pull request's `ci`
check is green. A claim of done without that run says so explicitly, with the reason the
run was not possible. Tests that fail are reported with their output, not summarised
away. A step that was skipped is named as skipped.

`xtask ci` refuses to start unless the checkout it was built from (the nearest `.git` above
its `CARGO_MANIFEST_DIR`) is the current directory's, so a worktree under `.worktrees/` and
the checkout above it are never confused; the refusal names both paths. The test step runs
every test binary (`--no-fail-fast`, no colour) and prints each one's resolved path and
counts. The run closes with
`xtask ci: N steps passed, S skipped (<names>), M tests passed, F failed, in <checkout> at <commit>`,
with the failed steps in place of the first part when any failed, and `with K uncommitted
changes` after the commit when the tree differs from it, counted before and after the
steps with the larger count reported. A step with nothing to check, such
as the title check outside a pull request, counts as skipped, not passed. The exit code is 0
exactly when no step failed. A log is evidence for a branch only when that line names its
checkout and a commit with no uncommitted changes.

The developer shell sets `noclobber`: `mise run ci > ci.log` onto an existing `ci.log`
fails with "file exists" before mise starts, and a following `echo $? >> ci.log` appends
`1` to whatever an earlier run left there. Write a log with `>|` or under a new name.

## Live suites

The suites that start real processes are ignored tests, run by their mise tasks on macOS;
`xtask ci` builds them and skips them.

| Task | Needs |
|---|---|
| `kill-tests`, `spine-tests`, `launcher-tests`, `chaos-tests` | the mise tools; they run at the same time, each test core on its own port slot |
| `worker-tests`, `control-tests` | the developer's Claude login, and `graph-plugin` for the worker suite; one at a time |
| `graph-tests` | `mise run graph-plugin` |
| `boundary-tests` | a terminal and the provisioned agent user: sudo asks for the developer's password on the terminal to run each probe as `tycho-agent` |

The boundary suite refuses to start when stdin is not a terminal, and when `sudo -n` runs as
the agent with no password after `sudo -k`, since nothing in the station installs such a
rule; it prints which answer it saw, and runs `sudo -k` again when it ends. `run_as_agent`
in the suite is the one place the identity switch is made; probes run with stdin closed,
since sudo reads the password from `/dev/tty`. Each probe ends with a line naming the uid it ran as and its exit
status, and decodes to one of four states: denied (permission denied, not permitted, git
write refused, or connection refused, named), succeeded (the boundary is open; the line
shows what the agent reached), could not run (sudo refused, the user or the target is
missing, a timeout), or unrecognised, which includes a probe that ran under any uid but the
agent's. Only a denial passes, except the agent's settings write, a listed gap whose outcome
is printed as a measurement. The run ends with the number of boundaries examined and the
count of each disposition; zero examined fails. The agent's walk to the canonical
repository names the first directory it cannot search, with `ls`'s line saying whether that
directory refused it or was absent.

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
  never a push to the default branch, so each merge reaches the save. Each passing push to
  the default branch saves an entry of up to 3 GiB against the repository's 10 GB cache
  limit, so the mise tool cache is evicted first. A run before the first save builds cold.
- The release workflow restores nothing.
- Locally the store grows under the platform cache directory (`mbx doctor` names it) and
  collects itself; `mise run cache-trim` trims it to the size ci saves, and `mbx stats`
  shows what it holds.
- Each checkout gets its own managed target directory: `target` is a link to
  `<cache>/targets/v1/<key>`, and `<key>.json` beside it records the checkout as
  `workspace_root`. Checkouts share compiled units from the store, never a target
  directory, so one tree's artefacts never stand in for another's, and the xtask sets no
  `CARGO_TARGET_DIR`. A unit that reads `env!("CARGO_MANIFEST_DIR")` holds its own
  checkout's path even when an identical source was compiled in another checkout first.
- A test binary's file name (`xtask-<hash>`) does not depend on the checkout, so the same
  name in two logs says nothing about which tree built it; the resolved path the test step
  prints, under `targets/v1/<key>`, does.

## Code scanning

Every ci run writes SARIF to `target/sarif/<tool>.sarif`: clippy, opengrep, zizmor,
jactionlint, and one file per xtask file check (`xtask-check-names`, `xtask-check-comments`,
`xtask-check-rules`, `xtask-check-credentials`). The `ci` job uploads them as the run's
`sarif` artifact. A second job, `code-scanning`, runs after it whether it passed or failed:
it builds the xtask, downloads the artifact into `target/sarif`, then runs
`xtask sarif-upload`, which posts each file to the code scanning API through
`gh api`, gzipped and base64-encoded, with the commit and ref of the run and the file's name
as its category, so one tool's upload never replaces another's alerts.

- Only `code-scanning` holds `security-events: write`; the only code that runs there is the
  xtask and its `--locked` dependency closure, build scripts included. The `ci` job, where
  the workspace's build scripts and tests run, has `contents: read`.
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

## Provisioning the agent user

`mise run provision-agent`, run once per machine as the developer from a terminal, creates
what the developer side of `mise run setup` checks, in this order:

1. the group `tycho-agent`;
2. the user `tycho-agent` with that group as its primary group (`sysadminctl -addUser`
   with `-GID` and `-password -`, so sysadminctl asks for the new user's password itself);
3. the agent's home directory, `/Users/tycho-agent`: `sudo createhomedir -c -u tycho-agent`,
   then `sudo chmod 0700 /Users/tycho-agent` when the mode it was created with is wider.
   `sysadminctl -addUser -home` writes the path into the user record only; the directory
   appears at a first login through the login window, and until it exists
   `sudo -iu tycho-agent` fails. Setup checks that the directory the record's
   `NFSHomeDirectory` names exists, is a directory and not a link, is owned by the agent's
   uid and primary gid, has mode 0700, and holds no ACL allow entry (a deny entry, such as
   the `group:everyone deny delete` a created home carries, passes). It reads the entry
   without following a link and the ACL with `ls -lde` rather than opening the directory,
   since the developer cannot open another user's 0700 directory. Both commands act only
   on `/Users/tycho-agent`; a record naming another path is left to the operator;
4. the shared group `tycho-zmx`, with the developer and the agent as members;
5. a deny entry for the agent in the developer's home ACL,
   `chmod +a "user:tycho-agent deny search,list,readattr,readextattr" ~`, run as the
   developer;
6. `/Users/Shared/tycho-agent-zmx`, owned by the developer, group `tycho-zmx`, mode 2770;
7. the core socket directory `~/.tycho/zmx`, mode 0700.

The agent's own primary group does not keep it out of the developer's home: macOS makes
every local account a member of `staff` through the `localaccounts` group, and a home is
commonly `staff` at 0750. The deny entry does, since the ACL is read before the mode bits.
Setup reports the home as open while the ACL holds no such entry and the mode lets others,
or a group the agent is in, search it.

- Each step runs only while its probe fails, and the probe runs again after it. A step whose
  probe still fails, or whose command prints output its decoder does not recognise, stops
  the run. A second run skips what is in place.
- The directory-service steps run through `sudo`, which asks for the developer's password on
  the terminal; the task prints a notice before each one. The xtask never reads or passes a
  password, and refuses to start when stdin is not a terminal, as the agent user, or as root.
- Root never changes the owner of a path, and changes one mode: the agent home's, whose
  entry sits in root-owned `/Users`, where no other user can swap it for a link. A home
  owned by another user, with another group, or with a mode narrower than 0700 is reported
  with its fix, not changed. A socket directory owned by another user, or owned by root
  with the wrong group or mode, is removed with `sudo /bin/rmdir`, which removes only an
  empty directory and never follows a link, and the developer creates it again; if `rmdir`
  fails the run stops and names the directory to inspect. The directories are created one
  level at a time and set on descriptors opened with `O_NOFOLLOW` by the xtask as the
  developer.
- A root step that outlasts its ten minutes is ended by killing `sudo`; the command under it
  may still finish. The probe after the step reads what happened, so a rerun skips a step
  that completed and repeats one that did not.
- `--print` probes, prints the plan and runs nothing; it exits non-zero while a step is
  outstanding.
- After the steps it prints the developer side of the setup report, with the agent's
  membership and primary group read from directory services, and exits non-zero while any
  of it fails.
- An agent user that exists with another primary group is reported with its fix, not
  changed: rebinding a live account's group is left to the operator.
- Left to the operator, since each needs a login or a setting in the agent's own session:
  `claude` and `codex login` as `tycho-agent` from a terminal in that account
  (`sudo -iu tycho-agent` or a login session), `git config --global credential.helper ""` as
  `tycho-agent`, and `entire auth` as the developer if the entire mirror is the sync remote.
  Then `mise run setup` as `tycho-agent`.

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
  past, `exp` ten minutes after `iat`, `iss` the App's client id from
  `TYCHO_RELEASE_CLIENT_ID`, or its numeric App id from `TYCHO_RELEASE_APP_ID` when no
  client id is set; GitHub prefers the client id), looks up the App's installation on this
  repository, and requests an installation token limited to this repository and to
  Contents and Pull requests write. A token whose grant is wider, or whose grant the
  response does not state, it refuses and revokes. The token reaches release-plz as
  `GIT_TOKEN` in its environment and is revoked when release-plz exits. The xtask makes
  the lookup, the token request and the revocation itself, over HTTPS (rustls on
  aws-lc-rs, the webpki roots compiled in, no proxy, no redirects), sending the JWT or
  the token as `Authorization: Bearer`; GitHub reads an App JWT only under that scheme.
  The key, the JWT and the token never appear in arguments, output, errors or child
  environments: no child process sees the JWT, release-plz sees the token only as
  `GIT_TOKEN`, and release-plz and the processes it starts get the job's environment
  without the App's ids and key. An error names GitHub's status and its message when the
  message reads as plain text.
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
  cannot read its secret. Generate a private key, then store the App's client id (shown
  on the App's settings page) and the key in the environment and delete the downloaded
  file:

  ```sh
  gh api -X PUT repos/frits-v/tycho-station/environments/release \
    -F 'deployment_branch_policy[protected_branches]=false' \
    -F 'deployment_branch_policy[custom_branch_policies]=true'
  gh api -X POST repos/frits-v/tycho-station/environments/release/deployment-branch-policies \
    -f name=main -f type=branch
  gh variable set TYCHO_RELEASE_CLIENT_ID -R frits-v/tycho-station --env release --body <client-id>
  gh secret set TYCHO_RELEASE_APP_PRIVATE_KEY -R frits-v/tycho-station --env release < key.pem
  rm key.pem
  ```

  `TYCHO_RELEASE_APP_ID` with the numeric App id is accepted in place of the client id; when
  both are set the client id is used. Then delete any repository secret that holds a user
  token for this workflow, and revoke that token in the account settings of the user who
  issued it.

- Rotation: generate a new private key in the App settings, store it with the same
  `gh secret set` command, delete the local file, then delete the old key in the App
  settings. The next `release-pr` run uses the new key.
- The first run that names the `release` environment creates it without a branch policy
  if it does not exist yet; the `PUT` above sets the policy either way. Until a client id
  or App id variable and the secret exist in it, the `release-pr` job fails with a message
  naming them and this section; the `release` and `binaries` jobs use the
  workflow's own `GITHUB_TOKEN` and are unaffected. A key that does not belong to the App
  the id names, or an App not installed on this repository, fails the installation lookup with
  GitHub's message.
