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
| Repository checks | `xtask` (`check-names`, `check-comments`, `check-rules`, `check-credentials`, `check-figures`, `check-config`, `check-commit-msg`, `check-pr-title`, `opengrep`, `workflows`, `codeql`) | ci, post-edit hook, lefthook |
| Source rules | `opengrep/rust.yml`, each rule with fixture lines in `opengrep/rust.rs` | `xtask opengrep` in ci and in lefthook pre-push when Rust or a rule changes |
| Workflow rules | `.github/workflow-policy.cue`; zizmor, jactionlint; CodeQL's Actions queries | `xtask workflows` in ci and pre-push; `xtask codeql` in pre-push when `.github` changes; code scanning on every pull request |
| Git hooks | `lefthook.json`, each command `cargo run -q -p xtask -- <command>` | commit-msg, pre-commit, pre-push |
| Host rules | repository ruleset on the default branch: the `ci` check, and code scanning with no new CodeQL alert of high security severity or error level | every push and merge |
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
  opengrep rule `rust-git-inherits-hook-environment` refuses `Command::new` given git by
  literal path or a field named `git` without `env_clear`, and a `run_captured`,
  `run_status`, `run_status_capped`, `run_captured_without`, `run_detached` or
  `run_status_from` call given git by literal path, a name `git` or `GIT`, a field named
  `git` or a variable bound to a git path, without `&git_environment_removed()`.
  `run_status_from` takes no removal list, so git through it is always refused. Git reached
  any other way, and anything under `tests/` directories, which opengrep skips by default,
  is review.
- A test that spawns git calls `refuse_hook_environment` first. With any of `GIT_DIR`,
  `GIT_INDEX_FILE`, `GIT_WORK_TREE` or `GIT_COMMON_DIR` set in the test process it panics,
  naming the variables and the hook it probably runs under, so `cargo test` started straight
  from a hook fails those tests instead of writing to the repository. A commit hook in a main
  checkout gets `GIT_INDEX_FILE` without `GIT_DIR`.

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
| `worker-tests` | a Claude token in the core's store (`tycho credentials set claude`), which the suite copies into its test core and hands its worker, and `graph-plugin`; never beside `control-tests` |
| `control-tests` | a Claude token in the core's store, which the suite copies into its test core and hands each control session; never beside `worker-tests` |
| `graph-tests` | `mise run graph-plugin` |
| `boundary-tests` | a terminal and the provisioned agent user: sudo asks for the developer's password on the terminal to run each probe as `tycho-agent` |
| `attach-tests` | a Ghostty terminal and the agent user: sudo once, again at teardown past its five-minute cache; up to two Automation dialogs (the suite's terminal, `osascript`) |

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

The attach suite refuses to start without a terminal and makes the same `sudo -n` check. In
one sudo call it creates three sessions as the agent in `/Users/Shared/tycho-agent-zmx` with
the prefix's zmx; each session's program reads one typed line, writes it to a marker file in
a directory of group `tycho-zmx`, then sleeps 600 seconds. Every zmx run in the shared
directory, the agent's and the developer's clients alike, runs under `umask 007` with
`ZMX_DIR_MODE=0770` and `ZMX_LOG_MODE=0660`, since the umask masks the socket, directory and
log modes. Three paths attach as the developer: a pty from `script`, which waits until
`zmx list` shows its client, types the line, detaches with Ctrl-\ and checks the session is
still listed; and a Ghostty tab opened by `osascript`, run once inside a developer zmx
session and once as a one-shot launchd user agent (`tycho-attach-test-<pid>`, its plist in
the suite's private directory, booted out at teardown). The tab script waits, bounded, until
`zmx list` shows the tab's client, then types the line through Ghostty's `input text`; a tab
whose client never shows fails.

A path passes only when the marker holds the typed line and the agent owns it; the marker is
opened without following a link or blocking on a FIFO and read within its bound. osascript's
answer decodes to opened, never attached, consent required (-1743, -1744), Ghostty
unavailable (-600, -10814, or -1728 when the script cannot compile without Ghostty),
unanswered (-1712, or no answer within 180 seconds) or unrecognised, which includes a -1728
at run time. A consent prompt is a path that could not look, and its line names System
Settings, Privacy & Security, Automation, the requesting application and Ghostty, to turn on
before running the suite again. The run prints the owner, mode, link flag and developer
write access of every entry in the shared directory, flags any symbolic link, ends with
`examined N attach paths` and each path's state, and fails on zero examined or any path that
did not attach. Teardown kills the agent's sessions by name as the agent, never by pid, then
kills by name any session of the run's prefix the developer owns, which `zmx attach` on a
missing name creates, and prints what the shared directory still lists. A second ignored
test runs the pty path against a developer session in a private directory, with no sudo.

Before every sudo, the teardown's included, the attach suite checks that its process group
is the terminal's foreground group, and refuses with a line naming both groups when it is
not, since sudo could then show its prompt but never read the password. It writes the
emulator resets to `/dev/tty` (the kitty keyboard protocol popped, then set to no flags,
bracketed paste, focus events and mouse reporting off), since a `zmx attach` in Ghostty can
leave the keyboard protocol on, after which Enter arrives as `CSI 13 u` and a canonical read
never ends, which termios cannot show. It puts the terminal in canonical mode with echo, DEL
as erase, and carriage return read as newline with neither ignored nor swapped, and prints
the process group, the foreground group, the input and local flags, VERASE, VMIN and VTIME
before and after. After each pty client and when the test ends, a panic included, it writes
the resets again and restores the saved settings. Each agent-side command runs with its
output in files and is bounded by sudo's own exit; on a timeout the line carries `ps`'s
state, process group and foreground group for sudo (`T` is stopped reading the terminal from
a background group, `S` is waiting), and a refused kill is named and not waited for. The
agent's scripts send zmx's output to a file of their own, so a session daemon that inherits
a descriptor cannot hold the run open.

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
- CodeQL runs in code scanning's default setup on every pull request, with the extended
  query suite, for Rust and GitHub Actions; the ruleset refuses a merge that adds a CodeQL
  alert of high security severity or above, or one at error level. A false positive is
  dismissed with its data-flow path as the reason.
- Before a push that changes `.github`, `xtask codeql` runs CodeQL's Actions security queries
  locally (about five seconds): the CLI version is pinned in `mise.toml`, the query pack in
  `xtask/src/codeql.rs`. It counts the workflow files the extractor took in and fails on
  none, and fails on any result. Its SARIF goes to `target/codeql`, not `target/sarif`: code
  scanning refuses CodeQL results uploaded beside its default setup. CodeQL's Rust queries
  take about two minutes on this repository and run only in code scanning. The CodeQL CLI
  licence permits this use on an open-source codebase; the repository is AGPL-3.0-only.

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
7. the core socket directory `~/.tycho/zmx`, mode 0700;
8. the shared tool prefix `/Users/Shared/tycho` with `bin` and `mise` beneath it, each mode
   0755;
9. the pinned mise in `/Users/Shared/tycho/bin/mise`;
10. the agent's tools in the prefix's mise data directory, recorded with their paths and
    digests in `station.json`;
11. release builds of `xtask` and `tycho` in `/Users/Shared/tycho/bin`.

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
- Left to the operator: storing the vendor credentials as the developer (Vendor
  credentials, below), then, from a terminal, in this order, each run as `tycho-agent`
  through `sudo` with no login shell, so none of the agent's startup files runs and the
  environment holds only what is written:

  ```sh
  sudo -u tycho-agent -H /usr/bin/env -i HOME=/Users/tycho-agent PATH=/usr/bin:/bin /usr/bin/git config --global credential.helper ""
  sudo -u tycho-agent -H /usr/bin/env -i HOME=/Users/tycho-agent USER=tycho-agent LOGNAME=tycho-agent PATH=/Users/Shared/tycho/bin:/Users/Shared/tycho/mise/installs/claude/2.1.280:/Users/Shared/tycho/mise/installs/codex/0.160.1/bin:/Users/Shared/tycho/mise/installs/zmx/0.8.1:/usr/bin:/bin MISE_DATA_DIR=/Users/Shared/tycho/mise MISE_GLOBAL_CONFIG_FILE=/Users/Shared/tycho/mise.toml MISE_CACHE_DIR=/Users/Shared/tycho/cache MISE_OVERRIDE_CONFIG_FILENAMES=/Users/Shared/tycho/no-project-config MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES=none MISE_OFFLINE=1 MISE_AUTO_INSTALL=false MISE_STATE_DIR=/Users/tycho-agent/.local/state/mise /Users/Shared/tycho/bin/xtask setup
  ```

  The empty credential helper clears every helper git reads, Apple's osxkeychain included.
  The agent logs in to no vendor: it has no login session, so no keychain it can read, and
  every session gets its vendor credential from the core. `entire auth` as the developer is
  needed only if the entire mirror is the sync remote. The task prints the same commands,
  with the versions of the pins it was built with.

### Vendor credentials

The core holds one credential per vendor in `~/.tycho/credentials`, a 0700 directory of the
developer, each file 0600, and hands the session's to each launcher over a socket the spawn
step serves (design section 7, Vendor credentials). The developer, who owns the Claude
subscription and the Codex plan, stores them once, from a terminal, with the prefix's
binaries:

```sh
/Users/Shared/tycho/mise/installs/claude/2.1.280/claude setup-token
/Users/Shared/tycho/bin/tycho credentials set claude
/Users/Shared/tycho/mise/installs/codex/0.160.1/bin/codex login -c 'cli_auth_credentials_store="file"'
/Users/Shared/tycho/bin/tycho credentials set codex < ~/.codex/auth.json
/Users/Shared/tycho/bin/tycho credentials status
```

- `setup-token` opens the browser login and shows the token on its own screen; paste it into
  `credentials set claude` and end the input with Ctrl-D. `credentials set` reads stdin only,
  so the value reaches no argument, history or `ps`, and refuses a value of the wrong shape
  or over its bound (512 bytes for the token, 16 KiB for `auth.json`).
- The `-c` override makes `codex login` write `~/.codex/auth.json` even where the Codex
  configuration names the keychain.
- `credentials status` prints each file's presence, owner, mode and age, never its content,
  and exits non-zero until both are present and private; `xtask setup` checks the same on
  the developer's side, in the core home `TYCHO_HOME` names when set, and, as the agent,
  that the store under the developer's default core home, `~/.tycho`, refuses it; the agent
  cannot see a moved core home.
- A launcher spawner refuses a Claude or Codex session whose credential is absent; a session
  whose launcher got none ends `vendor_credential_unavailable` in the inbox, and one whose
  vendor refused the credential ends `vendor_login_required`.
- Rotation: run the same pair of commands again. `credentials set` replaces the file by a
  rename, and the next session gets the new value; running sessions keep the old one until
  they end. The Claude token lasts a year.
- Codex refresh: Codex refreshes its tokens after about eight days and writes them to the
  session's `auth.json`, which is discarded with the session's Codex home, so the stored seed
  never advances. After the window every session refreshes from that seed, the second
  session after the vendor rotates the refresh token fails, and two sessions started together
  race for one refresh token. Once Codex sessions end `vendor_login_required`, run
  `codex login` and `credentials set codex` again. Returning the refreshed file to the core
  is [the Codex refresh issue](https://github.com/frits-v/tycho-station/issues/106).
- Revocation: removing a vendor's file from the store stops that vendor's new sessions at
  spawn; running sessions keep their copy until they end. The Claude token stays valid for
  its year: the Claude docs document no early revocation of a `setup-token` token, and
  `claude logout` has nothing to remove, since the token is stored only in the core.
  `codex logout` removes the developer's local Codex login and nothing in the store.

### The shared tool prefix

The agent cannot search the developer's home, where mise installs every tool and where the
station is built, so every binary the agent runs lives in `/Users/Shared/tycho`:

| Path | What |
|---|---|
| `bin/mise` | mise 2026.9.13, the version the workflows pin |
| `bin/xtask`, `bin/tycho` | release builds of this repository |
| `mise.toml` | the global mise configuration: the agent's pins and nothing else |
| `mise/installs/<tool>/<pin>` | the pinned claude, codex and zmx; codex's executable is under `bin` |
| `cache` | mise's cache, filled by the developer and read-only to the agent |
| `station.json` | per tool, its pin, the absolute path of its executable and the SHA-256 of its install; the SHA-256 of `bin/xtask` and `bin/tycho`, the commit they were built from and whether the tree was clean |

- The developer owns the prefix and every entry beneath it, and none is writable by group
  or other, so the agent reads and executes and changes nothing. `/Users/Shared` is
  world-writable and sticky, so only the developer or root can rename or remove the
  prefix's entry. No step runs as root and a pin bump needs no sudo.
- A session runs claude, codex and zmx by the absolute paths `station.json` records, and
  `PATH` holds those install directories, never mise's shims. A shim asks mise which version
  to run, and mise reads `.tool-versions` and `mise.toml` in the working directory and its
  parents, and cached bin paths, all of which the agent can write in its worktree or its
  home; a shim is therefore no trust anchor and nothing here goes through one. Any mise a
  session or a probe starts gets `MISE_OVERRIDE_CONFIG_FILENAMES` naming a path in the
  prefix that never exists, `MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES=none`, the prefix's
  read-only cache, `MISE_OFFLINE=1` and `MISE_AUTO_INSTALL=false`.
- The agent needs claude, codex and zmx from the prefix, and git from the system; nothing
  else. The prefix's `mise.toml` names those three at the versions in the repository's
  `mise.toml`, which are compiled into the xtask so the agent's `xtask setup` needs no
  checkout.
- mise is downloaded from the jdx/mise release with its `SHASUMS256.txt`. The digest
  compiled into the xtask for the pinned version is the anchor: the published digest and
  the download's must both equal it. A redirect is followed only to GitHub's own hosts, over
  HTTPS. A test keeps the pin equal to every `jdx/mise-action` version in the workflows.
- The tools are installed by the prefix's mise run from `/` with a cleared environment,
  file creation mask 022, the prefix's mise variables with the network allowed, and a state
  directory under the developer's home kept apart from the developer's own mise
  (`~/.local/state/tycho-prefix-mise`). The install step then requires `mise which` to name
  each pinned install's executable and records the path and the install's SHA-256 (over
  every entry's path, mode, and file content or link target).
- The station binaries are built with `mbx build --release --locked -p xtask -p tycho` from
  the checkout the task runs in. The commit and the tree's state are read before and after
  the build, and a change between them refuses the install. Every file is written beside its
  final name, flushed, given its mode, and renamed over the old one.
- `station.json` catches an accidental change, a partial install or a stale build. It does
  not stop tampering: whoever can replace a binary in the prefix can rewrite it too.
- Setup checks, on the developer's side: the prefix is a real directory the developer owns,
  mode 0755, with every ancestor a real directory owned by root or the developer and either
  closed to group and other writes or sticky, opened with `O_NOFOLLOW|O_DIRECTORY`; a walk of
  at most 4096 entries that follows no link finds every entry the developer's, no file or
  directory writable by group or other, every link resolving inside the prefix, and no
  `no-project-config`; mise answers with the pinned version; each of claude, codex and zmx
  resolves through `mise which` to its pinned install's executable, answers by absolute path
  with its pin, and has the recorded install digest; `bin/xtask` and `bin/tycho` have the
  digests `station.json` records, and it records this checkout's commit from a clean tree. A
  new commit therefore reads as not current until the task runs again.
- On the agent's side, `/Users/Shared/tycho/bin/xtask setup` walks the prefix and asks the
  kernel with `access(W_OK)` whether the agent can write any directory or file, which counts
  access lists and group memberships the mode bits do not show, and reports how many entries
  it examined; checks mise; runs each tool by absolute path at its pin and compares its
  install digest; and checks that stat, listing or opening the core's credential store is
  refused. No login probe runs as the agent: a session authenticates only with the credential
  the core hands its launcher, which the agent-side setup never holds, so authentication is
  proven where sessions start, by the worker suite and by a session's exit state.
- A prefix that is a link, is owned by another user, or sits below an ancestor another user
  can swap is reported with its fix and nothing is installed into it.
- `LauncherSpawner::for_prefix` builds the spawner from `ToolPrefix`, which reads
  `station.json`: zmx types the prefix's `bin/tycho` as the launcher, sessions run under the
  recorded zmx, the launcher's `PATH` holds the prefix's `bin` and the recorded install
  directories, and the vendor gets the mise variables. `TYCHO_TOOL_PREFIX` moves the prefix
  for a test core home and is refused for the production one. The launcher, control, worker
  and chaos suites start their sessions this way from a scratch prefix that links the built
  `tycho` and the developer's pinned tools (`tycho_harness::tool_prefix`). The production
  endpoint does not start sessions yet; when it does, it builds its spawner with
  `for_prefix`. The core's own processes (restate-server, the endpoint, the watchdog) run as
  the developer and keep the developer's `mise which` and the running `tycho`.
- `bin/xtask` resolves the checkout it was built from, so after that checkout is removed its
  station checks read as unreachable until `mise run provision-agent` runs again from a
  current checkout.
- The agent's shell startup files are not written: a file in the agent's home is the
  agent's to replace, so every agent command sets its environment in full instead.

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

## Code review

Claude reviews a pull request and the review App `frits-code-review` posts a verdict on it:
`APPROVE`, `REQUEST_CHANGES` or `COMMENT`. `xtask review` does all of it; the workflows only
check out, build and run it.

### When a review runs

- The `review` workflow starts on `pull_request_target` when a pull request whose author is
  an owner, member or collaborator is marked ready for review, and on `issue_comment` when a
  comment on a pull request, any pull request a fork's included, mentions
  `@frits-code-review` or `@claude` as a whole word, from an account of type `User` whose
  association is `OWNER`, `MEMBER` or `COLLABORATOR`. Opening a pull request, pushing to it or
  editing a comment starts nothing; the workflow's condition and the xtask's event decoder
  both enforce this.
- The review's own text holds no `@`: model text is posted with `<`, `>`, `&` and `@`
  escaped. A review never asks for another one.
- A pull request takes at most 20 reviews from the App; past that the run fails before
  calling the model.
- Runs of one pull request share a concurrency group on the job, after its condition; a new
  request cancels the run in progress, and a comment that starts no review cancels nothing.

### What runs where

- The trusted `review` job runs the base branch's workflow and xtask. It checks the base
  branch out with its history, builds the base branch's xtask, and runs
  `xtask review --post`. The workflow checks out nothing of the pull request.
- The xtask resolves the head commit (from the `ready_for_review` event, or from the pull
  requests API for a comment), fetches exactly that commit from `origin` (a fork's head
  included: GitHub serves it from the base repository) and checks it out as a detached
  worktree under `RUNNER_TEMP`, with hooks off and Git LFS not smudging; it checks the
  worktree is at that commit and posts the review on it. A push after the commit was resolved
  changes nothing about what is reviewed; a push between a comment and the run is reviewed on
  its own merits, since the commenter asks for a review and vouches for no code, and the
  verdict is attached to the commit it judged.
- Nothing from the worktree is built or run: the xtask runs git in it with `--no-ext-diff
  --no-textconv`, runs the Claude binary `mise which claude` names from the base checkout (a
  mise shim run in the worktree would take the pull request's pin), and hands the model only
  read tools. git and mise run without the App key, the Langfuse secret key, the OIDC request
  variables or any job token in their environment. The worktree is removed when the run ends.
- The job runs in the `review` environment, whose secrets are the App key and the Langfuse
  key. `pull_request_target` and `issue_comment` runs carry the default branch's ref, so an
  environment that admits only the default branch serves them and refuses every branch's own
  workflow.
- The `review-dry-run` workflow runs by hand from any branch:
  `gh workflow run review-dry-run.yml --ref <branch>`. It runs that branch's xtask with
  `xtask review --dry-run` against `origin/main`, prints the verdict it would give and the
  findings, writes them to the step summary, and posts nothing; it holds no App key. It is
  how a change to the reviewer is tried before it reaches the base branch. On `main` itself
  the merge base is the head, so the diff is empty and the run fails with nothing to review;
  dispatch it on a branch that differs from `main`. `mise run review`
  does the same locally with the developer's Claude login and refuses a tree with
  uncommitted changes, since the model reads the working tree.

### The review

- The xtask diffs the merge base against the head, leaving out `Cargo.lock`, `config/export`
  and `docs/figures`. A diff over 512 KiB, or one with no head-side lines once those are left
  out, fails the run instead of being cut.
- A find pass runs `claude -p` (model alias `opus`) with the diff, `CLAUDE.md`, the ledger and
  this document to read, and returns at most 20 candidates in the JSON Schema exported from
  `schemas/review.cue`, handed to the CLI without its `$schema` dialect. The App's earlier
  findings on the pull request are listed for it; one that still holds is reported again.
- Each of the 12 most severe candidates gets a verify pass in a fresh session, four at a
  time, that tries to refute it and answers `confirmed` or `refuted`; the job log shows each
  verdict's reasoning.
- The model runs with the tools Read, Grep and Glob under permission mode `dontAsk`, which
  refuses any read outside the reviewed checkout and the run's own 0700 directory under
  `RUNNER_TEMP`, passed with `--add-dir`; that directory holds the diff, the earlier findings
  and the instructions, since the CLI refuses reads of gitignored paths. `--setting-sources ""`
  keeps the pull request's `.claude/settings.json` from adding a hook or a permission. Its
  environment is `PATH`, `HOME`, `LANG`, `TMPDIR`, the user name and the Anthropic access
  token: never the App's token, the Langfuse keys or the OIDC request variables.
- Each find pass is capped at 80 turns and $10, each verify pass at 30 turns and $2.

### The verdict

- A rule decides it from the confirmed findings, never the model: a confirmed high or medium
  finding requests changes; without one, a high or medium candidate nobody judged (over the
  cap of 12, or a verify pass that ended without a verdict) gets `COMMENT`, as does a fork's
  pull request; otherwise the App approves. Low findings never block. A finding posted before
  that still holds counts again.
- While the passes run, nothing about the other checks reaches the model. Afterwards the
  xtask reads the check runs and commit statuses on the head commit every 30 seconds, leaving
  out the review's own jobs, until none is pending or 45 minutes after the start, and lists
  each with its outcome in the review body; a read that fails is retried at the next poll, and
  the last failure is named in the body instead of stopping the review. They never change the
  verdict: a failing required
  check, code scanning alert or secret scanning result is the branch rules' to enforce, and
  the review judges the code.
- A new finding on a line the diff shows becomes an inline comment; any other goes into the
  body, since GitHub refuses a whole review whose comment names a line outside the diff. Each
  carries a fingerprint of its path, category and summary in a hidden marker; a finding whose
  fingerprint the App posted before is not posted again. Only markers in the App's own
  comments and reviews count, so nobody else's text can suppress a finding.
- A finding that holds the run's own token fails the run and posts nothing; one that holds
  another credential prefix is withheld and counted.
- The run fails when it cannot post, when a verify pass gives no verdict, when the trace
  cannot be sent, or when revoking the App's token fails; the verdict, when there is one, is
  posted first.

### Credentials

- The App's installation token is minted like the release App's: an RS256 JWT from
  `FRITS_CODE_REVIEW_CLIENT_ID` and `FRITS_CODE_REVIEW_APP_PRIVATE_KEY`, exchanged for a token
  limited to this repository and to Checks read, Pull requests write and Commit statuses
  read, whatever else the App is granted; a wider grant is refused and revoked. The App's
  login, `<slug>[bot]`, comes from `GET /app`. The token is revoked when the run ends.
- Anthropic: the xtask asks the Actions OIDC endpoint for a token with audience
  `https://api.anthropic.com` and trades it at `https://api.anthropic.com/v1/oauth/token` with
  a JWT bearer grant naming `ANTHROPIC_FEDERATION_RULE_ID`, `ANTHROPIC_ORGANIZATION_ID` and,
  when set, `ANTHROPIC_SERVICE_ACCOUNT_ID` and `ANTHROPIC_WORKSPACE_ID`. It requires a `Bearer`
  token type and an `expires_in` of at most a day, and bounds the passes to that lifetime less
  two minutes, at most 30 minutes. Anthropic documents no revocation; the token lapses.
- This repository's OIDC tokens carry GitHub's immutable-id subject,
  `repo:frits-v@4488681/tycho-station@1411277668:environment:<name>`, not the
  `repo:<owner>/<name>:...` form GitHub's documentation shows. The federation rule therefore
  matches stable claims in a CEL condition instead of `sub`:

  ```text
  claims.repository_id == "1411277668" && (
    (claims.environment == "review" &&
     claims.job_workflow_ref == "frits-v/tycho-station/.github/workflows/review.yml@refs/heads/main") ||
    (claims.environment == "review-dry-run" &&
     claims.job_workflow_ref.startsWith("frits-v/tycho-station/.github/workflows/review-dry-run.yml@"))
  )
  ```

  Before each exchange the xtask prints the claims a rule matches on (`sub`, `environment`,
  `job_workflow_ref`, `ref` and the token's lifetime), never the token. An exchange the rule
  refuses answers an opaque `401`; the Console's authentication history names the failed
  check, such as `match_condition_false`.
- The rule's token lifetime is at least 1920 seconds: the passes run for at most 30 minutes
  and the xtask leaves two minutes unused. A shorter lifetime fails the run before any pass,
  naming the lifetime it got.
- All exchanges are made in process over HTTPS (rustls on aws-lc-rs, the webpki roots
  compiled in, no proxy, no redirects); no token appears in arguments, output or errors.

### Tracing

When `LANGFUSE_BASE_URL`, `LANGFUSE_PUBLIC_KEY` and `LANGFUSE_SECRET_KEY` are all set, the
xtask sends one trace per run to `<base>/api/public/otel/v1/traces` as OTLP/JSON, with Basic
authentication and `x-langfuse-ingestion-version: 4`. The root span is the review (input the
commit range, output the verdict and its reason, the counts as metadata) and each pass is a
generation span with its instructions, its output, the model alias, its token counts and its
cost. Runs of one pull request share the session `owner/name#<number>`; a dry run's session is
`dry-run:<head>`. Each trace is tagged `post` or `dry-run`. None of the three set means no
trace; some but not all is an error.

### Setup, once

- Install the App on this repository. Its repository permissions may be wider than the token
  the xtask asks for.
- Create the `review` environment admitting only the default branch, and put the App key and
  the Langfuse secret key in it; create `review-dry-run` with only the Langfuse secret key:

  ```sh
  gh api -X PUT repos/frits-v/tycho-station/environments/review \
    -F 'deployment_branch_policy[protected_branches]=false' \
    -F 'deployment_branch_policy[custom_branch_policies]=true'
  gh api -X POST repos/frits-v/tycho-station/environments/review/deployment-branch-policies \
    -f name=main -f type=branch
  gh secret set FRITS_CODE_REVIEW_APP_PRIVATE_KEY -R frits-v/tycho-station --env review < key.pem
  gh secret set LANGFUSE_SECRET_KEY -R frits-v/tycho-station --env review
  gh api -X PUT repos/frits-v/tycho-station/environments/review-dry-run
  gh secret set LANGFUSE_SECRET_KEY -R frits-v/tycho-station --env review-dry-run
  ```

  Then delete the repository-level copies of both secrets, which every branch's workflow can
  read. `FRITS_CODE_REVIEW_CLIENT_ID`, the four `ANTHROPIC_*` identifiers, `LANGFUSE_BASE_URL`
  and `LANGFUSE_PUBLIC_KEY` are repository variables.
- Whether the App's approval counts toward a required review is the repository ruleset's
  setting. When it does, a review run that fails before posting leaves the pull request
  without that approval: the review fails closed.
