# Code and documentation style

Reference, not instruction. Each rule names what enforces it; a rule enforced by a lint or
check is not repeated in any instruction file. "review" means a reader rejects it.

## Code

| Rule | Enforced by |
|---|---|
| Stability over performance over convenience; the trade-off is named when it comes up | review |
| Security over convenience: where options differ in security, the most secure one that does the work is taken and the trade-off named | review |
| No `unsafe` | `unsafe_code = "forbid"` |
| Every `Result` handled; no `unwrap`, `expect`, `panic`, `todo`, `unimplemented` outside tests | clippy `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented`, `let_underscore_must_use` |
| No slice indexing; use `get` | clippy `indexing_slicing` |
| No unchecked arithmetic | clippy `arithmetic_side_effects` |
| No `loop` without exit; every loop bounded or over a finite collection | clippy `infinite_loop`; review for `while` bounds |
| No recursion; explicit bounded stack | review |
| Functions do one thing, under sixty lines, bounded complexity | clippy `too_many_lines` (60), `cognitive_complexity` (15) |
| Every external input declares a maximum; exceeding it is an error | review; constants named `*_MAX_*` |
| Decoders of external output enumerate states with an unrecognised state | review |
| Assertions at boundaries (entry, parsing, ingress, persistence, external calls), each with a negative test | review |
| A check reports how many things it examined; zero is a failure | `xtask` `finish`; review for new checks |
| A probe that could not run is a failure, never not applicable | review |
| Specific names; no `tmp`, `ctx`, `obj`, `arr`, `cfg` unless a framework imposes it | `xtask check-names` |
| A cargo build started from Rust goes through `mbx` by name (`mbx clippy`, `mbx test`); `cargo fmt` is not a build and stays | `xtask opengrep` (`rust-cargo-build-bypasses-mbx`) |
| Every `allow` states a reason | clippy `allow_attributes_without_reason` |
| No `dbg!`, no printing or exiting outside the command line crate | clippy `dbg_macro`, `print_stdout`, `print_stderr`, `exit` |
| Formatting and clippy pedantic and nursery clean | `cargo fmt --check`, `cargo clippy -D warnings` in ci and the post-edit hook |
| New behaviour ships with a test; a bug fix ships with the test that failed before it | review; `notes/ledger.md` |
| Shallow call graphs; three levels of indirection is a smell | review |

## Documentation and comments

| Rule | Enforced by |
|---|---|
| A comment exists only for a non-obvious why: a constraint, an invariant, a workaround | review |
| No history in code or docs: nothing about what the code did before, no ticket or PR numbers, hashes, or names of people | `xtask opengrep` (`rust-history-trace-comment`) for history phrases in Rust comments; `xtask check-comments` for the rest of its marker list, ticket and issue numbers in Rust comments, and documents; review for the rest |
| A TODO in Rust names a ticket key (`ABC-123`) or a link | `xtask opengrep` (`rust-todo-without-ticket`) |
| No narration: no process commentary addressed to the reader | `xtask check-comments` for the phrases in its marker list |
| No filler emphasis: bold sprinkles, emdashes as default punctuation, horizontal rules inside a document, emoji | review |
| Docstrings only where the signature does not state the contract; one line | review |
| Documents are atemporal and state what the system does; trade-offs as bullets | review |
| Density matches the surrounding text | review |
| Commit subjects and pull request titles are conventional, lowercase after the type, under 72 characters | `xtask check-commit-msg` (lefthook), `check-pr-title` (ci) |

## Configuration and figures

| Rule | Enforced by |
|---|---|
| CUE before JSON before YAML; TOML only for mise; YAML only for GitHub Actions | review; `xtask check-config` |
| Configuration and JSON Schema are exported from CUE and checked in; an export that drifts from its CUE fails | `xtask check-config` in ci and the post-edit hook |
| Workflow files pass zizmor and jactionlint at pedantic, with their online audits in ci; actions pinned by commit; a workflow uses only the actions `.github/jactionlint.yaml` lists | `xtask workflows` in `xtask ci`, `xtask workflows --offline` in lefthook pre-push when `.github` changes, `forbidden-uses` in `.github/jactionlint.yaml` |
| A check that reports findings at a file and line writes them as SARIF under `target/sarif`, which the `code-scanning` job uploads | `finish_findings` in the xtask; review for new checks |
| Figures are stencil documents authored in CUE under `figures/`, rendered to `docs/figures/` and the design page, and checked in ci | `xtask check-figures` (`cue vet`, `stencil check`, byte comparison) in ci and the post-edit hook; `xtask render-figures` writes them |
| Rule files carry `paths` frontmatter and stay short | `xtask check-rules` |

## Credentials

| Rule | Enforced by |
|---|---|
| No personal access tokens; a credential is the shortest-lived and narrowest the task allows, issued to the station's own identity | `xtask check-credentials` (markers `personal access token`, `fine-grained token`, `classic token`, `gh auth token`, `ghp_`, `gho_`, `ghu_`, `ghr_`, `github_pat_`, `RELEASE_PLZ_TOKEN`, case-insensitive, with whitespace, no-break spaces, zero-width and soft-hyphen characters and their HTML entities removed before matching, over every file `git ls-files` lists or would list that holds no NUL byte, binary files counted, minus the check's own source, this row and the exact lines of mandate clause 7.4) in ci and the post-edit hook; review for lifetime and scope |
