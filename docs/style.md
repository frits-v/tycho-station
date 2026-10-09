# Code and documentation style

Reference, not instruction. Each rule names what enforces it; a rule enforced by a lint or
check is not repeated in any instruction file. "review" means a reader rejects it.

## Code

| Rule | Enforced by |
|---|---|
| Stability over performance over convenience; the trade-off is named when it comes up | review |
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
| Every `allow` states a reason | clippy `allow_attributes_without_reason` |
| No `dbg!`, no printing or exiting outside the command line crate | clippy `dbg_macro`, `print_stdout`, `print_stderr`, `exit` |
| Formatting and clippy pedantic and nursery clean | `cargo fmt --check`, `cargo clippy -D warnings` in ci and the post-edit hook |
| New behaviour ships with a test; a bug fix ships with the test that failed before it | review; `notes/ledger.md` |
| Shallow call graphs; three levels of indirection is a smell | review |

## Documentation and comments

| Rule | Enforced by |
|---|---|
| A comment exists only for a non-obvious why: a constraint, an invariant, a workaround | review |
| No history in code or docs: nothing about what the code did before, no ticket or PR numbers, hashes, or names of people | `xtask check-comments` for the phrases in its marker list; review for the rest |
| No narration: no process commentary addressed to the reader | `xtask check-comments` for the phrases in its marker list |
| No filler emphasis: bold sprinkles, emdashes as default punctuation, horizontal rules inside a document, emoji | review |
| Docstrings only where the signature does not state the contract; one line | review |
| Documents are atemporal and state what the system does; trade-offs as bullets | review |
| Density matches the surrounding text | review |
| Commit subjects and pull request titles are conventional, lowercase after the type, under 72 characters | `xtask check-commit-msg` (lefthook), `check-pr-title` (ci) |

## Configuration and figures

| Rule | Enforced by |
|---|---|
| CUE before JSON before YAML; TOML only for mise; YAML only for GitHub Actions | review; `cue vet` once configuration exists |
| Workflow files pass zizmor pedantic and actionlint; actions pinned by commit | `xtask ci`, lefthook pre-push |
| Figures are stencil documents authored in CUE under `figures/`, rendered to `docs/figures/` and the design page, and checked in ci | `xtask check-figures` (`cue vet`, `stencil check`, byte comparison) in ci and the post-edit hook; `xtask render-figures` writes them |
| Rule files carry `paths` frontmatter and stay short | `xtask check-rules` |
