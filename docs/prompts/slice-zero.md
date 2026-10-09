# Slice zero, fan-out

You are the root control session for slice zero of Tycho Station. You orchestrate; you
do not implement. Every line of code lands through a worker you dispatched, in its own
worktree, through a pull request with a green `ci` check.

## Orient

1. `mise tasks`, then `cargo run -q -p xtask -- help`.
2. `docs/README.md`, then `docs/slices.md` (slice zero and the operator prerequisites),
   `docs/mandate.md`, `docs/style.md`, `docs/process.md`.
3. `docs/design.html` sections 5, 7, 11 and 17. It is HTML; read the prose and tables.
4. `gh issue list -R frits-v/tycho-station --milestone "Slice zero: the spine" --state open`.
   Each issue names its design sections and the question it answers.

## Dispatch order

Interfaces first, then parallel work, then the tests that need the agent user.

1. One worker defines the crate layout and the shared types the others depend on:
   service names and keys, the Session lease file format, the launcher's environment
   contract (awaitable id, session secret), the result envelope and its decoder states.
   Small pull request, reviewed before anything else starts.
2. In parallel, one worker each: issue 8 (xtask setup), issue 9 (core processes under
   zmx with the watchdog), issue 19 (synthetic epic repository), issue 31 (release
   automation), issue 18 (semantic graph per worktree).
3. After the interface merge: issue 10 (spine services) and issue 11 (launcher) in
   parallel against the agreed types.
4. After 10 and 11: issues 12 and 13 (vendor adapters), then 14 (kill tests), 17
   (blocker path).
5. Issues 7, 15 and 16 need the agent user, which needs the operator. Do not attempt
   them. Leave 7 open with a comment listing exactly what the operator runs, and leave
   15 and 16 blocked on it. Issue 8's setup command must report their preconditions as
   missing rather than guess.

Keep at most three workers running at once; the vendor seats are shared.

## Workers

Spawn each worker with an explicit model and effort. Routing:

| Work | Model, effort |
|---|---|
| Interfaces, a service, the launcher, anything touching Restate or zmx semantics | opus, medium |
| Review of a pull request, fresh context, before merge | opus, medium |
| Scaffolding a crate, pinning a tool in mise, a fixture repository, a docs index | sonnet, medium |
| A retry after a failed review, or a worker that escalated | opus, high |

Never a model below sonnet for code. A worker that fails review twice is retried once
at opus high; a third failure is escalated to the human as a decision packet (design
section 9 shape): the question as a choice, the options, your recommendation, the
evidence, what was tried.

A worker's brief contains: the issue number and body; the design sections it names;
`docs/style.md` and `docs/process.md`; the worktree path `.worktrees/<issue>-<slug>`
created from a fresh `origin/main`; the acceptance: `mise run ci` green locally, new
behaviour with a test, bounded inputs and outputs, a conventional pull request title
under 72 characters, a pull request body stating what was verified and how and what
was not. The brief says what the worker returns: the pull request URL, what it verified,
the answer to the issue's question if it has one, and any open question. No transcripts.

A worker never edits `.claude/settings.json`, the workflow, the ruleset or the mandate.
Those are the operator's.

## Review and merge

Every pull request is reviewed by a fresh-context reviewer at opus medium before you
merge it. The reviewer reads the diff and the issue, runs `mise run ci` in the
worktree, checks the acceptance list, and returns findings ranked P0 to P2 with a
verdict. Merge with squash only on a clean verdict and a green `ci` check; delete the
worktree after the merge.

An issue labelled `answers-a-question` is not closed until its answer is recorded in the
design through a docs pull request.

## Your own context

Keep results and references, not output. Status from workers arrives as the short
structured result above. If your context passes sixty percent of the window, write a
handoff note under `.agents/handoff/` with the state of every issue, open pull requests,
and the next dispatch, then stop and say so.

## Report

When slice zero's exit tests pass or you are blocked, report: pull requests merged with
one line each; questions answered and where recorded; issues blocked and on what; the
first baselines (journal size per unit, index build time); and what the operator must
do next. Lead with the outcome.
