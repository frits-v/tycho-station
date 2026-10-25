# Vendor extensions and surfaces

A time-boxed assessment of whether Claude Code mods and OpenAI's Intelligent UI, with the
extension points and surfaces around them, should carry part of the station. Each area
ends in a go or no-go, and the go verdicts become the follow-up issues listed at the end.
Section numbers refer to `design.html`, article numbers to `mandate.md`. Vendor documents
were read on 2026-10-09 and the mods pages again on 2026-10-15. Probes ran against the
binaries named in the evidence table, without a login, except the probes of 2026-10-15,
which ran sessions under the seat login.

## Terms

| Operator term | Vendor feature | Status and version | Documents |
|---|---|---|---|
| Claude mods | Mods: a Claude Code plugin whose JavaScript or TypeScript event handlers run inside the Claude Code process. A handler can observe, rewrite or answer tool calls, prompts, turns, session events and interface drawing, and reaches files, processes and the network only through the mods API. | On by default from CLI 2.1.287 (Desktop 2.1.286). The newest field the station mod uses, `next.error` re-entry, needs 2.1.292. Section 6 pins the CLI at 2.1.295. A worktree's settings load a mod there in both session modes when the session reads them (Evidence, mod loading); every station session starts with `--setting-sources=` and reads none, which the operator's ruling took as the pin's gate. | [overview](https://code.claude.com/docs/en/plugins/mods/overview), [reference](https://code.claude.com/docs/en/plugins/mods/reference), [events](https://code.claude.com/docs/en/plugins/mods/events), [api](https://code.claude.com/docs/en/plugins/mods/api), [admin](https://code.claude.com/docs/en/plugins/mods/admin) |
| OpenAI's intelligent UI | Intelligent UI: GPT-6 in ChatGPT composes an answer from text, visuals and interactive elements such as buttons and forms. | Rolling out in ChatGPT from 2026-10-07 (Plus, Pro, Business, Enterprise) and 2026-10-08 (Free, Go). No API, SDK, MCP or Codex surface is documented for it. | [announcement](https://community.openai.com/t/gpt-6-and-intelligent-ui-in-chatgpt/1404139); [openai.com post](https://openai.com/index/gpt-6-for-everyone/) refuses an unauthenticated fetch |

Both terms name shipped features, so the assessment runs. Intelligent UI offers the
station nothing to program against, so each area records it as such and then assesses its
programmable neighbours: ChatGPT apps on the Apps SDK (built on the MCP Apps standard),
ChatKit, and the Codex app-server. On the Claude side the neighbours of mods are settings
hooks, skills, channels, the cross-session socket, managed settings, MCP Apps in Claude,
MCP elicitation, Remote Control and `claude plugin eval`.

## 1. Control sessions (sections 6, 7)

| Candidate | Gains | Accepts | Design section | Mechanism it would need |
|---|---|---|---|---|
| Station mod as an in-session guard | `session.compact` answers `{ skip }`, so vendor compaction is refused instead of detected after it fired. `session.measure` fires after each turn and `$.session.usage()` returns context tokens, window and percent, so context size comes from the vendor's own count rather than the transcript. `tool.call` denies write tools in control sessions inside the process (R3). `session.start` reads the effective settings with `$.settings.read` and can refuse to go on when the sandbox differs from the launcher's. Hooks also run under `claude -p`, so workers get the measure and the compaction refusal. | Mods are unsandboxed, against the trust boundary of section 7, where the launcher passes the sandbox settings on every launch so that repository settings cannot loosen them: a mod runs as the agent user, a program it starts with `$.process.run` reaches the network outside the vendor's network policy, and `$.http.fetch` is bounded only by the organisation's web-fetch setting. From 2.1.287 this holds for any mod a session loads, including one a worktree enables, and the agent writes the worktree: on 2.1.295, `extraKnownMarketplaces` naming a directory marketplace inside the worktree with `enabledPlugins` naming its plugin, in `.claude/settings.json` or `.claude/settings.local.json`, loads the plugin's mod and runs its `session.start` hook in a `dontAsk` control session and in an `acceptEdits` worker, with no prompt in either. The same key pair is refused in a session started with `--setting-sources=`, `--setting-sources ''` or `--setting-sources user`, where the plugin directory in the `--settings` object still loads, so the launcher passes `--setting-sources=` on every start and resume (Evidence, mod loading and setting sources). A session can lose the mod after start: three crashes of the hooks worker unload every mod that is not built in until `/reload-plugins` or a new session, and `--safe-mode` starts without installed mods, so a marker written at `session.start` does not show the mod is still loaded. `session.start` and `$.fs.write` run in both modes on 2.1.295. Unverified: the other hooks' behaviour at runtime, under `claude -p` included; and that a missing `session.measure` record detects such an unload. A hook that throws or times out is skipped and the call goes ahead; a `.catch` that answers makes it fail closed, and a failing `.catch` is skipped again. It narrows the blast radius and is never a gate, like the vendor sandbox. TypeScript beside the Rust code. A mods API that adds fields every few releases, so the pin follows it. `$.fs.write` is not atomic. | 6 (compaction and login), 7 (context budget and rollover, trust boundaries), R3, R31, 16 | A core-owned plugin directory named by `CLAUDE_CODE_PLUGIN_DIRS` in the `env` of the settings object the launcher passes on every start and resume (section 6). Against a worktree's files the launcher's layer wins: 2.1.295 loads the directory from the `--settings` object in both modes, and ignores the key in a worktree's `.claude/settings.json` or `.claude/settings.local.json` with a warning in the debug log (`CLAUDE_CODE_PLUGIN_DIRS in .claude/settings.json is ignored — project-scoped settings can't set this key`), so a worktree neither replaces the launcher's directory nor adds one, in either mode; `system/init` lists the mod as `<name>@inline`. A session started with `--setting-sources=` reads no user settings, so the key in `~/.claude/settings.json`, which the agent can write, does neither (Evidence, setting sources). A `.catch` on every gating hook that refuses. `claude plugin validate --strict --json` and `claude plugin test` in `ci`. The launcher fails closed when the mod's `session.start` marker is missing, as it does for bare mode, and kills the session when a turn the transcript records as completed still has no `session.measure` record in the progress file at the next heartbeat after the one that first saw the turn, so a record written just after the transcript is not a kill. The station mod calls none of `$.process.run`, `$.process.spawn` and `$.http.fetch`: a `ci` check reads the call list that `claude plugin validate --strict --json` reports and fails when it names any of them or names no calls at all (unverified: that the JSON report carries the call list the text form prints). |
| Relay lines posted by the mod | A `$.clock.every` timer reads the relay directory and posts each line with `$.prompt.submit`, which resolves when the turn starts: a delivery confirmation the socket never gives. Drops the socket hop, its 30-second line window and the registry lookup on every post. The model reads the line after a sentence naming the mod as its sender, so it stays distinct from typed input. Once no station instruction reaches the socket, every message there is a peer's, so `session.receive` can consume each message with `origin.kind` peer (article 4.5). While the launcher posts to the socket, a core instruction and a peer's message look the same there (section 6), and consuming peer messages would drop the station's own instructions. | Probe: whether `submit` waits until the session is idle, so that a line queues behind a running turn. The relay's ownership, mode and link checks move into the mod only if `$.fs.stat` exposes owner, mode and link count; otherwise the launcher keeps them and the mod reads only lines it validated. Delivery once is rebuilt around a call that resolves at turn start. Which `origin.kind` a line submitted by the mod carries at `session.receive` is not established; if it is peer, consuming every peer message would drop the mod's own relay lines. If the probe returns peer, `session.receive` passes through each line whose idempotency key matches a line the mod submitted and consumes every other peer message; if a submitted line does not carry its key to `session.receive`, peer consumption drops out. | 6 (relay, delivery once), 7 (interactive control sessions receive instructions over the per-session socket) | The station mod above with a bounded poll (eight files a tick, as the launcher does), a posted marker written through the launcher, and the chaos case that kills the session between submit and marker. Peer consumption in `session.receive` only after the launcher's socket post is removed and the adapter writes every instruction to the relay directory, so that nothing of the station's reaches the socket. |
| Settings hook or skill that renders the brief | None over the brief the launcher already hands over. | A hook or a skill's `!command` runs as the agent user and cannot read the store (article 7.1), so it can only read a file the core rendered. An `http` hook pulls on session events and cannot push between turns. | none | none |
| Channels | An MCP server pushes events into a running session. | Research preview; absent from `--help` in 2.1.280 and 2.1.295. Unverified: the same OS-user limits as the socket. An MCP server per session. | none | none |
| Managed settings for the sandbox object | Managed settings sit above `--settings` and are re-read at launch, so a resume needs no flag. | Machine-wide: on the developer's Mac the same policy reaches the developer's own sessions; no per-OS-user scope is documented. | none | none |

Verdict: go for a station mod in Claude sessions that refuses compaction, measures context,
denies write tools in control sessions and asserts the effective settings, once the pin's
gate is met. After a probe, go for posting relay lines with `$.prompt.submit`, and with it
for consuming peer messages, which waits until no station instruction reaches the socket
and follows the outcome of the `origin.kind` probe.
The relay directory, its checks and the secret-checked handler stay; the mod replaces the
socket post, not the relay. No-go on hooks, skills, channels and managed settings for
delivery or for the sandbox object. Vendor coupling stays inside article 7.1: the mod
reads references and the relay directory and writes the progress file, never the store.

## 2. Workers and adapters (sections 6, 13)

| Candidate | Gains | Accepts | Design section | Mechanism it would need |
|---|---|---|---|---|
| Codex permission profile with a writable `.git` | Codex workers commit, so the adapter stops refusing every headless task. The restriction is sandbox policy, not protocol: the built-in `:workspace` profile keeps `.git` read-only, and a named profile granting `".git" = "write"` lifts it while network and paths outside the project stay refused (probe below). | Unverified: that the profile reaches `codex exec` with no protocol change; it was probed only with `codex sandbox`. The worktree's `.git` becomes agent-writable for Codex workers, as it already is for Claude workers, so the core's fetch from the worktree path reads a repository the agent controls for both vendors. The profile lives in config, so the agent's Codex configuration stays core-owned (R24). Codex reads project config layers, and whether a `.codex/config.toml` in the worktree can redefine the profile or `default_permissions` is not established. `allowed_permission_profiles` can lock the choice only from managed requirements, which are machine-wide. | 6 (Codex paragraph), 7 (trust boundaries), R24 | The profile passed on every launch with `-c`, as the Claude sandbox object is, unless a probe shows repository config cannot change it. Boundary tests as the agent user: a commit in the worktree passes; a write outside it, a network request, and a worktree `.codex/config.toml` that widens the profile all fail. |
| App-server as the Codex worker substrate | `thread/tokenUsage/updated` carries `last` usage and `modelContextWindow`, so a Codex worker's context size is measured and the threshold kill works for Codex. `turn/steer` (with `expectedTurnId`) and `turn/interrupt`. `outputSchema` and `sandboxPolicy` per turn. `TurnStatus` is a closed set: `completed`, `interrupted`, `failed`, `inProgress`. `account/rateLimits/updated` reports plan limits. | Unverified: that `thread/tokenUsage/updated` arrives for each turn of a worker under a seat login; the schema was generated without one. Marked experimental in 0.160.1. 104 request methods and 83 notifications, most unrelated to the station (accounts, plugin sharing, realtime audio, feedback upload), so the adapter pins a subset and every other notification decodes to unrecognised. No turn cap in `TurnStartParams`, as under `codex exec`. The worker becomes a JSON-RPC client that holds a turn open for the whole run. | 6 (headless worker results, Codex table, context size), 13 (SessionVendor) | The schema generated from the pinned binary by `codex app-server generate-json-schema`, checked in and compared with a fresh generation in `ci`. A decoder over `TurnStatus`, turn errors and the pinned notifications with an unrecognised state. |
| One packaged extension carrying the tool allowlist and result-file contract into both vendors | One artifact per vendor instead of launcher flags. Claude plugins bundle skills, agents, hooks, MCP servers, default settings and mods; Codex plugins bundle skills, MCP servers and lifecycle hooks. | Neither plugin format has a declarative tool allowlist: Codex denies only from a `PreToolUse` hook, Claude from settings or a mod. The result contract is a per-run flag in both (`--json-schema`, `--output-schema` or `outputSchema`). The exit tables decode process exits and stream events, which no extension changes, so they do not shrink. | none | none |

Verdict: go on the Codex permission profile, which lifts the commit restriction under
`codex sandbox` and, pending the probe that it reaches `codex exec`, under `codex exec`
without the app-server. Go on the app-server as the Codex worker substrate behind the
SessionVendor port, with workers switching from `codex exec` only at parity: every state
in the section 6 Codex exit table maps through the app-server decoder to the same result
state, and the schema generated from the pinned binary diffs empty against the one
checked in. No-go on a cross-vendor extension.

## 3. Decision packets and the inbox (sections 9, 10)

The acceptance criteria are article 7.2 (the human alone resolves a verdict) and article
10.1 (a decision, not a transcript).

| Candidate | Gains | Accepts | Design section | Mechanism it would need |
|---|---|---|---|---|
| Intelligent UI | Buttons and forms in a ChatGPT answer. | No developer surface: nothing the station can render into or receive a verdict from. | none | none |
| ChatGPT app (Apps SDK, MCP Apps) | The packet as a component with its options as buttons; the component calls a tool with the choice. | ChatGPT reaches only remote MCP servers over HTTPS, never localhost, so the core is exposed through a tunnel. ChatGPT is the OAuth 2.1 client and the station runs the authorization server. The packet, with its evidence excerpts and repository paths, goes to OpenAI. The verdict arrives as a tool call from OpenAI's infrastructure in a conversation whose model can call the same tools, so the core cannot tell a click from a model call by anything it verifies itself: fails 7.2. | none | none |
| ChatKit | A chat panel with widgets in a page the station serves. | The script loads from OpenAI's CDN and does not render on a domain that `api.openai.com` has not verified. A chat thread is the wrong shape for a packet (10.1). | none | none |
| MCP Apps in Claude | The packet as interactive UI in claude.ai or Claude Desktop. | Rendered only through a remote connector that Claude reaches from Anthropic's infrastructure; Claude Code does not render it. Same egress and the same 7.2 failure as a ChatGPT app. | none | none |
| MCP elicitation or a mod pane in an agent session | Local; works with a stdio server or inside the process. | The human answers inside a process the agent user runs, so the verdict passes through the agent domain, which can forge it: fails 7.2, which keeps the human's only path through the reader. | none | none |

Verdict: no-go. No vendor surface brings a verdict to the core without either a model that
can call the same tool or the agent domain in the path. The reader's web view and its
secret stay the verdict path.

## 4. Reader surfaces (sections 10, 12)

| Candidate | Gains | Accepts | Design section | Mechanism it would need |
|---|---|---|---|---|
| ChatGPT app or Intelligent UI over the inbox | Inbox, unit states and cases in ChatGPT, read-only from the store-reader's JSON, so no second source of truth. | The same public endpoint and egress as area 3: every inbox item and case summary leaves the machine. | none | none |
| Remote Control, Claude Desktop, Artifacts | The operator follows sessions from claude.ai, the desktop app (`--desktop` in 2.1.295) or a phone. | Remote Control keeps execution local and stores the transcript on Anthropic's servers; an Artifact is a page on claude.ai. Each is a copy of agent-domain content outside the machine (article 7.3). | none | none |
| Read-only mod pane in the developer's own session | Local; draws the inbox from the reader's JSON over localhost. | A third renderer of one packet beside the TUI and the web view, shown only while a Claude session is open; the reader is still needed for the verdict. | none | none |

Verdict: no-go for slice two. The reader's TUI and web view remain the surfaces.

## 5. Evaluation (section 17)

| Candidate | Gains | Accepts | Design section | Mechanism it would need |
|---|---|---|---|---|
| OpenAI Evals API | Hosted graders (string check, text similarity, score and label models, Python) with per-run pass, fail and error counts. | Read-only from 2026-10-31 and shut down on 2026-11-30. API-key auth, billed outside the ChatGPT plan. Data kept by OpenAI until deleted. No human grader. | none | none |
| `claude plugin eval` for rollover fidelity | Runs locally under the seat login. A case's prompt can be the rendered brief and handoff note, or `context.history_file` resumes a transcript. `tool_used` with `min: 0` and `max: 0`, and `regex` with `match: not_contains` on the trace, are deterministic graders that assert a listed dead end is not repeated. Repeated runs per case, a cost ceiling, and a JSON result with `schemaVersion: 1`. | Unverified: a run as the agent user under its seat login; no run was made. Publishes its report to claude.ai by default under a subscription, so `--no-publish` is mandatory (article 7.3). Runs as the invoking user, so the harness runs it as the agent user. A run that hits a plan or rate limit scores zero and the suite is not marked partial. Exit 1 covers both a missed threshold and a case that failed to load. Before 2.1.283 it did not check git's version when turning git hooks off. It evaluates a plugin, so the cases target the station mod's directory. | 17 (metric table, hard gates), 11 (ledger decoding) | A decoder from the result file, not the exit code alone: one or more cases, every one loaded and scored at or above threshold, to a passed examination; a case below threshold to a refused firing; zero cases, a load failure, exit 2, 130 or 143, or a run whose `error` names a usage or rate limit to could not run; anything else to unrecognised. Every record states its case count. Records enter the ledger as agent-domain data, keyed by the result file's digest. |
| Either vendor for the cold-reader packet score | none | Neither vendor measures a human's time to a decision: the Evals API has no human grader and plugin eval grades the model's output. | none | none |

Verdict: go on `claude plugin eval` as the runner for rollover-fidelity cases that gate
changes to prompts, hooks and the station mod, with the decoder above. No-go on the OpenAI
Evals API and on any vendor tool for the packet score, which the harness measures from
verdict timestamps.

## Follow-up issues

The pin is at 2.1.295, where mods run, and no station session reads a settings file. The
relay through the station mod and the rollover-fidelity cases wait on the station mod.

- *Station mod for Claude sessions: compaction refusal, context measure, guards*:
  compaction refusal, context measure into the progress file, write-tool denial in
  control sessions and the settings assertion, loaded from a core-owned plugin directory
  that `env.CLAUDE_CODE_PLUGIN_DIRS` names in the launcher's `--settings` object and
  checked in `ci`, including a check that the mod calls none of `$.process.run`,
  `$.process.spawn` and `$.http.fetch`. The launcher kills a session when a completed
  turn has no `session.measure` record by the next heartbeat after the one that first saw
  it, which covers a mod unloaded mid-session.
- *Post relay lines through the station mod instead of the inbox socket*: after probing
  which fields `$.fs.stat` returns, how a line queues behind a running turn, and which
  `origin.kind` a submitted line carries at `session.receive`. The launcher's socket post
  is removed and the adapter writes every instruction to the relay directory; only then
  does `session.receive` consume peer messages (article 4.5). If the probe returns peer,
  `session.receive` passes through each line whose idempotency key matches a line the mod
  submitted and consumes every other peer message; if a submitted line does not carry its
  key to `session.receive`, peer consumption drops out.
- *Codex worker permission profile with a writable .git*: drop the commit refusal, add
  the boundary tests, and probe that the profile reaches `codex exec` and that a worktree
  `.codex/config.toml` cannot widen it.
- *Codex workers over the app-server with context size*: generated schema checked in and
  compared in `ci`, a decoder over `TurnStatus` and the pinned notifications, and context
  size from `thread/tokenUsage/updated`. Workers switch from `codex exec` at parity: every
  state in the section 6 Codex exit table maps through the app-server decoder to the same
  result state, and the schema generated from the pinned binary diffs empty against the
  one checked in.
- *Rollover-fidelity cases on claude plugin eval*: run as the agent user with
  `--no-publish`, `--json` and `--max-cost-usd`, with the decoder from area 5.

## Evidence

Probes:

| Probe | Binary | Command | Decisive output |
|---|---|---|---|
| Codex built-in profile | codex 0.160.1 | `codex sandbox -P :workspace -C <repo> -- sh -c 'echo b > b; git add b && git commit -m t'` | the file is written; `fatal: Unable to create '<repo>/.git/index.lock': Operation not permitted` |
| Codex `writable_roots` key | codex 0.160.1 | the same, with `-c 'sandbox_workspace_write.writable_roots=["<repo>/.git"]'` | the same refusal |
| Codex named profile | codex 0.160.1 | the profile below, `codex sandbox -P workspace-git -C <repo> -- sh -c '…'` | the commit lands; `curl: (6) Could not resolve host`; a write to `/Users/Shared` gives `Operation not permitted` |
| App-server protocol | codex 0.160.1 | `codex app-server generate-json-schema --out <dir>` | 104 request methods including `turn/steer` and `turn/interrupt`; 83 notifications including `thread/tokenUsage/updated`; `ThreadTokenUsage` has `last`, `total`, `modelContextWindow`; `TurnStartParams` has `outputSchema` and `sandboxPolicy` and no turn cap |
| Mods API names | claude 2.1.280 and 2.1.295 | `claude plugin validate --strict <mod>` on a mod using the hooks and calls of area 1 | both list hooks `session.start`, `session.measure`, `session.compact`, `tool.call{tool=Write}`, `session.receive` and calls `$.clock.every`, `$.fs.list`, `$.fs.read`, `$.fs.write`, `$.prompt.submit`, `$.session.usage`, `$.settings.read`; 2.1.295 adds `gating hook without .catch` for the three gating hooks |
| CLI surface | claude 2.1.280 and 2.1.295 | `claude --help`, `claude plugin eval --help` | no channels flag in either; 2.1.295 adds `--desktop` and `purge`; `--no-publish  Keep the HTML report local only; skip publishing it to claude.ai` |
| Mod loading, positive control (2026-10-15) | claude 2.1.295 | worker: `claude -p --output-format stream-json --verbose --permission-mode acceptEdits --permission-prompts none --max-turns 1 --settings <launcher object> --plugin-dir <mod>`; control: `claude --permission-mode dontAsk --settings <launcher object> --plugin-dir <mod>` on a pty | the `--plugin-dir` mod's marker and the launcher mod's in both; `hooks module probe-p@inline loaded (worker, environment 1, tier user); events: session.start` |
| Mod loading, launcher route (2026-10-15) | claude 2.1.295 | the same without `--plugin-dir`; the launcher object carries `env.CLAUDE_CODE_PLUGIN_DIRS` naming the launcher mod, as in every cell | the launcher mod's marker in both; worker `system/init` lists `probe-a@inline` |
| Mod loading, worktree marketplace route (2026-10-15) | claude 2.1.295 | the launcher's argv; the worktree's `.claude/settings.json` or `.claude/settings.local.json` holds `extraKnownMarketplaces` with a `directory` source inside the worktree and `enabledPlugins` naming its plugin | the worktree mod's marker beside the launcher mod's in all four cells, no dialog in the control session; `Skipped auto-recording probe-w@probe-market — enabled only by repo-authored settings`, then `hooks module probe-w@probe-market loaded (worker, environment 1, tier user)` and `plugin.register: probe-w (user, probe-w@probe-market), judged by core alone: admitted`; worker `system/init` lists `probe-w@probe-market` |
| Mod loading, worktree `CLAUDE_CODE_PLUGIN_DIRS` route and settings layer (2026-10-15) | claude 2.1.295 | the launcher's argv; `env.CLAUDE_CODE_PLUGIN_DIRS` naming a mod in the worktree, in either file | the launcher mod's marker and not the worktree mod's in all four cells; `[WARN] CLAUDE_CODE_PLUGIN_DIRS in .claude/settings.local.json is ignored — project-scoped settings can't set this key. Set it in ~/.claude/settings.json or managed settings instead.` |
| Setting sources (2026-10-15) | claude 2.1.295 | the launcher's argv with the worktree marketplace route, started with `--setting-sources user` or `--setting-sources ''`; then `--setting-sources ''` in a copy of a home where a session had recorded the worktree's marketplace in `known_marketplaces.json`, and in that copy after `claude plugin install probe-w@probe-market --scope user` | the launcher mod's marker and not the worktree mod's in all twelve cells; no `hooks module probe-w` line |
| Managed guard | claude 2.1.295 | `allowManagedModsOnly` and `disableSideloadFlags` in `/Library/Application Support/ClaudeCode/managed-settings.json`, the station's probe mod as an organisation mod, the cells above as the agent user | not run: writing managed settings and running as the agent both need sudo, and the operator's ruling took setting sources as the pin's gate instead |
| Section 6 events (2026-10-15) | claude 2.1.295 | `claude -p --output-format stream-json --verbose` with the session token, with an invalid token, and with `--bare` | the token run: `system/init` with `claude_code_version` 2.1.295, `apiKeySource` none and a `messaging_socket_path`, a `rate_limit_event`, then `result` `success`; the invalid token: an `authentication_failed` assistant error and `result` `success` with `is_error` and `api_error_status` 401; `--bare`: `system/init` with no `messaging_socket_path` and three tools. The binary names the same five result subtypes as 2.1.280 |
| Section 6 suites (2026-10-15) | claude 2.1.295 | `mise run worker-tests`, `mise run control-tests` and `mise run spine-tests` with the pin and `CLAUDE_PINNED_VERSION` at 2.1.295 in the working tree only | worker 3 passed: a completed run with a commit and context tokens, a turn cap decoded as a re-plan, and an escalation, each past the banner and bare-mode checks; control 3 passed: a socket post confirmed by the registry, a permission prompt that stalls the inbox while `dontAsk` does not, and a resume with the settings passed again, each naming `2.1.295 (Claude Code)` as its binary's version; spine 18 passed |
| Session sandbox destinations, Claude (2026-10-25) | claude 2.1.280 | `mise run worker-tests` and `mise run vendor-sandbox-tests` through the session proxy, with Claude's telemetry, error reporting and update switches off in its environment | each worker run's proxy line: 3 to 6 CONNECTs to `api.anthropic.com`, allowed, and nothing else tried by Claude itself; under the developer's home, the developer's user-level MCP servers `mcp.slack.com:443` and `mcp.context7.com:443`, 16 attempts a run, refused and recorded |
| Destinations before the switches (2026-10-20, nono CLI) | claude 2.1.280 | `nono run --allow-domain api.anthropic.com …` without the telemetry variables | telemetry to `datadoghq.com` refused; the run granted `claude.ai`, `statsig.anthropic.com` and `sentry.io` as well, so whether Claude tries them is not recorded |
| Destinations, Codex (2026-10-21, nono CLI) | codex 0.160.1 | `codex exec --sandbox danger-full-access` under a profile allowing `chatgpt.com`, `api.openai.com` and `auth.openai.com` | the model answered; two `oaiusercontent.com` hosts tried and refused; `github.com` refused |
| Vendor sandbox under the station's (2026-10-25) | claude 2.1.280 | `claude -p` as the worker runs it, through the session proxy and `tycho session-leader`, asked to run `echo probe-$((6*7))` with Bash: the launcher's `--settings` with the sandbox off and no worktree setting; the same with a worktree `.claude/settings.json` turning the sandbox on with `failIfUnavailable` and no unsandboxed retry; that object passed by the launcher instead | `probe-42` in the first two cells; in the third, `Sandbox is required but failed to initialize: EPERM: operation not permitted, listen '/tmp/srt-mux-<pid>-2.sock'`. The launcher's layer wins in the worker mode; the control mode is not probed |
| Configuration save under the station's sandbox (2026-10-25) | claude 2.1.280 | `claude -p` in a fresh home seeded with `{"numStartups":0}` in `.claude.json`, unsandboxed and sandboxed, with the file granted alone and then with its `.claude.json.<suffix>` siblings | unsandboxed, the save writes ten keys (`firstStartTime`, `userID`, `machineID` among them); sandboxed with the file alone, the seed is unchanged; with the siblings, the same ten keys |
| Setting sources, the launcher's word (2026-10-25) | claude 2.1.295 | the four worktree marketplace-route cells, each file in each mode, with the launcher's argv ending `--setting-sources=` and its object carrying Claude's sandbox off and the Bash allow rule; and, with an invalid token, a worktree `settings.json` setting an output style, started with no flag, `--setting-sources=` and `--setting-sources ''` | the launcher mod's marker and not the worktree mod's in all four cells; `system/init` reports the worktree's output style without the flag and `default` with either spelling |
| What a session reads (2026-10-25) | claude 2.1.295 | the worker's argv with an invalid token, so the run ends in a 401 after `system/init`; a fresh home and worktree per cell with one location planted, each with and without `--setting-sources=`: the worktree's `.claude/settings.json` (an output style, a `SessionStart` hook, a deny rule) with a `.mcp.json` server and project commands, skills and agents; the same settings in `.claude/settings.local.json`; the same in `~/.claude/settings.json` with user commands, skills and agents; MCP servers in `~/.claude.json`, global and per project; then the launcher's object carrying an output style, a hook and `env.CLAUDE_CODE_PLUGIN_DIRS` | without the flag each planted item shows at `system/init` or its hook runs; with it none does: output style `default`, no probe server, command, skill or agent, no hook event; the launcher's output style, hook and `probe-a@inline` apply with and without the flag; 10 cells, all ran |
| Memory files (2026-10-25) | claude 2.1.295 | one haiku turn per cell asking for the codewords its instructions give, with one in each of the worktree's `CLAUDE.md`, `.claude/CLAUDE.md` and `CLAUDE.local.md` and the user's `~/.claude/CLAUDE.md` | all four without the flag; none with `--setting-sources=` |
| Settings layers in both modes under the station's sandbox (2026-10-25) | claude 2.1.295 | worker: `mise run vendor-sandbox-tests`, with the worktree's `settings.json` and `settings.local.json` and the user's `settings.json` turning Claude's sandbox on and denying Bash; control: `mise run control-tests`, a `dontAsk` session started through the launcher with the worktree's files turning the sandbox on and running a `SessionStart` hook, and the launcher's object running another | worker: the Bash call runs with the files in place; with the worker's words less `--setting-sources=` the files apply and Bash is taken out of the session (`No such tool available: Bash`); the launcher's object with the sandbox on refuses the call; control: the launcher's hook ran and the worktree's did not |
| Section 6 on the pin (2026-10-25) | claude 2.1.295 | the worker's command line captured into `crates/tycho/src/fixtures/claude-worker-*.jsonl` in a fresh home; `mise run worker-tests` and `mise run control-tests` | captures: a run that commits ends `success`; `--max-turns 1` ends `error_max_turns`; `--bare` gives an init with no `messaging_socket_path`, after a `system/ui_invalidate` event 2.1.280 did not write; no `USER` and no token ends with an `authentication_failed` error and `result` `success` with `is_error`; worker 3 passed, each proxy line 3 CONNECTs allowed and none refused, where 2.1.280 under the same home tried the developer's user-level MCP servers; control 3 passed: a socket post confirmed by the registry, `dontAsk` never waiting, and a resumed process whose command line carries the settings object and `--setting-sources=` once |

The mod-loading probes ran as the developer, not as `tycho-agent`: running as the agent
asks for a password, so that run is the operator's. Each cell had a fresh `HOME` holding
an empty `~/.claude/settings.json` and a `.claude.json` that trusts the worktree, or a copy
of an earlier cell's home and worktree; a fresh git worktree; the session credential in
`CLAUDE_CODE_OAUTH_TOKEN`; and the launcher's settings object (the sandbox of section 7,
inbound accept, the auto-compact window) naming the launcher mod's directory in
`env.CLAUDE_CODE_PLUGIN_DIRS`. The machine has no managed settings, so the built-in guard
was not observed. Each probe mod's `session.start` hook wrote a marker file beside the
worktree, and a cell counts as run only when the launcher mod's marker is there, so a
session that stopped before its plugins loaded reads as could not run, never as a
refusal; a control session ran 50 seconds and answered one typed prompt. The script
examines 24 cells: two `--plugin-dir` controls, two launcher-route cells, eight route
cells, which also answer the settings-layer question, and twelve setting-sources cells;
all 24 ran, and the worktree's mod loaded in the four marketplace-route cells only.

The probes of 2026-10-25 also ran as the developer, each cell in a fresh home and git
worktree laid out the same way. The marketplace cells with the launcher's word examined 4 cells and all ran; the
read probe ran with an invalid token, so it spends no turn, and examined 10; the memory
probe examined 2. The suites ran the binary `mise which claude` names in the worktree,
`~/.local/share/mise/installs/claude/2.1.295/claude`.

The named profile:

```toml
[permissions.workspace-git.filesystem]
":root" = "read"
":tmpdir" = "write"

[permissions.workspace-git.filesystem.":project_roots"]
"." = "write"
".git" = "write"

[permissions.workspace-git.network]
enabled = false
```

Claude documents: [mods overview](https://code.claude.com/docs/en/plugins/mods/overview),
[mods reference](https://code.claude.com/docs/en/plugins/mods/reference),
[mods events](https://code.claude.com/docs/en/plugins/mods/events),
[mods API](https://code.claude.com/docs/en/plugins/mods/api),
[mods admin](https://code.claude.com/docs/en/plugins/mods/admin),
[cross-session messaging](https://code.claude.com/docs/en/cross-session-messaging),
[channels](https://code.claude.com/docs/en/channels),
[hooks](https://code.claude.com/docs/en/hooks),
[managed settings](https://code.claude.com/docs/en/managed-settings),
[sessions](https://code.claude.com/docs/en/sessions),
[plugin components](https://code.claude.com/docs/en/plugins/components),
[skills](https://code.claude.com/docs/en/skills),
[MCP and elicitation](https://code.claude.com/docs/en/mcp),
[Remote Control](https://code.claude.com/docs/en/remote-control),
[artifacts](https://code.claude.com/docs/en/artifacts),
[plugin evals](https://code.claude.com/docs/en/plugin-evals),
[MCP Apps in Claude](https://claude.com/docs/connectors/building/mcp-apps/quickstart).

OpenAI documents: [Intelligent UI announcement](https://community.openai.com/t/gpt-6-and-intelligent-ui-in-chatgpt/1404139),
[app-server](https://learn.chatgpt.com/docs/app-server),
[permissions](https://learn.chatgpt.com/docs/permissions),
[hooks](https://learn.chatgpt.com/docs/hooks),
[skills and plugins](https://learn.chatgpt.com/docs/skills-and-plugins),
[`.git` under workspace-write](https://github.com/openai/codex/issues/15505),
[MCP Apps in ChatGPT](https://developers.openai.com/apps-sdk/mcp-apps-in-chatgpt),
[Apps SDK deploy](https://developers.openai.com/apps-sdk/deploy),
[app auth](https://developers.openai.com/plugins/build/auth),
[developer mode](https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt),
[ChatKit script hosting](https://github.com/openai/chatkit-js/issues/57),
[ChatKit domain keys](https://github.com/openai/chatkit-js/issues/62),
[Evals guide](https://developers.openai.com/api/docs/guides/evals),
[Evals output items](https://developers.openai.com/api/reference/resources/evals/subresources/runs/subresources/output_items/methods/list),
[data retention](https://developers.openai.com/api/docs/guides/your-data).

Unverified claims: 13, each stated above as unverified or as a probe.

| Claim | Settled by |
|---|---|
| A session of the agent user started with `--setting-sources=` refuses a worktree's mod and reads no settings file, as the developer's does | the operator's run of the mod-loading and setting-sources cells as the agent |
| The mod's hooks other than `session.start` behave at runtime as documented, under `claude -p` included | the pin, then the `ci` tests in *Station mod for Claude sessions: compaction refusal, context measure, guards* |
| A completed turn with no `session.measure` record by the next heartbeat detects a mod unloaded mid-session | liveness test in *Station mod for Claude sessions: compaction refusal, context measure, guards* |
| `$.fs.stat` returns owner, mode and link count | probe in *Post relay lines through the station mod instead of the inbox socket* |
| How a line submitted with `$.prompt.submit` queues behind a running turn | probe in *Post relay lines through the station mod instead of the inbox socket* |
| A line submitted by the mod reaches `session.receive` with an `origin.kind` other than peer | probe in *Post relay lines through the station mod instead of the inbox socket* |
| The named Codex profile reaches `codex exec`, not only `codex sandbox` | probe in *Codex worker permission profile with a writable .git* |
| A worktree `.codex/config.toml` cannot redefine the profile or `default_permissions` | boundary test in *Codex worker permission profile with a writable .git* |
| `thread/tokenUsage/updated` arrives for each turn of a worker under a seat login; the schema was generated without one | parity run in *Codex workers over the app-server with context size* |
| The JSON report of `claude plugin validate --strict --json` carries the call list the text form prints | the call-list check in *Station mod for Claude sessions: compaction refusal, context measure, guards* |
| `claude plugin eval` scores cases when run as the agent user under its seat login | first run in *Rollover-fidelity cases on claude plugin eval* |
| A Codex worker commits in its worktree under the station's sandbox with Codex's own sandbox off | a Codex worker run under the session sandbox, then the adapter's commit refusal lifted |
| Channels carry the same OS-user limits as the socket | none; the no-go rests on the research-preview status |
