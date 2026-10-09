# Vendor extensions and surfaces

A time-boxed assessment of whether Claude Code mods and OpenAI's Intelligent UI, with the
extension points and surfaces around them, should carry part of the station. Each area
ends in a go or no-go, and the go verdicts become the follow-up issues listed at the end.
Section numbers refer to `design.html`, article numbers to `mandate.md`. Vendor documents
were read on 2026-10-09; probes ran against the binaries named in the evidence table,
without a login.

## Terms

| Operator term | Vendor feature | Status and version | Documents |
|---|---|---|---|
| Claude mods | Mods: a Claude Code plugin whose JavaScript or TypeScript event handlers run inside the Claude Code process. A handler can observe, rewrite or answer tool calls, prompts, turns, session events and interface drawing, and reaches files, processes and the network only through the mods API. | On by default from CLI 2.1.287 (Desktop 2.1.286). The newest field the station mod uses, `next.error` re-entry, needs 2.1.292. Section 6 records the CLI at 2.1.280, where mods ran only behind an early-access variable that 2.1.287 and later ignore; the pin moves under the follow-up issue that pins 2.1.295. | [overview](https://code.claude.com/docs/en/plugins/mods/overview), [reference](https://code.claude.com/docs/en/plugins/mods/reference), [events](https://code.claude.com/docs/en/plugins/mods/events), [api](https://code.claude.com/docs/en/plugins/mods/api), [admin](https://code.claude.com/docs/en/plugins/mods/admin) |
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
| Station mod as an in-session guard | `session.compact` answers `{ skip }`, so vendor compaction is refused instead of detected after it fired. `session.measure` fires after each turn and `$.session.usage()` returns context tokens, window and percent, so context size comes from the vendor's own count rather than the transcript. `tool.call` denies write tools in control sessions inside the process (R3). `session.start` reads the effective settings with `$.settings.read` and can refuse to go on when the sandbox differs from the launcher's. Hooks also run under `claude -p`, so workers get the measure and the compaction refusal. | Mods are unsandboxed, against the trust boundary of section 7, where the launcher passes the sandbox settings on every launch so that repository settings cannot loosen them: a mod runs as the agent user, a program it starts with `$.process.run` reaches the network outside the vendor's network policy, and `$.http.fetch` is bounded only by the organisation's web-fetch setting. From 2.1.287 this holds for any mod a session loads, including one a repository's settings could enable in a control session or in a worker, whose worktree's `.claude/settings.json` and `.claude/settings.local.json` the agent writes, so the pin waits on a probe of that path in both modes. A session can lose the mod after start: three crashes of the hooks worker unload every mod that is not built in until `/reload-plugins` or a new session, and `--safe-mode` starts without installed mods, so a marker written at `session.start` does not show the mod is still loaded. Unverified: the hooks' behaviour at runtime, under `claude -p` included, since the probe parsed the mod without running it; and that a missing `session.measure` record detects such an unload. A hook that throws or times out is skipped and the call goes ahead; a `.catch` that answers makes it fail closed, and a failing `.catch` is skipped again. It narrows the blast radius and is never a gate, like the vendor sandbox. TypeScript beside the Rust code. A mods API that adds fields every few releases, so the pin follows it. `$.fs.write` is not atomic. | 6 (compaction and login), 7 (context budget and rollover, trust boundaries), R3, R31, 16 | A core-owned plugin directory loaded through `CLAUDE_CODE_PLUGIN_DIRS` in the `env` of the agent user's core-owned settings, so every start and resume loads it with no flag. A `.catch` on every gating hook that refuses. `claude plugin validate --strict --json` and `claude plugin test` in `ci`. The launcher fails closed when the mod's `session.start` marker is missing, as it does for bare mode, and kills the session when a turn the transcript records as completed still has no `session.measure` record in the progress file at the next heartbeat after the one that first saw the turn, so a record written just after the transcript is not a kill. The station mod calls none of `$.process.run`, `$.process.spawn` and `$.http.fetch`: a `ci` check reads the call list that `claude plugin validate --strict --json` reports and fails when it names any of them or names no calls at all (unverified: that the JSON report carries the call list the text form prints). If the pin's gate is met with the built-in guard's `allowManagedModsOnly`, a mod loaded from a plugin directory counts as a user's and is refused, so the station mod loads as an organisation mod instead: managed `enabledPlugins` and a directory marketplace named by absolute path. |
| Relay lines posted by the mod | A `$.clock.every` timer reads the relay directory and posts each line with `$.prompt.submit`, which resolves when the turn starts: a delivery confirmation the socket never gives. Drops the socket hop, its 30-second line window and the registry lookup on every post. The model reads the line after a sentence naming the mod as its sender, so it stays distinct from typed input. Once no station instruction reaches the socket, every message there is a peer's, so `session.receive` can consume each message with `origin.kind` peer (article 4.5). While the launcher posts to the socket, a core instruction and a peer's message look the same there (section 6), and consuming peer messages would drop the station's own instructions. | `submit` waits until the session is idle, so a line queues behind a running turn. The relay's ownership, mode and link checks move into the mod only if `$.fs.stat` exposes owner, mode and link count; otherwise the launcher keeps them and the mod reads only lines it validated. Delivery once is rebuilt around a call that resolves at turn start. Which `origin.kind` a line submitted by the mod carries at `session.receive` is not established; if it is peer, consuming every peer message would drop the mod's own relay lines. If the probe returns peer, `session.receive` passes through each line whose idempotency key matches a line the mod submitted and consumes every other peer message; if a submitted line does not carry its key to `session.receive`, peer consumption drops out. | 6 (relay, delivery once), 7 (interactive control sessions receive instructions over the per-session socket) | The station mod above with a bounded poll (eight files a tick, as the launcher does), a posted marker written through the launcher, and the chaos case that kills the session between submit and marker. Peer consumption in `session.receive` only after the launcher's socket post is removed and the adapter writes every instruction to the relay directory, so that nothing of the station's reaches the socket. |
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

The pin comes first: mods run only from 2.1.287, and the mod probe here parsed a mod
without running it. The station mod, the relay through it and the rollover-fidelity cases
wait on the pin; the relay and the rollover-fidelity cases also wait on the station mod.

- *Pin Claude Code at 2.1.295 and re-run the section 6 probes*: the worker exit table,
  bare mode, the socket registry and settings on resume. Probe as the agent user whether
  a plugin with a mod enabled from a worktree's `.claude/settings.json` or
  `.claude/settings.local.json` loads in an interactive `dontAsk` control session and in a
  `claude -p --permission-mode acceptEdits` worker. The pin moves only when that probe
  shows a refusal for both files in both modes, or when the built-in guard's
  `allowManagedModsOnly`, with `disableSideloadFlags`, is shown refusing such a mod in
  both modes for the agent user; both are managed settings and so machine-wide, as the
  managed settings row of area 1 records.
- *Station mod for Claude sessions: compaction refusal, context measure, guards*:
  compaction refusal, context measure into the progress file, write-tool denial in
  control sessions and the settings assertion, loaded through the agent user's
  core-owned settings and checked in `ci`, including a check that the mod calls none of
  `$.process.run`, `$.process.spawn` and `$.http.fetch`. The launcher kills a session
  when a completed turn has no `session.measure` record by the next heartbeat after the
  one that first saw it, which covers a mod unloaded mid-session. Probes as the agent
  user: whether `prependPlugins` in user settings takes effect for that login, and
  whether `system/init` names a mod loaded through `CLAUDE_CODE_PLUGIN_DIRS`.
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

Unverified claims: 14, each stated above as unverified or as a probe.

| Claim | Settled by |
|---|---|
| A worktree's `.claude/settings.json` or `.claude/settings.local.json` cannot enable a plugin with a mod in a `dontAsk` control session or an `acceptEdits` worker of the agent user | probe in *Pin Claude Code at 2.1.295 and re-run the section 6 probes* |
| The mod's hooks behave at runtime as documented, under `claude -p` included; the probe parsed the mod and never ran it | the pin, then the `ci` tests in *Station mod for Claude sessions: compaction refusal, context measure, guards* |
| `prependPlugins` in user settings takes effect for the agent user's login | probe in *Station mod for Claude sessions: compaction refusal, context measure, guards* |
| `system/init` names a mod loaded through `CLAUDE_CODE_PLUGIN_DIRS` | probe in *Station mod for Claude sessions: compaction refusal, context measure, guards* |
| A completed turn with no `session.measure` record by the next heartbeat detects a mod unloaded mid-session | liveness test in *Station mod for Claude sessions: compaction refusal, context measure, guards* |
| `$.fs.stat` returns owner, mode and link count | probe in *Post relay lines through the station mod instead of the inbox socket* |
| How a line submitted with `$.prompt.submit` queues behind a running turn | probe in *Post relay lines through the station mod instead of the inbox socket* |
| A line submitted by the mod reaches `session.receive` with an `origin.kind` other than peer | probe in *Post relay lines through the station mod instead of the inbox socket* |
| The named Codex profile reaches `codex exec`, not only `codex sandbox` | probe in *Codex worker permission profile with a writable .git* |
| A worktree `.codex/config.toml` cannot redefine the profile or `default_permissions` | boundary test in *Codex worker permission profile with a writable .git* |
| `thread/tokenUsage/updated` arrives for each turn of a worker under a seat login; the schema was generated without one | parity run in *Codex workers over the app-server with context size* |
| The JSON report of `claude plugin validate --strict --json` carries the call list the text form prints | the call-list check in *Station mod for Claude sessions: compaction refusal, context measure, guards* |
| `claude plugin eval` scores cases when run as the agent user under its seat login | first run in *Rollover-fidelity cases on claude plugin eval* |
| Channels carry the same OS-user limits as the socket | none; the no-go rests on the research-preview status |
