package figures

import "github.com/frits-v/tycho-station/figures/grammar:tycho"

figures: topology: tycho.#Figure & {
	#page: {
		title:  "Topology"
		kicker: "Tycho Station"
		lede:   "Human surfaces attach to zmx sessions; root, control and worker sessions run under zmx; the durable core lives outside every repo."
		width:  1040
		body: [{
			tag: "Col"
			gap: 48
			children: [
				{
					tag:   "Box"
					kind:  "zone"
					id:    "surfaces"
					label: "HUMAN SURFACES, DISPOSABLE READERS"
					children: [{tag: "Row", children: [
						_surface & {id: "ghostty", title: "Ghostty", subtitle: "tabs via AppleScript"},
						_surface & {id: "tui", title: "TUI", subtitle: "inbox, feed, focus"},
						_surface & {id: "web", title: "Web view", subtitle: "localhost, SSE"},
						_surface & {id: "notifications", title: "Notifications", subtitle: "link to web"},
					]}]
				},
				{tag: "Row", grow: [3, 1], children: [
					{
						tag:   "Box"
						kind:  "host"
						id:    "zmx"
						label: "ZMX: ONE DAEMON PER SESSION, OWNS THE PTY"
						children: [{tag: "Col", gap: 28, children: [
							{tag: "Row", grow: [1, 1], gap: 24, children: [
								{tag: "Item", kind: "root", id: "root", title: "Root control session", subtitle: "orchestrator of orchestrators; never edits", facts: [{text: "cf7a.root.claude", source: "built"}]},
								{tag: "Item", kind: "process", id: "reader", title: "Reader binary", subtitle: "serves TUI and web view from the store; restartable at any time"},
							]},
							{tag: "Row", gap: 24, children: [
								{tag: "Col", gap: 28, children: [
									{tag: "Item", kind: "control", id: "wu03", title: "Control session, work unit 03", facts: [{text: "cf7a.wu03.ctl.codex", source: "built"}]},
									{tag: "Row", children: [
										_worker & {id: "w1", title: "wu03.wrk.claude.a1f3"},
										_worker & {id: "w2", title: "wu03.wrk.codex.b77e"},
									]},
								]},
								{tag: "Col", gap: 28, children: [
									{tag: "Item", kind: "control", id: "wu04", title: "Control session, work unit 04", facts: [{text: "cf7a.wu04.ctl.claude", source: "built"}]},
									{tag: "Row", children: [
										_worker & {id: "w3", title: "wu04.wrk.claude.c201"},
										_worker & {id: "w4", title: "wu04.wrk.agy.d9c4"},
									]},
								]},
							]},
							{tag: "Text", body: ["workers: headless, stream-json, one task each, exit when done"]},
						]}]
					},
					{
						tag:   "Box"
						kind:  "host"
						id:    "core"
						label: "DURABLE CORE, OUTSIDE EVERY REPO"
						children: [
							{tag: "Item", kind: "process", id: "restate", title: "Restate server", subtitle: "one binary under zmx: journal, state, timers"},
							{tag: "Item", kind: "object", id: "services", title: "Factory services", subtitle: "Rust endpoint: epic, work unit, escalation, packet"},
							{tag: "Item", kind: "store", title: "Read model", subtitle: "SQLite graph, rebuilt from handlers"},
							{tag: "Item", kind: "store", title: "Case law and blobs", subtitle: "JSON per case, content-addressed artifacts"},
						]
					},
				]},
				{tag: "Item", kind: "store", title: "Canonical repo", subtitle: "core-owned bare repo; children write only to worktrees; the core verifies, fast-forwards default, then syncs to any remote"},
			]
		}]
		legend: [tycho.legend.awaitable, tycho.legend.signal, tycho.legend.attach]
		links: [
			tycho.#Attach & {from: "ghostty", to: "root", label: "zmx attach"},
			tycho.#Attach & {from: "tui", to: "reader", from_side: "bottom", to_side: "top"},
			tycho.#Attach & {from: "web", to: "reader", label: "reads store via reader", from_side: "bottom", to_side: "top"},
			tycho.#Attach & {from: "notifications", to: "core", label: "read only"},
			tycho.#Awaitable & {from: "root", to: "wu03", from_side: "bottom", to_side: "top"},
			tycho.#Awaitable & {from: "root", to: "wu04", from_side: "bottom", to_side: "top"},
			tycho.#Awaitable & {from: "wu03", to: "w1"},
			tycho.#Awaitable & {from: "wu03", to: "w2"},
			tycho.#Awaitable & {from: "wu04", to: "w3"},
			tycho.#Awaitable & {from: "wu04", to: "w4"},
			tycho.#Signal & {from: "root", to: "restate"},
			tycho.#Signal & {from: "wu04", to: "services"},
		]
	}
}

_surface: {tag: "Item", kind: "surface"}
_worker: {tag: "Item", kind: "worker"}
