package figures

import "github.com/frits-v/tycho-station/figures/grammar:tycho"

figures: lifecycle: tycho.#Figure & {
	#page: {
		title:  "Work unit lifecycle"
		kicker: "WorkUnit workflow"
		lede:   "The states of the WorkUnit workflow's run handler and the awaits that move a unit between them."
		width:  820
		body: [{
			tag:   "Box"
			kind:  "workflow"
			label: "WorkUnit run handler"
			children: [
				_step & {id: "queued", title: "queued"},
				_down & {label: "child claims lease", from: "queued", to: "claimed"},
				_step & {id: "claimed", title: "claimed"},
				_down & {label: "first status", from: "claimed", to: "running"},
				{tag: "Row", grow: [2, 0, 3], children: [
					_step & {id: "running", title: "running"},
					{tag: "Col", gap: 64, children: [
						{tag: "Col", gap: 4, children: [
							_right & {label: "silence > T1", from: "running", to: "stalled"},
							tycho.#Signal & {tag: "Pipe", dir: "h", arrow: "start", label: "nudge answered", from: "running", to: "stalled"},
						]},
						{tag: "Col", children: [
							tycho.#Failure & {tag: "Pipe", dir: "h", arrow: "end", label: "worker gave up", from: "running", to: "retry"},
						]},
						{tag: "Col", gap: 4, children: [
							_right & {label: "give-up rule hit", from: "running", to: "escalated"},
							tycho.#Signal & {tag: "Pipe", dir: "h", arrow: "start", label: "verdict", from: "running", to: "escalated"},
						]},
					]},
					{tag: "Col", gap: 0, justify: "center", children: [
						_step & {id: "stalled", title: "stalled"},
						tycho.#Failure & {tag: "Pipe", dir: "v", arrow: "end", label: "no progress > T2: kill, attempt+1"},
						_step & {id: "retry", title: "retry queued"},
						_down & {label: "attempt > max", from: "retry", to: "escalated"},
						{tag: "Row", gap: 4, children: [
							_step & {id: "escalated", title: "escalated"},
							_right & {label: "verdict: abandon"},
							_step & {id: "abandoned", title: "abandoned"},
						]},
					]},
				]},
				{tag: "Row", gap: 8, children: [
					_down & {label: "result: done", from: "running", to: "verifying"},
					tycho.#Failure & {tag: "Pipe", dir: "v", arrow: "start", label: "criteria fail: findings, attempt+1", from: "running", to: "verifying"},
				]},
				_step & {id: "verifying", title: "verifying"},
				_down & {label: "fresh checkout, criteria pass"},
				_step & {id: "fast-forward", title: "fast-forward"},
				_down & {label: "default advanced"},
				_step & {id: "merged", title: "merged"},
				_down & {label: "prune, checkpoint"},
				_step & {id: "done", title: "done"},
			]
		}]
		legend: [tycho.legend.awaitable, tycho.legend.failure, tycho.legend.signal]
		links: [
			tycho.#Awaitable & {from: "retry", to: "claimed", label: "backoff done", from_side: "right", to_side: "bottom", via: [{x: 760, y: 274}]},
		]
	}
}

_step: {tag: "Item", kind: "step"}
_down: tycho.#Awaitable & {tag: "Pipe", dir: "v", arrow: "end"}
_right: tycho.#Awaitable & {tag: "Pipe", dir: "h", arrow: "end"}
