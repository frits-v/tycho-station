package figures

import "github.com/frits-v/tycho-station/figures/grammar:tycho"

figures: escalation: tycho.#Figure & {
	#page: {
		title:  "Escalation ladder"
		kicker: "Escalation and arbitration"
		lede:   "A question climbs from the worker to its control session, the parent control and the human, and each rung has a give-up rule."
		body: [{
			tag: "Col"
			gap: 40
			children: [
				_rung & {children: [
					{tag: "Item", kind: "human", id: "human", title: "Human", subtitle: "decision packet in; binding case out"},
					{tag: "Col", gap: 12, children: [{tag: "Text", heading: "GIVE-UP RULE TO REACH THIS RUNG", body: ["Council failed, or authority reserved to the human: spend, external commitments, data deletion, epic scope, hook-marked human-only, or the ruling would overrule a human case."]}]},
				]},
				_rung & {children: [
					{tag: "Item", kind: "control", id: "parent", title: "Parent control, arbiter L2 .. root", subtitle: "same steps, wider scope"},
					{tag: "Col", gap: 12, children: [{tag: "Text", body: ["Council failed (no quorum, or an unrefuted blocking dissent), or the question crosses the work unit boundary: other worktrees, shared interfaces, epic acceptance criteria, budget."]}]},
				]},
				_rung & {children: [
					{tag: "Item", kind: "control", id: "control", title: "Control session, arbiter L1", subtitle: "rules alone or convenes a council"},
					{tag: "Col", gap: 12, children: [{tag: "Text", body: ["Blocker reproduced; at least two distinct attempts logged with outcomes; case law queried; question typed with options. Immediate if outside worker authority: scope, interface, irreversible action, security."]}]},
				]},
				_rung & {children: [
					{tag: "Item", kind: "worker", id: "worker", title: "Worker", subtitle: "implements; may not rule"},
					{tag: "Col", gap: 12, children: [
						{tag: "Text", heading: "AT EVERY ARBITER", body: ["1 empirical: probe   2 fresh binding precedent: cite   3 no council trigger: rule alone   4 else council"]},
						{tag: "Text", body: ["An escalation with no proposed ruling is sent back down. Unpicked escalations move up after a timeout, with a cap."]},
					]},
				]},
			]
		}]
		legend: []
		links: [
			tycho.#Awaitable & {from: "worker", to: "control", from_side: "top", to_side: "bottom"},
			tycho.#Awaitable & {from: "control", to: "parent", from_side: "top", to_side: "bottom"},
			tycho.#Awaitable & {from: "parent", to: "human", from_side: "top", to_side: "bottom"},
		]
	}
}

_rung: {tag: "Row", grow: [1, 2], gap: 32}
