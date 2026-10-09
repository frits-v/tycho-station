// The tycho grammar: the kinds the design's figures draw, the line kinds, and
// the light and dark theme tokens of the design page. `grammar` is exported to
// tycho.json beside every exported figure, which names it by that path.
package tycho

import (
	"list"

	"github.com/frits-v/stencil/cue:stencil"
)

grammar: stencil.#Grammar & {
	name: "tycho"
	containers: [
		{
			name:     "host"
			role:     "boundary"
			tone:     "strong"
			tintable: false
			border: {pattern: "dashed", width: 1.5}
			padding: 12
			radius:  8
			label:   "plain"
			parents: ["page"]
		},
		{
			name:     "zone"
			role:     "boundary"
			tone:     "strong"
			tintable: false
			border: {pattern: "dashed", width: 1.5}
			padding: 12
			radius:  8
			label:   "plain"
			parents: ["page", "host"]
		},
		{
			name:     "workflow"
			role:     "group"
			tone:     "neutral"
			tintable: true
			border: {pattern: "solid", width: 1.5}
			padding: 12
			radius:  8
			label:   "plain"
			parents: ["page", "host"]
		},
	]
	items: [for itemName in _itemNames {
		name:  itemName
		icons: "none"
		products: []
		parents: list.Concat([[for c in containers {c.name}], ["page"]])
		if itemName == "human" {shape: "figure"}
		if itemName == "store" {shape: "cylinder"}
		if itemName != "human" && itemName != "store" {shape: "block"}
	}]
	remembered: []
}

// Sessions are root, control and worker; a surface is a disposable reader a
// human looks through; a process is a long-lived binary that is not a session;
// an object is a keyed Restate service; a step is one stretch of a workflow
// handler between awaits.
_itemNames: ["root", "control", "worker", "human", "surface", "process", "object", "step", "store"]

_nesting: stencil.#GrammarNesting & {#grammar: grammar}

#Page: _nesting.#KindedPage & {
	chrome: "none"
	canvas: "customer"
	width:  *960 | int
}

// Line kinds. A stencil grammar declares container and item kinds only, so the
// line kinds are named lines here, each with the legend entry that explains it.
#Awaitable: {line: "solid", tint: 3, ...}
#Failure: {line: "solid", tint: 7, ...}
#Signal: {line: "dash", tint: 5, ...}
#Attach: {line: "gray", ...}

legend: {
	awaitable: #Awaitable & {text: "awaitable: a resolved promise, a fired timer or a completed step"}
	failure: #Failure & {text: "awaitable that fails the attempt"}
	signal: #Signal & {text: "signal from a session or an arbiter"}
	attach: #Attach & {text: "attach or read; owns no process"}
}

// Theme tokens. Each figure renders once on clear and once on clear-dark, with
// the page and card colors of the design page's surface tokens so a figure sits
// on its diagram panel without a second background.
_light: {
	page: "#FFFFFF"
	card: {fill: "#EEF2F0", border: {color: "#B9C3C0", width: 1, pattern: "solid"}}
}
_dark: {
	page: "#161C1B"
	card: {fill: "#1D2524", border: {color: "#3A4644", width: 1, pattern: "solid"}}
}

// A figure is one page; light and dark are the two documents rendered from it.
// The renderer finds the grammar by path, while #KindedPage accepts only the
// grammar's name in `grammar`, so the vetted page leaves the field out and each
// document copies the page's fields into a struct that adds it.
#Figure: {
	#page: #Page
	light: {for field, value in #page {(field): value}, grammar: _grammarFile, theme: "clear", theme_overrides: _light}
	dark: {for field, value in #page {(field): value}, grammar: _grammarFile, theme: "clear-dark", theme_overrides: _dark}
}

_grammarFile: "tycho.json"
