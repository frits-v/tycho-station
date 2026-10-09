package figures

import "github.com/frits-v/tycho-station/figures/grammar:tycho"

figures: "deep-links": tycho.#Figure & {
	#page: {
		title:  "Deep links"
		kicker: "Inbox and surfaces"
		lede:   "A notification carries a localhost link that the reader resolves to a Ghostty tab attached to the session."
		width:  1120
		body: [{
			tag: "Col"
			gap: 16
			children: [
				{tag: "Row", grow: [3, 0, 4, 0, 3, 0, 5], children: [
					{tag: "Item", kind: "surface", title: "Notification", subtitle: "Slack, mail, macOS"},
					_hop & {label: "http link survives"},
					{tag: "Item", kind: "surface", title: "Web view", subtitle: "localhost/inbox/pkt-0142"},
					_hop & {label: "GET /open/S"},
					{tag: "Item", kind: "process", title: "Reader binary", subtitle: "resolves pane ref"},
					_hop & {label: "AppleScript"},
					{tag: "Item", kind: "surface", title: "Ghostty tab", subtitle: "focus by terminal id, or new tab: zmx attach S"},
				]},
				{tag: "Text", body: ["Chat tools strip custom URL schemes, so the notification carries a localhost link. The reader keeps the Ghostty terminal id it last opened for each session; it focuses that, or opens a tab running the attach."]},
			]
		}]
		legend: []
	}
}

_hop: tycho.#Attach & {tag: "Pipe", dir: "h", arrow: "end"}
