// Adapter selection per project; `default` applies to a project without its own entry.
package config

adapters: #Adapters & {
	projects: default: {
		session_vendor: "claude"
		pane_host:      "zmx"
		tracker:        "github"
		remote_sync:    "git"
		code_graph:     "entire"
	}
}
