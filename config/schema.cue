// Schema of the factory configuration. Each value file unifies one top-level field with a
// definition here; `xtask config-export` exports each field to export/<name>.json.
package config

import (
	"list"
	"strings"
	"struct"
)

#Name:    string & =~"^[a-z0-9][a-z0-9-]*$" & strings.MaxRunes(32)
#Model:   string & =~"^[a-z0-9][a-z0-9.-]*$" & strings.MaxRunes(64)
#Effort:  "minimal" | "low" | "medium" | "high" | "max"
#Seconds: int & >=1 & <=86400

#Class: {
	minimum_tier!: #Name
	effort!:       #Effort
	attempt_cap!:  int & >=1 & <=99
}

#Tier: {
	models!: {
		claude!: #Model
		codex!:  #Model
	}
	// The tier a failed attempt moves up to; null at the top.
	fallback!: #Name | null
}

// A class's minimum tier and a tier's fallback each name a tier in the table.
#Routing: {
	classes!: {[#Name]: #Class & {minimum_tier: or(_tier_names)}} &
		struct.MinFields(1) & struct.MaxFields(32)
	tiers!: {[#Name]: #Tier & {fallback: null | or(_tier_names)}} &
		struct.MinFields(1) & struct.MaxFields(8)
	// The attempt cap of a class the table does not list.
	attempt_cap_default!: int & >=1 & <=99
	_tier_names: [for name, _ in tiers {name}]
}

#Thresholds: {
	stall!: {
		// T1: silence before a nudge.
		silence_seconds!: #Seconds
		// T2: an unchanged progress marker before kill and re-queue.
		progress_seconds!: #Seconds & >silence_seconds
	}
	slots!: {
		control!: int & >=1 & <=64
		worker!:  int & >=1 & <=64
	}
	retry!: {
		backoff_initial_seconds!:  #Seconds
		backoff_max_seconds!:      #Seconds & >=backoff_initial_seconds
		backoff_factor!:           2
		port_step_attempts_max!:   int & >=1 & <=100
		slot_retry_delay_seconds!: #Seconds
		// Attempts one work unit makes before it is abandoned.
		unit_attempt_cap!: int & >=1 & <=99
	}
	session!: {
		heartbeat_interval_seconds!:  #Seconds
		lease_fresh_seconds!:         #Seconds & >heartbeat_interval_seconds
		spawn_grace_seconds!:         #Seconds
		reconciler_interval_seconds!: #Seconds
		// Fraction of the context window at which a control session rolls over.
		rollover_fraction!: number & >0 & <1
	}
	// Article 14.3 to 15.3 thresholds; null until the operator sets them.
	mandate!: {
		convention_citations_min!:    null | int & >=1 & <=10000
		petition_repeat_count!:       null | int & >=1 & <=10000
		convention_held_period_days!: null | int & >=1 & <=3650
		review_period_days!:          null | int & >=1 & <=3650
	}
}

#Adapter: {
	session_vendor!: "claude" | "codex" | "antigravity" | "amp" | "opencode"
	pane_host!:      "zmx"
	tracker!:        "none" | "github"
	remote_sync!:    "none" | "git"
	code_graph!:     "none" | "entire"
}

#Adapters: {
	projects!: {[#Name]: #Adapter} & struct.MaxFields(64)
	projects: default!: #Adapter
}

#Slice:  "zero" | "one" | "two"
#Record: "store" | "journal" | "forge" | "not_recorded"
#Mechanism: {
	what!:    string & strings.MinRunes(1) & strings.MaxRunes(512)
	runs!:    string & strings.MinRunes(1) & strings.MaxRunes(256)
	record!:  #Record
	pending!: bool
}

#Clause: {
	requires!: string & strings.MinRunes(1) & strings.MaxRunes(512)
	mechanisms!: [...#MechanismId] & list.MaxItems(4) & list.UniqueItems()
	// How the cited mechanisms reach the clause; empty when none is cited.
	coverage!: string & strings.MaxRunes(256)
	partial!:  bool
	slices!: [...#Slice] & list.MinItems(1) & list.MaxItems(3) & list.UniqueItems()
	if len(mechanisms) == 0 {
		partial:  false
		coverage: ""
	}
	if len(mechanisms) > 0 {
		coverage: strings.MinRunes(1)
	}
}

#MechanismId: "ruleset" | "ci" | "lefthook" | "post_edit_hook" | "core_directory_check" |
	"setup" | "spine_services"

#Mandate: {
	mechanisms!: {[#MechanismId]: #Mechanism}
	mechanisms: struct.MaxFields(16)
	// Every numbered clause of docs/mandate.md, 1.1 to 15.4.
	clauses!: {[=~"^(1[0-5]|[1-9])\\.[1-9]$"]: #Clause} & struct.MinFields(50) & struct.MaxFields(50)
	// The design table's status and record per clause, derived from the mechanism table so
	// neither can drift from it. A clause is pending when every mechanism it cites is.
	rows: {for id, clause in clauses {
		let cited = len(clause.mechanisms)
		let pending = len([for m in clause.mechanisms if mechanisms[m].pending {m}])
		"\(id)": {
			records: [for m in clause.mechanisms {mechanisms[m].record}]
			if cited == 0 {status: "none"}
			if cited > 0 && pending == cited && clause.partial {status: "pending, partial"}
			if cited > 0 && pending == cited && !clause.partial {status: "pending"}
			if cited > 0 && pending < cited && clause.partial {status: "partial"}
			if cited > 0 && pending < cited && !clause.partial {status: "closed"}
		}
	}}
}
