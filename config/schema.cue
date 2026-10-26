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
	// null at the top of the ladder.
	fallback!: #Name | null
}

// A class's minimum tier and a tier's fallback each name a tier in the table; a run whose
// class the table does not list is refused at dispatch.
#Routing: {
	classes!: {[#Name]: #Class & {minimum_tier: or(_tier_names)}} &
		struct.MinFields(1) & struct.MaxFields(32)
	tiers!: {[#Name]: #Tier & {fallback: null | or(_tier_names)}} &
		struct.MinFields(1) & struct.MaxFields(8)
	_tier_names: [for name, _ in tiers {name}]
}

#Thresholds: {
	stall!: {
		// T1, before a nudge.
		silence_seconds!: #Seconds
		// T2, on an unchanged progress marker, before kill and re-queue.
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
		unit_attempt_cap!:         int & >=1 & <=99
	}
	session!: {
		heartbeat_interval_seconds!:  #Seconds
		lease_fresh_seconds!:         #Seconds & >heartbeat_interval_seconds
		spawn_grace_seconds!:         #Seconds
		reconciler_interval_seconds!: #Seconds
		// Fraction of the context window at which a control session rolls over.
		rollover_fraction!: number & >0 & <1
	}
}

// Every threshold and period of mandate articles 14 and 15, with the petition mechanism's
// own bounds (design section 11); reported with every petition. Each key is bounded.
#Petitions: {
	// Consecutive human rulings with one ruling on one question fingerprint.
	repeated_ruling_count!: int & >=2 & <=50
	// Verified citations without a failed one before a case becomes a convention (14.3).
	convention_citations_min!: int & >=1 & <=1000
	// Days a convention holds without a failed citation.
	convention_hold_days!: int & >=7 & <=730
	// Days without a citation or a firing before a rule is listed as dormant.
	review_period_days!: int & >=7 & <=730
	// Petitions open or amending at once; a crossing past it waits for a later pass.
	open_max!: int & >=1 & <=8
	// Seconds between passes of the Petitions tick.
	evaluation_interval_seconds!: #Seconds & >=60
	// Motivating cases a packet lists; the rest are counted.
	cases_listed_max!: int & >=1 & <=16
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

// unscheduled: no slice in docs/slices.md closes it; the operator assigns one.
#Slice:       "zero" | "one" | "two" | "unscheduled"
#Record:      "store" | "journal" | "forge" | "not_recorded"
#GitHubLogin: string & =~"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$"
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

#ClauseIds: [
	"1.1", "1.2", "1.3", "1.4", "2.1", "2.2", "2.3", "3.1", "3.2", "4.1",
	"4.2", "4.3", "4.4", "4.5", "4.6", "5.1", "5.2", "5.3", "5.4", "5.5",
	"6.1", "6.2", "6.3", "7.1", "7.2", "7.3", "7.4", "8.1", "8.2", "8.3",
	"8.4", "9.1", "9.2", "9.3", "10.1", "10.2", "10.3", "10.4", "11.1", "11.2",
	"12.1", "12.2", "13.1", "13.2", "14.1", "14.2", "14.3", "14.4", "14.5", "15.1",
	"15.2", "15.3", "15.4", "15.5",
]

#MechanismId: "ruleset" | "ci" | "lefthook" | "post_edit_hook" | "core_directory_check" |
	"setup" | "credential_handoff" | "spine_services" | "codeowners"

#Mandate: {
	// The GitHub login CODEOWNERS names as the mandate's sole owner; xtask check-codeowners
	// reads it back from the export so the owner it requires is never hardcoded in Rust.
	operator_github_handle!: #GitHubLogin
	mechanisms!: {[#MechanismId]: #Mechanism}
	mechanisms: struct.MaxFields(16)
	// Each numbered clause of docs/mandate.md is required by its id, and no other id is allowed;
	// `xtask check-config` compares the list with the document.
	clauses!: {for id in #ClauseIds {"\(id)"!: #Clause}}
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

#Host:        string & =~"^([a-z0-9-]+\\.)+[a-z]{2,}$" & strings.MaxRunes(253)
#SystemPath:  string & =~"^/[^\\x00]*$" & !~"/\\.\\.?(/|$)" & strings.MaxRunes(256)
#AccessMode:  "read" | "write" | "read_write"
#Platform:    "macos" | "linux"
#Arch:        "aarch64" | "x86_64"

// One system path the session sandbox grants on one platform. Every macOS entry is
// required to exist when a session starts; `optional` is for the Linux list, which only the
// ci runner uses, and lets an entry absent on that runner be skipped.
#SystemGrant: {
	path!:     #SystemPath
	access!:   #AccessMode
	platform!: #Platform
	arch?:     #Arch
	optional:  bool | *false
	if platform == "macos" {
		optional: false
	}
}

#VendorNetwork: {
	// The hosts the session proxy lets the vendor reach; anything else is refused and recorded.
	allowed_hosts!: [...#Host] & list.MinItems(1) & list.MaxItems(16) & list.UniqueItems()
}

#Sandbox: {
	system_paths!: [...#SystemGrant] & list.MinItems(1) & list.MaxItems(256)
	vendors!: {
		claude!: #VendorNetwork
		codex!:  #VendorNetwork
	}
}
