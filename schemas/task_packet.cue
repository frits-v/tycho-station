// The task_packet payload of crates/tycho-types/src/task_packet.rs.
package schemas

import "list"

#RoutingName: #Slug32
#Effort:      "minimal" | "low" | "medium" | "high" | "max"

#DoneCriterion: {
	kind!:          "command"
	command!:       #ShortText
	expected_exit!: #U8
} | {
	kind!: "file_present"
	path!: #RelativePath
} | {
	kind!: "file_absent"
	path!: #RelativePath
}

#Boundaries: {
	worktree!: #AbsolutePath
	branch!:   #BranchName
	writable_paths!: [...#RelativePath] & list.MaxItems(64)
	forbidden_actions!: [...#ShortText] & list.MaxItems(64)
}

#Routing: {
	class!:         #RoutingName
	tier!:          #RoutingName
	effort!:        #Effort
	binding?:       #Vendor | null
	rationale!:     #ShortText
	fallback_tier?: #RoutingName | null
}

#Budget: {
	tokens_max!:        int & >=1 & <=50000000
	wall_clock_max_ms!: int & >=1 & <=86400000
}

#TaskPacketPayload: {
	objective!: #ContentRef
	done_criteria!: [...#DoneCriterion] & list.MaxItems(64)
	boundaries!: #Boundaries
	inputs!: [...#ContentRef] & list.MaxItems(64)
	routing!:       #Routing
	budget!:        #Budget
	result_schema!: #ContentRef
}
