// The message envelope and the result, status and escalation payloads of
// crates/tycho-types/src/envelope.rs. Parse-level checks the schema cannot carry: the
// 65,536-byte size cap, `from`, `to`, `correlation_id` and `work_unit_id` agreeing on the
// epic and unit, the direction by level, and a sender addressing itself.
package schemas

import "list"

#Usage: {
	input_tokens!:       #U64
	output_tokens!:      #U64
	cost_micro_dollars?: #U64
}

#CriterionReport: {
	criterion!: #U16
	passed!:    bool
	evidence!: [...#ContentRef] & list.MaxItems(64)
}

#ResultPayload: {
	outcome!:  "done" | "not_done"
	branch!:   #BranchName
	head_sha!: #CommitSha
	criteria!: [...#CriterionReport] & list.MaxItems(64)
	usage!: #Usage
}

#ProgressMarker: {
	head_sha?:      #CommitSha | null
	tests_passing!: #U32
}

#StatusPayload: {
	state?:                 #StateName | null
	summary!:               #ShortText
	last_progress_unix_ms!: #U64
	progress!:              #ProgressMarker
	active_workers!:        #U16
	usage!:                 #Usage
	blockers!: [...#ContentRef] & list.MaxItems(64)
}

#EscalationOption: {
	label!:         #ShortText
	reversibility!: "two_way" | "costly" | "one_way"
	blast_radius!:  #ShortText
}

#EscalationPayload: {
	level_reached!:  #Level
	give_up_reason!: #ShortText
	question!:       #ContentRef
	question_type!:  "empirical" | "judgment" | "authority"
	options!: [...#EscalationOption] & list.MaxItems(4)
	proposed_ruling?: #ContentRef | null
	evidence!: [...#ContentRef] & list.MaxItems(64)
	cases_consulted!: [...#RecordId] & list.MaxItems(64)
	blocking!: bool
}

// A hidden field rather than a definition: the JSON Schema encoder closes an embedded
// definition against the fields beside it, which would refuse every envelope.
_envelopeBase: {
	schema_version!:     1
	id!:                 #RecordId
	work_unit_id!:       #WorkUnitId
	from!:               #SessionName
	to!:                 #SessionName
	causation_id?:       #RecordId | null
	correlation_id!:     #EpicId
	created_at_unix_ms!: #U64
	expires_at_unix_ms?: #U64 | null
}

#Envelope: {
	_envelopeBase
	type!:    "task_packet"
	payload!: #TaskPacketPayload
} | {
	_envelopeBase
	type!:    "result"
	payload!: #ResultPayload
} | {
	_envelopeBase
	type!:    "status"
	payload!: #StatusPayload
} | {
	_envelopeBase
	type!:    "escalation"
	payload!: #EscalationPayload
}
