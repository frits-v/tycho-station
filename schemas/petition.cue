// A petition for amendment as the Petitions object records it and its packet header shows it
// (design section 11). The packet's prose sections are markdown and not part of this shape.
package schemas

import "list"

#PetitionCounter: "repeated_ruling" | "convention_hold" | "void_finding" | "dormancy" | "early"

// open and amend count toward the open maximum and block a second petition with the same
// fingerprint; merged, closed and reject are terminal. A dormancy petition whose pull request
// closes without a merge goes from amend back to open.
#PetitionState: "open" | "amend" | "merged" | "closed" | "reject"

// What a suppressing case records, per counter: the counter's value when the case is written
// (design section 11). Dormancy and early petitions record none.
#RepeatedRulingBaseline: {
	counter!: "repeated_ruling"
	count!:   #U32
}
#ConventionHoldBaseline: {
	counter!:            "convention_hold"
	decided!:            =~"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"
	verified_citations!: #U32
}
#VoidFindingBaseline: {
	counter!: "void_finding"
	count!:   #U32
}
#PetitionBaseline: #RepeatedRulingBaseline | #ConventionHoldBaseline | #VoidFindingBaseline

// The article number of the clause the petition would amend, or "new" for a new article.
#PetitionArticle: =~"^([1-9][0-9]?|new)$"

#Petition: {
	fingerprint!: =~"^[0-9a-f]{64}$"
	article!:     #PetitionArticle
	sequence!:    int & >=1 & <=9999
	counter!:     #PetitionCounter
	// The counter key: question fingerprint and ruling digest, case id, article, clause or
	// mechanism id, or escalation id.
	key!: #ShortText
	// The counter's value when the petition was raised; null for an early petition.
	evidence!: #U32 | null
	// The superseded case's baseline, when raised on new evidence. CUE holds its counter to
	// the petition's; the JSON Schema export carries the per-counter shapes only.
	baseline?: #PetitionBaseline & {counter: _petition_counter}
	let _petition_counter = counter
	thresholds!: {
		repeated_ruling_count!:    #U32
		convention_citations_min!: #U32
		convention_hold_days!:     #U32
		review_period_days!:       #U32
		// Digest of config/export/petitions.json, so the reader can match the values.
		digest!: #ContentRef
	}
	// Content hash of the mandate copy the pass pinned.
	mandate!: #ContentRef
	cases!: [...#RecordId] & list.MaxItems(16)
	cases_total!: #U32
	state!:       #PetitionState
	// The latest suppressing case holding this fingerprint, when raised on new evidence.
	supersedes?: #RecordId
}
