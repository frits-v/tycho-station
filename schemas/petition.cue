// A petition for amendment as the Petitions object records it and its packet header shows it
// (design section 11). The packet's prose sections are markdown and not part of this shape.
package schemas

import "list"

#PetitionCounter: "repeated_ruling" | "convention_hold" | "void_finding" | "dormancy" | "early"

// open and amend count toward the open maximum and block a second petition with the same
// fingerprint; merged, closed and reject are terminal.
#PetitionState: "open" | "amend" | "merged" | "closed" | "reject"

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
	// The superseded rejection's baseline, when raised on new evidence.
	baseline?: #U32
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
	// The latest rejection case holding this fingerprint, when raised on new evidence.
	supersedes?: #RecordId
}
