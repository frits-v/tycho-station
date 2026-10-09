// A petition for amendment as the Petitions object records it and its packet header shows it
// (design section 11). The packet's prose sections are markdown and not part of this shape.
package schemas

import "list"

#PetitionCounter: "repeated_ruling" | "convention_hold" | "void_finding" | "dormancy" | "early"
#PetitionState:   "open" | "amend" | "reject"

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
	// The counter's evidence value when the petition was raised.
	evidence!: #U32
	thresholds!: {
		repeated_ruling_count!: #U32
		convention_hold_days!:  #U32
		review_period_days!:    #U32
		// Digest of config/export/petitions.json, so the reader can match the values.
		digest!: #ContentRef
	}
	cases!: [...#RecordId] & list.MaxItems(16)
	cases_total!: #U32
	state!:       #PetitionState
	// The silent-by-design case this petition overcomes with new evidence.
	supersedes?: #RecordId
}
