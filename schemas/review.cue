// The structured output of the two `xtask review` passes in xtask/src/review.rs: the find
// pass reports candidate findings, the verify pass judges one candidate.
package schemas

import (
	"list"
	"strings"
)

#ReviewSeverity: "high" | "medium" | "low"
#ReviewCategory: "correctness" | "security" | "repository-rule" | "test-coverage"

#ReviewFinding: {
	path!:             #RelativePath
	line!:             int & >=1 & <=1000000
	severity!:         #ReviewSeverity
	category!:         #ReviewCategory
	summary!:          #ShortText
	failure_scenario!: #Text & strings.MaxRunes(2000)
}

#ReviewFindings: {
	findings!: [...#ReviewFinding] & list.MaxItems(20)
}

#ReviewVerdict: {
	verdict!:   "confirmed" | "refuted"
	reasoning!: #Text & strings.MaxRunes(2000)
}
