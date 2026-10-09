// The wire form of ExitState in crates/tycho-types/src/exit.rs: what serialization writes.
// Decoding accepts any string and maps one outside this set to the unrecognised state.
package schemas

#ExitState: "completed" | "escalated" | "too_large" | "stalled" | "cancelled" | "killed" |
	"budget_exceeded" | "rate_limited" | "failed" |
	=~"^unrecognised:[0-9]+(:[!-~]{0,64})?$"
