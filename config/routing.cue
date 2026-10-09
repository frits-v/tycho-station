// Task class to minimum tier, effort and attempt cap; tier to model per vendor and the
// tier a failed attempt moves up to. The design gives no classes, tiers or models: these are
// placeholders until the harness sets them, and the codex models until the launcher probes them.
package config

routing: #Routing & {
	classes: {
		probe: {minimum_tier: "light", effort: "low", attempt_cap: 3}
		implement: {minimum_tier: "standard", effort: "medium", attempt_cap: 3}
		review: {minimum_tier: "standard", effort: "high", attempt_cap: 3}
		plan: {minimum_tier: "strong", effort: "high", attempt_cap: 3}
		judge: {minimum_tier: "strong", effort: "high", attempt_cap: 3}
	}
	tiers: {
		light: {models: {claude: "haiku", codex: "gpt-5-codex-mini"}, fallback: "standard"}
		standard: {models: {claude: "sonnet", codex: "gpt-5-codex"}, fallback: "strong"}
		strong: {models: {claude: "opus", codex: "gpt-5-codex"}, fallback: null}
	}
}
