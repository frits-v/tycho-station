// String and integer shapes of crates/tycho-types/src/token.rs and the checked strings built on it.
// maxLength counts code points where Rust counts bytes; the two agree on the ASCII-only shapes.
package schemas

import "strings"

#U8:  int & >=0 & <=255
#U16: int & >=0 & <=65535
#U32: int & >=0 & <=4294967295
#U64: int & >=0 & <=18446744073709551615

#Slug16: string & =~"^[a-z0-9][a-z0-9-]*$" & strings.MaxRunes(16)
#Slug32: string & =~"^[a-z0-9][a-z0-9-]*$" & strings.MaxRunes(32)
#Slug64: string & =~"^[a-z0-9][a-z0-9-]*$" & strings.MaxRunes(64)

// No control characters (Unicode category Cc), so text cannot carry terminal escapes.
#Text:      string & =~"^[^\\x00-\\x1f\\x7f-\\x9f]+$"
#ShortText: #Text & strings.MaxRunes(512)

#EpicId:     #Slug16
#WorkUnitId: #Slug16 & !="root"
#TaskId:     #Slug64
#RecordId:   string & =~"^[A-Za-z0-9_-]+$" & strings.MaxRunes(64)
#StateName:  #Slug32
#ContentRef: string & =~"^sha256:[0-9a-f]{64}$"
#CommitSha:  string & =~"^([0-9a-f]{40}|[0-9a-f]{64})$"

// A portable subset of git check-ref-format: no leading dash, no trailing dot, no `..`,
// no empty component, no component starting with a dot or ending in `.lock`.
#BranchName: string & =~"^[A-Za-z0-9._/-]+$" & strings.MaxRunes(128) &
	!~"^-|\\.$|\\.\\.|^/|//|/$|(^|/)\\.|\\.[lL][oO][cC][kK](/|$)"

#AbsolutePath: #Text & strings.MaxRunes(1024) & =~"^/" & !~"//|/$|/\\.\\.?(/|$)"
#RelativePath: #Text & strings.MaxRunes(1024) & !~"^[/-]|//|/$|(^|/)\\.\\.?(/|$)"

#Vendor: "claude" | "codex" | "antigravity" | "amp" | "opencode"
#Level:  "root" | "control" | "worker"

#VendorPattern: "(claude|codex|antigravity|amp|opencode)"
#SlugPattern:   "[a-z0-9][a-z0-9-]*"

// `<epic>.<unit>.<ctl|wrk>.<vendor>[.<suffix>]` or `<epic>.root.<vendor>[.<suffix>]`; a unit
// named `root` is the root form, so `<epic>.root.ctl.` is refused.
#SessionName: string & strings.MaxRunes(64) &
	=~"^\(#SlugPattern)\\.(root|\(#SlugPattern)\\.(ctl|wrk))\\.\(#VendorPattern)(\\.\(#SlugPattern))?$" &
	!~"^[^.]*\\.root\\.(ctl|wrk)\\."
